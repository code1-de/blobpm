use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod client;
mod install;
mod platform;
mod remove;
mod repo;
mod server;
#[cfg(test)]
mod testutil;
mod tls;
mod upload;

#[derive(Parser)]
#[command(
    name = "blob",
    about = format!("blob package manager {} by Christoph Lüders — https://lueders.io\nMax file size per extracted file: 1 GB", env!("CARGO_PKG_VERSION")),
    version,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install a package (use name@version for a specific version)
    Install {
        /// Package name, or name@version for a specific version
        name: String,

        /// Reinstall even if already installed (e.g. to change version)
        #[arg(long, short)]
        force: bool,
    },
    /// Remove a package (auto-removes orphaned auto-installed dependencies)
    Remove {
        /// Package name
        name: String,

        /// Remove even if other packages depend on it (leaves them broken)
        #[arg(long)]
        force: bool,

        /// Also remove packages that depend on this one (cascades upward)
        #[arg(long)]
        transitive: bool,

        /// Keep orphaned auto-installed dependencies instead of removing them
        #[arg(long)]
        keep: bool,
    },
    /// Update installed packages to latest versions
    Update {
        /// Package name (optional, updates all if omitted)
        name: Option<String>,
    },
    /// List installed packages (with package name: show details)
    List {
        /// Package name (optional, show deps, files, install reason)
        name: Option<String>,

        /// Show details for all packages (deps, files)
        #[arg(long, short = 'l')]
        long: bool,
    },
    /// Search for packages on the server (regex pattern, use ".*" for all)
    Search {
        /// Regex pattern to match package names
        pattern: String,

        /// Show all available versions (sorted, latest last)
        #[arg(long = "available", short = 'a')]
        versions: bool,
    },
    /// Configure blob settings interactively (server URL, base dir, credentials)
    Config,
    /// Mark a package as manually installed (prevents auto-removal as orphan)
    Manual {
        /// Package name
        name: String,
    },
    /// Remove all orphaned auto-installed packages (auto deps no longer needed)
    Purge,
    /// Clean the download cache (delete cached zip files)
    CleanCache,
    /// Run the package server (HTTPS with auto-generated TLS cert)
    Serve {
        /// Path to the repository directory
        #[arg(long)]
        repo: PathBuf,

        /// Address to bind to (default: 127.0.0.1, use 0.0.0.0 to expose to network)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,

        /// Port to listen on
        #[arg(long, default_value = "53777")]
        port: u16,

        /// Username for Basic Auth
        #[arg(long, env = "BLOB_USERNAME")]
        username: String,

        /// Password for Basic Auth
        #[arg(long, env = "BLOB_PASSWORD")]
        password: String,
    },
    /// Upload a package to the server
    ///
    /// Maps files to destination dirs using glob:dest patterns.
    /// Absolute globs use filename only, relative globs preserve path from --from.
    /// Examples: "*.exe:bin" "C:\tools\7z*.exe:util" --from src "lib/**:lib"
    Upload {
        /// Package name@version (e.g. helper@3.0)
        package: String,

        /// File mappings: "glob:dest" (first match wins). Use absolute paths or relative to --from
        mappings: Vec<String>,

        /// Base directory for relative glob patterns
        #[arg(long, default_value = ".")]
        from: PathBuf,

        /// Package dependency (can be repeated: --dep zip --dep helper)
        #[arg(long = "dep", short)]
        deps: Vec<String>,

        /// Package description
        #[arg(long, default_value = "")]
        description: String,

        /// Interactive mode — review and edit all fields before uploading
        #[arg(long, short)]
        interactive: bool,

        /// Overwrite if version already exists on server
        #[arg(long, short)]
        force: bool,
    },
    /// Generate or regenerate TLS certificate and key (~/.blob/cert.pem, key.pem)
    GenerateKeys {
        /// Overwrite existing keys without asking
        #[arg(long, short)]
        force: bool,
    },
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();

    if let Err(e) = run_command(&cli.command) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run_command(command: &Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Serve { repo, bind, port, username, password } => {
            if std::env::var("BLOB_PASSWORD").is_err() {
                eprintln!("Warning: password passed via command line — visible in process listings.");
                eprintln!("         Prefer setting BLOB_PASSWORD environment variable instead.");
            }
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(repo.clone(), bind, *port, (username.clone(), password.clone())))?;
        }
        Commands::Install { name, force } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            let mut db = client::Database::load()?;
            let (pkg_name, version) = parse_package_spec(name);
            install::install(&pkg_name, version.as_deref(), *force, &http, &mut db)?;
        }
        Commands::Search { pattern, versions } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            upload::search(pattern, *versions, &http)?;
        }
        Commands::Remove { name, force, transitive, keep } => {
            let mut db = client::Database::load()?;
            remove::remove(name, *force, *transitive, *keep, &mut db)?;
        }
        Commands::Manual { name } => {
            let mut db = client::Database::load()?;
            match db.packages.get_mut(name.as_str()) {
                Some(pkg) => {
                    if pkg.reason == client::InstallReason::Manual {
                        println!("{name} is already marked as manual");
                    } else {
                        pkg.reason = client::InstallReason::Manual;
                        db.save()?;
                        println!("{name} marked as manually installed");
                    }
                }
                None => {
                    return Err(format!("{name} is not installed").into());
                }
            }
        }
        Commands::Purge => {
            let mut db = client::Database::load()?;
            remove::purge(&mut db)?;
        }
        Commands::CleanCache => {
            let config = client::Config::load()?;
            println!("Cleaning cache (max age: {} day(s))...", config.cache_days);
            install::clean_cache(&config.base_dir, config.cache_days);
        }
        Commands::Update { name } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            let mut db = client::Database::load()?;
            install::update(name.as_deref(), &http, &mut db)?;
        }
        Commands::List { name, long } => {
            let db = client::Database::load()?;
            if db.packages.is_empty() {
                println!("No packages installed.");
            } else {
                let packages: Vec<_> = match name {
                    Some(n) => {
                        if !db.packages.contains_key(n.as_str()) {
                            println!("{n} is not installed");
                            return Ok(());
                        }
                        vec![n.as_str()]
                    }
                    None => db.packages.keys().map(String::as_str).collect(),
                };
                let show_details = *long || name.is_some();
                for n in &packages {
                    let pkg = &db.packages[*n];
                    let reason = match pkg.reason {
                        client::InstallReason::Manual => "manual",
                        client::InstallReason::Auto => "auto",
                    };
                    if show_details {
                        println!("{n} {} [{reason}]", pkg.version);
                        if !pkg.dependencies.is_empty() {
                            println!("  Dependencies: {}", pkg.dependencies.join(", "));
                        }
                        for (file, path) in &pkg.files {
                            println!("  {file} -> {}", path.display());
                        }
                    } else {
                        let suffix = if pkg.reason == client::InstallReason::Auto { " (auto)" } else { "" };
                        println!("{n} {}{suffix}", pkg.version);
                    }
                }
            }
        }
        Commands::Upload { package, mappings, from, deps, description, interactive, force } => {
            let (pkg_name, version) = parse_package_spec(package);
            let version = version.ok_or("Version required: use name@version")?;
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;

            if *interactive || mappings.is_empty() {
                upload::upload_interactive(&pkg_name, &version, from, mappings, deps, description, *force, &http)?;
            } else {
                upload::upload(&pkg_name, &version, from, mappings, deps, description, *force, &http)?;
            }
        }
        Commands::GenerateKeys { force } => {
            tls::generate_keys(*force)?;
        }
        Commands::Config => {
            run_config()?;
        }
    }
    Ok(())
}

/// Parse `name@version` into (name, Some(version)) or (name, None).
fn parse_package_spec(spec: &str) -> (String, Option<String>) {
    if let Some((name, version)) = spec.split_once('@') {
        (name.to_string(), Some(version.to_string()))
    } else {
        (spec.to_string(), None)
    }
}

fn run_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = client::Config::load().unwrap_or_else(|_| client::Config {
        server_url: "https://localhost:53777".to_string(),
        base_dir: PathBuf::from("C:/"),
        username: String::new(),
        password: String::new(),
        server_fingerprint: String::new(),
        cache_days: 1,
    });

    println!("blob configuration");
    println!("Press Enter to keep current value.\n");

    let server_url = upload::prompt_line("Server URL", &config.server_url)?;
    let base_dir = upload::prompt_line("Base install directory", &config.base_dir.display().to_string())?;
    let username = upload::prompt_line("Username", &config.username)?;
    let password = upload::prompt_line("Password", &config.password)?;
    let cache_days_str = upload::prompt_line("Cache max age (days, 0=no cache)", &config.cache_days.to_string())?;
    let cache_days: u32 = cache_days_str.parse().unwrap_or(config.cache_days);

    let base_dir = PathBuf::from(base_dir);
    let base_dir = dunce::canonicalize(&base_dir).unwrap_or(base_dir);

    let new_config = client::Config {
        server_url,
        base_dir,
        username,
        password,
        server_fingerprint: config.server_fingerprint.clone(),
        cache_days,
    };

    new_config.save()?;
    println!("\nConfig saved.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
