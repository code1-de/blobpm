use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

mod client;
mod repo;
mod server;
#[cfg(test)]
mod testutil;
mod tls;

#[derive(Parser)]
#[command(
    name = "blob",
    about = format!("blob package manager {} by Christoph Lüders — https://lueders.io", env!("CARGO_PKG_VERSION")),
    version,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the package server
    Serve {
        /// Path to the repository directory
        #[arg(long)]
        repo: PathBuf,

        /// Port to listen on
        #[arg(long, default_value = "8803")]
        port: u16,

        /// Username for Basic Auth (optional, no auth if omitted)
        #[arg(long)]
        username: Option<String>,

        /// Password for Basic Auth
        #[arg(long)]
        password: Option<String>,
    },
    /// Install a package
    Install {
        /// Package name
        name: String,

        /// Reinstall even if already installed
        #[arg(long, short)]
        force: bool,
    },
    /// Remove an installed package
    Remove {
        /// Package name
        name: String,

        /// Remove even if other packages depend on it
        #[arg(long)]
        force: bool,

        /// Also remove dependencies that are no longer needed
        #[arg(long)]
        transitive: bool,

        /// Don't auto-remove orphaned dependencies
        #[arg(long)]
        keep: bool,
    },
    /// Search for packages on the server (regex)
    Search {
        /// Regex pattern to match package names
        pattern: String,

        /// Show all available versions
        #[arg(long = "available", short = 'a')]
        versions: bool,
    },
    /// Mark a package as manually installed
    Manual {
        /// Package name
        name: String,
    },
    /// Remove all orphaned auto-installed packages
    Purge,
    /// Update installed packages
    Update {
        /// Package name (optional, updates all if omitted)
        name: Option<String>,
    },
    /// List installed packages
    List {
        /// Package name (optional, show details for this package)
        name: Option<String>,
    },
    /// Generate TLS certificate and key
    GenerateKeys,
    /// Configure blob settings
    Config,
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();

    if let Err(e) = run_command(&cli.command) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run_command(command: &Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Serve { repo, port, username, password } => {
            let u = username.as_ref().ok_or("--username is required")?;
            let p = password.as_ref().ok_or("--password is required")?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(repo.clone(), *port, (u.clone(), p.clone())))?;
        }
        Commands::Install { name, force } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            let mut db = client::Database::load()?;
            let (pkg_name, version) = parse_package_spec(name);
            client::install(&pkg_name, version.as_deref(), *force, &http, &mut db)?;
        }
        Commands::Search { pattern, versions } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            client::search(pattern, *versions, &http)?;
        }
        Commands::Remove { name, force, transitive, keep } => {
            let mut db = client::Database::load()?;
            client::remove(name, *force, *transitive, *keep, &mut db)?;
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
            client::purge(&mut db)?;
        }
        Commands::Update { name } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            let mut db = client::Database::load()?;
            client::update(name.as_deref(), &http, &mut db)?;
        }
        Commands::List { name } => {
            let db = client::Database::load()?;
            match name {
                Some(n) => {
                    if let Some(pkg) = db.packages.get(n.as_str()) {
                        let reason = match pkg.reason {
                            client::InstallReason::Manual => "manual",
                            client::InstallReason::Auto => "auto",
                        };
                        println!("{n} {} [{reason}]", pkg.version);
                        if !pkg.dependencies.is_empty() {
                            println!("  Dependencies: {}", pkg.dependencies.join(", "));
                        }
                        for (file, path) in &pkg.files {
                            println!("  {file} -> {}", path.display());
                        }
                    } else {
                        println!("{n} is not installed");
                    }
                }
                None => {
                    if db.packages.is_empty() {
                        println!("No packages installed.");
                    } else {
                        for (n, pkg) in &db.packages {
                            let suffix = if pkg.reason == client::InstallReason::Auto { " (auto)" } else { "" };
                            println!("{n} {}{suffix}", pkg.version);
                        }
                    }
                }
            }
        }
        Commands::GenerateKeys => {
            tls::generate_keys()?;
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

fn prompt(label: &str, default: &str) -> std::io::Result<String> {
    print!("{label} [{default}]: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() { Ok(default.to_string()) } else { Ok(input.to_string()) }
}

fn run_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = client::Config::load().unwrap_or_else(|_| client::Config {
        server_url: "https://localhost:8803".to_string(),
        base_dir: PathBuf::from("C:/"),
        username: String::new(),
        password: String::new(),
        server_fingerprint: String::new(),
    });

    println!("blob configuration");
    println!("Press Enter to keep current value.\n");

    let server_url = prompt("Server URL", &config.server_url)?;
    let base_dir = prompt("Base install directory", &config.base_dir.display().to_string())?;
    let username = prompt("Username", &config.username)?;
    let password = prompt("Password", &config.password)?;

    let base_dir = PathBuf::from(base_dir);
    let base_dir = dunce::canonicalize(&base_dir).unwrap_or(base_dir);

    let new_config = client::Config {
        server_url,
        base_dir,
        username,
        password,
        server_fingerprint: config.server_fingerprint.clone(),
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
