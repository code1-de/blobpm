use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
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
    about = format!("blob package manager {} by Christoph Lüders — https://lueders.io", env!("CARGO_PKG_VERSION")),
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

        /// Show what would be updated without actually doing it
        #[arg(long, short = 'n')]
        dry_run: bool,
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

        /// Also search in package descriptions
        #[arg(long, short)]
        description: bool,
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
    CleanCache {
        /// Max age in days (0 = delete all, default: `cache_days` from config)
        days: Option<u32>,
    },
    /// Run the package server
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

        /// Path to log file (appended to; if omitted, only stdout)
        #[arg(long)]
        log: Option<PathBuf>,
    },
    /// Upload a package to the server
    ///
    /// Maps files to destination dirs using glob:dest patterns.
    /// Multiple files can share a dest with semicolons: "a.exe;b.dll:bin"
    /// Absolute globs use filename only, relative globs preserve path from --from.
    /// Examples: "*.exe:bin" "a.exe;b.chm:bin" "git/**:bin" --from src "lib/**:lib"
    Upload {
        /// Package name@version (e.g. helper@3.0)
        package: String,

        /// File mappings: "glob:dest" or "a;b;c:dest" (first match wins). Relative to --from
        mappings: Vec<String>,

        /// Base directory for relative glob patterns
        #[arg(long, default_value = ".")]
        from: PathBuf,

        /// Package dependency (can be repeated: --dep zip --dep helper)
        #[arg(long = "dep", short = 'D')]
        deps: Vec<String>,

        /// Package description
        #[arg(long, short, default_value = "")]
        description: String,

        /// Interactive mode — review and edit all fields before uploading
        #[arg(long, short)]
        interactive: bool,

        /// Overwrite if version already exists on server
        #[arg(long, short)]
        force: bool,
    },
    /// Show which files in a directory are managed by blob
    #[command(alias = "st")]
    Status {
        /// Directories to scan (default: current directory)
        paths: Vec<PathBuf>,

        /// Show all files including unmanaged ones (marked with ?)
        #[arg(long, short)]
        all: bool,

        /// Show installed files that are missing from disk (marked with !)
        #[arg(long, short)]
        missing: bool,

        /// Don't recurse into subdirectories
        #[arg(long, short = 'N')]
        no_recurse: bool,

        /// Maximum directory depth (0 = only files in the given directory)
        #[arg(long)]
        depth: Option<usize>,
    },
    /// Delete a package version from the server
    Delete {
        /// Package name@version (e.g. helper@3.0)
        package: String,
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
    let install_limits = format!(
        "Limits:\n  Max file size per extracted file: {} GB\n  Max total extraction size: {} GB\n  Max zip entries: {}",
        install::MAX_EXTRACT_SIZE / 1024 / 1024 / 1024,
        install::MAX_TOTAL_EXTRACT_SIZE / 1024 / 1024 / 1024,
        install::MAX_ZIP_ENTRIES,
    );
    let serve_limits = format!(
        "Limits:\n  Max upload size: {} MB\n  Max concurrent connections: {}\n  Auth lockout: {} failures per IP / {} global in {} seconds",
        server::MAX_UPLOAD_SIZE / 1024 / 1024,
        server::MAX_CONCURRENT,
        server::MAX_AUTH_FAILURES,
        server::MAX_GLOBAL_AUTH_FAILURES,
        server::AUTH_LOCKOUT_SECS,
    );
    let upload_limits = format!(
        "Limits:\n  Max upload size: {} MB",
        server::MAX_UPLOAD_SIZE / 1024 / 1024,
    );
    let cmd = Cli::command()
        .mut_subcommand("install", |c| c.after_help(install_limits))
        .mut_subcommand("serve", |c| c.after_help(serve_limits))
        .mut_subcommand("upload", |c| c.after_help(upload_limits));
    let cli = Cli::from_arg_matches(&cmd.get_matches()).expect("cli parse");

    if let Err(e) = run_command(&cli.command) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run_command(command: &Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Serve { repo, bind, port, username, password, log } => {
            if std::env::var("BLOB_PASSWORD").is_err() {
                eprintln!("Warning: password passed via command line — visible in process listings.");
                eprintln!("         Prefer setting BLOB_PASSWORD environment variable instead.");
            }
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(repo.clone(), bind, *port, (username.clone(), password.clone()), log.clone()))?;
        }
        Commands::Install { name, force } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            let mut db = client::Database::load()?;
            let (pkg_name, version) = parse_package_spec(name);
            install::install(&pkg_name, version.as_deref(), *force, &http, &mut db)?;
        }
        Commands::Search { pattern, versions, description } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            upload::search(pattern, *versions, *description, &http)?;
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
        Commands::CleanCache { days } => {
            let config = client::Config::load()?;
            let max_days = days.unwrap_or(config.cache_days);
            println!("Cleaning cache (max age: {max_days} day(s))...");
            install::clean_cache(&config.cache_dir()?, max_days);
        }
        Commands::Update { name, dry_run } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            let mut db = client::Database::load()?;
            install::update(name.as_deref(), *dry_run, &http, &mut db)?;
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
        Commands::Status { paths, all, missing, no_recurse, depth } => {
            let db = client::Database::load()?;
            let dirs: Vec<PathBuf> = if paths.is_empty() {
                vec![std::env::current_dir()?]
            } else {
                paths.clone()
            };
            let max_depth = if *no_recurse { Some(0) } else { *depth };
            for dir in &dirs {
                if dirs.len() > 1 {
                    println!("{}:", dir.display());
                }
                run_status(dir, &db, *all, *missing, max_depth)?;
                if dirs.len() > 1 {
                    println!();
                }
            }
        }
        Commands::Delete { package } => {
            let (pkg_name, version) = parse_package_spec(package);
            let version = version.ok_or("Version required: use name@version")?;
            client::validate_pkg_spec("package name", &pkg_name)?;
            client::validate_pkg_spec("version", &version)?;
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config)?;
            let url = format!("{}/packages/{pkg_name}/{version}", config.server_url);
            let resp = http.delete(&url)?;
            if resp.status().is_success() {
                println!("Deleted {pkg_name}@{version}");
            } else {
                return Err(format!("Failed to delete {pkg_name}@{version}: {}", resp.status()).into());
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

fn run_status(dir: &std::path::Path, db: &client::Database, show_all: bool, show_missing: bool, max_depth: Option<usize>) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;

    let dir = dunce::canonicalize(dir).map_err(|e| format!("Cannot access {}: {e}", dir.display()))?;

    // Build reverse map: canonical file path -> "pkg version"
    let mut owned: BTreeMap<PathBuf, String> = BTreeMap::new();
    for (pkg_name, pkg) in &db.packages {
        let label = format!("{pkg_name} {}", pkg.version);
        for dest_path in pkg.files.values() {
            owned.insert(dest_path.clone(), label.clone());
        }
    }

    // Walk directory
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_files(&dir, &mut entries, 0, max_depth)?;
    entries.sort();

    if entries.is_empty() && !show_missing {
        println!("No files in {}", dir.display());
        return Ok(());
    }

    let mut managed = 0u32;
    let mut unmanaged = 0u32;
    let mut missing_count = 0u32;
    let entries_set: std::collections::HashSet<&PathBuf> = entries.iter().collect();
    for path in &entries {
        let display = path.strip_prefix(&dir).unwrap_or(path);
        if let Some(label) = owned.get(path) {
            println!("  {:<50} [{label}]", display.display());
            managed += 1;
        } else {
            unmanaged += 1;
            if show_all {
                println!("? {}", display.display());
            }
        }
    }

    // Show files that should be under this dir but are missing from disk
    if show_missing {
        for (path, label) in &owned {
            if path.starts_with(&dir) && !entries_set.contains(path) {
                let display = path.strip_prefix(&dir).unwrap_or(path);
                println!("! {:<50} [{label}]", display.display());
                missing_count += 1;
            }
        }
    }

    if show_missing && missing_count > 0 {
        println!("\n{managed} managed, {unmanaged} unmanaged, {missing_count} missing, {} on disk", managed + unmanaged);
    } else {
        println!("\n{managed} managed, {unmanaged} unmanaged, {} on disk", managed + unmanaged);
    }
    Ok(())
}

fn collect_files(dir: &std::path::Path, out: &mut Vec<PathBuf>, current_depth: usize, max_depth: Option<usize>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if max_depth.is_none_or(|max| current_depth < max) {
                collect_files(&path, out, current_depth + 1, max_depth)?;
            }
        } else {
            out.push(path);
        }
    }
    Ok(())
}

fn run_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = client::Config::load().unwrap_or_else(|_| client::Config {
        server_url: "https://localhost:53777".to_string(),
        base_dir: PathBuf::from("C:/"),
        username: String::new(),
        password: String::new(),
        server_fingerprint: String::new(),
        cache_days: 1,
        path_map: std::collections::BTreeMap::new(),
        cache_dir: None,
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

    // Path mappings
    let mut path_map = config.path_map.clone();
    if path_map.is_empty() {
        println!("\nPath mappings: (none — all files install under base dir)");
    } else {
        println!("\nPath mappings:");
        for (key, target) in &path_map {
            println!("  {key} -> {}", target.display());
        }
    }
    println!("Enter mappings as 'segment=path' to add, '-segment' to remove, empty to finish.");
    loop {
        let line = upload::prompt_line("Path map", "")?;
        if line.is_empty() {
            break;
        }
        if let Some(key) = line.strip_prefix('-') {
            if path_map.remove(key.trim()).is_some() {
                println!("  Removed mapping for '{}'", key.trim());
            } else {
                println!("  No mapping for '{}'", key.trim());
            }
        } else if let Some((key, path)) = line.split_once('=') {
            let path = PathBuf::from(path.trim());
            let path = dunce::canonicalize(&path).unwrap_or(path);
            path_map.insert(key.trim().to_string(), path.clone());
            println!("  {} -> {}", key.trim(), path.display());
        } else {
            println!("  Format: segment=path or -segment");
        }
    }

    let new_config = client::Config {
        server_url,
        base_dir,
        username,
        password,
        server_fingerprint: config.server_fingerprint.clone(),
        cache_days,
        path_map,
        cache_dir: None,
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
