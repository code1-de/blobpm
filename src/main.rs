use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::path::PathBuf;

mod client;
mod install;
mod platform;
mod remove;
mod repo;
mod server;
#[cfg(all(windows, target_pointer_width = "64"))]
mod shim;
#[cfg(test)]
mod testutil;
mod tls;
mod upload;
mod util;

#[derive(Parser)]
#[command(
    name = "blob",
    about = format!("blob package manager {} by Christoph Lüders — https://lueders.io", env!("CARGO_PKG_VERSION")),
    version,
)]
struct Cli {
    /// Non-interactive mode: answer yes to prompts, never enter interactive input
    #[arg(long, short, global = true)]
    yes: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install packages (use name@version for a specific version)
    Install {
        /// Package names, or name@version for specific versions
        names: Vec<String>,

        /// Reinstall even if already installed (e.g. to change version)
        #[arg(long, short)]
        force: bool,

        /// Ignore cached zip files, always download from server
        #[arg(long, short = 'C')]
        no_cache: bool,

        /// Install even if files conflict with other packages
        #[arg(long, short = 'o')]
        overwrite: bool,
    },
    /// Remove packages (auto-removes orphaned auto-installed dependencies)
    Remove {
        /// Package names
        names: Vec<String>,

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
        /// Package names (updates all if omitted)
        names: Vec<String>,

        /// Show what would be updated without actually doing it
        #[arg(long, short = 'n')]
        dry_run: bool,

        /// Install even if files conflict with other packages
        #[arg(long, short = 'o')]
        overwrite: bool,
    },
    /// List installed packages (with package names: show details)
    List {
        /// Package names (optional, show deps, files, install reason)
        names: Vec<String>,

        /// Show details for all packages (deps, files)
        #[arg(long, short = 'l')]
        long: bool,

        /// Show only manually installed packages
        #[arg(long, short)]
        manual: bool,
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

        /// Show details: all versions, deps, files (use pattern@version to inspect a specific version)
        #[arg(long, short = 'l')]
        long: bool,
    },
    /// Show details of a remote package (files, deps, description)
    Info {
        /// Package name, or name@version for a specific version
        package: String,
    },
    /// Configure blob settings interactively (server URL, base dir, credentials)
    Config,
    /// Mark packages as manually installed (prevents auto-removal as orphan)
    Manual {
        /// Package names
        names: Vec<String>,
    },
    /// Remove all orphaned auto-installed packages (auto deps no longer needed)
    Purge,
    /// Delete leftover *.__blob__ files from in-use renames during updates
    Cleanup {
        /// Internal: called by self-update to retry cleanup in a specific directory
        #[arg(long, hide = true)]
        self_update: Option<PathBuf>,
    },
    /// Clean the download cache (delete cached zip files)
    CleanCache {
        /// Max age in days (0 = delete all, default: `cache_days` from config)
        days: Option<u32>,
    },
    /// Run the package server
    Serve {
        /// Path to server config file (JSON with repo, bind, port, log, users)
        config: PathBuf,
    },
    /// Upload a package to the server
    ///
    /// Maps files to destination dirs using glob:dest patterns.
    /// Multiple files can share a dest with semicolons: "a.exe;b.dll:bin"
    /// Absolute globs use filename only, relative globs preserve path from --from.
    /// Meta-packages (no files, only deps): omit mappings, use --dep only.
    ///
    /// Examples:
    ///   blob upload tool@1.0 "*.exe:bin"
    ///   blob upload tool@1.0 "a.exe;b.chm:bin" "git/**:bin"
    ///   blob upload devtools@1.0 --dep fd --dep ripgrep -d "Dev bundle"
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

        /// Shim link: "dest:target" — create a shim exe at dest that launches target
        /// (both relative paths). Example: --link "bin/git.exe:git/mingw64/bin/git.exe"
        #[arg(long)]
        link: Vec<String>,

        /// Package description
        #[arg(long, short, default_value = "")]
        description: String,

        /// Interactive mode — review and edit all fields before uploading
        #[arg(long, short)]
        interactive: bool,

        /// Overwrite if version already exists on server
        #[arg(long, short)]
        force: bool,

        /// Lowercase all filenames in the manifest and zip
        #[arg(long, short = 'L')]
        lowercase: bool,
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
        "Limits:\n  Max upload size: {} MB\n  Max concurrent connections: {} ({} per IP)\n  Auth lockout: {} failures per IP, exponential backoff {}s–{}s\n  Request timeout: {}s",
        server::MAX_UPLOAD_SIZE / 1024 / 1024,
        server::MAX_CONCURRENT,
        server::MAX_CONNECTIONS_PER_IP,
        server::MAX_AUTH_FAILURES,
        server::BASE_LOCKOUT_SECS,
        server::MAX_LOCKOUT_SECS,
        server::REQUEST_TIMEOUT_SECS,
    );
    let upload_limits = format!(
        "Limits:\n  Max upload size: {} MB\n\nExit codes:\n  0  Success\n  1  Error\n  2  Version already exists (use --force to overwrite)",
        server::MAX_UPLOAD_SIZE / 1024 / 1024,
    );
    let cmd = Cli::command()
        .mut_subcommand("install", |c| c.after_help(install_limits))
        .mut_subcommand("serve", |c| c.after_help(serve_limits))
        .mut_subcommand("upload", |c| c.after_help(upload_limits));
    let cli = Cli::from_arg_matches(&cmd.get_matches()).expect("cli parse");

    if let Err(e) = run_command(&cli.command, cli.yes) {
        let msg = e.to_string();
        if let Some((first, rest)) = msg.split_once('\n') {
            eprintln!("{}\n{rest}", util::red(&format!("Error: {first}")));
        } else {
            eprintln!("{}", util::red(&format!("Error: {msg}")));
        }
        let code =
            if e.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) {
                2
            } else {
                1
            };
        std::process::exit(code);
    }
}

#[allow(clippy::too_many_lines)]
fn run_command(command: &Commands, yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Serve { config } => {
            let content = std::fs::read_to_string(config)
                .map_err(|e| format!("Cannot read server config {}: {e}", config.display()))?;
            let server_config: server::ServerConfig = serde_json::from_str(&content)
                .map_err(|e| format!("Invalid server config {}: {e}", config.display()))?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(server_config))?;
        }
        Commands::Install { names, force, no_cache, overwrite } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config, yes)?;
            let mut db = client::Database::load()?;
            for name in names {
                let (pkg_name, version) = parse_package_spec(name);
                install::install(&pkg_name, version.as_deref(), *force, *no_cache, *overwrite, &http, &mut db)?;
            }
        }
        Commands::Search { pattern, versions, description, long } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config, yes)?;
            let (search_pattern, pin_version) = if let Some((p, v)) = pattern.split_once('@') {
                (p.to_string(), Some(v.to_string()))
            } else {
                (pattern.clone(), None)
            };
            upload::search(&search_pattern, *versions || *long, *description, *long, pin_version.as_deref(), &http)?;
        }
        Commands::Info { package } => {
            let (pkg_name, version) = parse_package_spec(package);
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config, yes)?;
            run_info(&pkg_name, version.as_deref(), &http)?;
        }
        Commands::Remove { names, force, transitive, keep } => {
            let mut db = client::Database::load()?;
            for name in names {
                remove::remove(name, *force, *transitive, *keep, &mut db)?;
            }
        }
        Commands::Manual { names } => {
            let mut db = client::Database::load()?;
            let mut changed = false;
            for name in names {
                match db.packages.get_mut(name.as_str()) {
                    Some(pkg) => {
                        if pkg.reason == client::InstallReason::Manual {
                            println!("{name} is already marked as manual");
                        } else {
                            pkg.reason = client::InstallReason::Manual;
                            changed = true;
                            println!("{name} marked as manually installed");
                        }
                    }
                    None => {
                        eprintln!("{name} is not installed");
                    }
                }
            }
            if changed {
                db.save()?;
            }
        }
        Commands::Purge => {
            let mut db = client::Database::load()?;
            remove::purge(&mut db)?;
        }
        Commands::Cleanup { self_update } => {
            if let Some(dir) = self_update {
                // Self-update mode: retry cleanup in a specific directory
                let count = platform::cleanup_with_retry(dir);
                if count > 0 {
                    println!("Cleaned {count} leftover file{}.", util::plural(count as usize));
                }
            } else {
                // Derive roots from config (base_dir + path_map values + own exe dir)
                let config = client::Config::load()?;
                let mut roots = std::collections::HashSet::new();
                roots.insert(config.base_dir.clone());
                for mapped in config.path_map.values() {
                    roots.insert(mapped.clone());
                }
                if let Ok(exe) = std::env::current_exe()
                    && let Some(dir) = exe.parent()
                {
                    roots.insert(dir.to_path_buf());
                }
                let count = platform::cleanup_blob_renames(&roots);
                if count > 0 {
                    println!("Cleaned {count} leftover file{}.", util::plural(count as usize));
                } else {
                    println!("Nothing to clean up.");
                }
            }
        }
        Commands::CleanCache { days } => {
            let config = client::Config::load()?;
            let max_days = days.unwrap_or(config.cache_days);
            println!("Cleaning cache (max age: {max_days} day{})...", util::plural(max_days as usize));
            install::clean_cache(&config.cache_dir()?, max_days, true);
        }
        Commands::Update { names, dry_run, overwrite } => {
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config, yes)?;
            let mut db = client::Database::load()?;
            if names.is_empty() {
                install::update(None, *dry_run, *overwrite, &http, &mut db)?;
            } else {
                for name in names {
                    install::update(Some(name.as_str()), *dry_run, *overwrite, &http, &mut db)?;
                }
            }
        }
        Commands::List { names, long, manual } => {
            let db = client::Database::load()?;
            if db.packages.is_empty() {
                println!("No packages installed.");
            } else {
                let packages: Vec<_> = if names.is_empty() {
                    db.packages
                        .iter()
                        .filter(|(_, pkg)| !manual || pkg.reason == client::InstallReason::Manual)
                        .map(|(n, _)| n.as_str())
                        .collect()
                } else {
                    let mut list = Vec::new();
                    for n in names {
                        if db.packages.contains_key(n.as_str()) {
                            list.push(n.as_str());
                        } else {
                            eprintln!("{n} is not installed");
                        }
                    }
                    list
                };
                let show_details = *long || !names.is_empty();
                if show_details {
                    for n in &packages {
                        let pkg = &db.packages[*n];
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
                    }
                } else {
                    let rows: Vec<_> = packages
                        .iter()
                        .map(|n| {
                            let pkg = &db.packages[*n];
                            let reason = if pkg.reason == client::InstallReason::Auto { "auto" } else { "" };
                            (*n, pkg.version.as_str(), reason)
                        })
                        .collect();
                    let w0 = rows.iter().map(|(n, _, _)| n.len()).max().unwrap_or(0);
                    let w1 = rows.iter().map(|(_, v, _)| v.len()).max().unwrap_or(0);
                    for (n, version, reason) in &rows {
                        if reason.is_empty() {
                            println!("{n:<w0$}  {version}");
                        } else {
                            println!("{n:<w0$}  {version:<w1$}  ({reason})");
                        }
                    }
                }
            }
        }
        Commands::Upload { package, mappings, from, deps, link, description, interactive, force, lowercase } => {
            let (pkg_name, version) = parse_package_spec(package);
            let version = version.ok_or("Version required: use name@version")?;
            let config = client::Config::load()?;
            let http = client::HttpClient::new(&config, yes)?;

            if *interactive && !yes {
                upload::upload_interactive(
                    &pkg_name,
                    &version,
                    from,
                    mappings,
                    deps,
                    link,
                    description,
                    *force,
                    *lowercase,
                    &http,
                )?;
            } else if mappings.is_empty() && deps.is_empty() {
                return Err("No file mappings or dependencies provided. Use glob:dest patterns, --dep, or -i for interactive mode.".into());
            } else {
                upload::upload(
                    &pkg_name,
                    &version,
                    from,
                    mappings,
                    deps,
                    link,
                    description,
                    *force,
                    *lowercase,
                    &http,
                )?;
            }
        }
        Commands::Status { paths, all, missing, no_recurse, depth } => {
            let db = client::Database::load()?;
            let dirs: Vec<PathBuf> = if paths.is_empty() { vec![std::env::current_dir()?] } else { paths.clone() };
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
            let http = client::HttpClient::new(&config, yes)?;
            let url = format!("{}/packages/{pkg_name}/{version}", config.server_url);
            let resp = http.delete(&url)?;
            if resp.status().is_success() {
                println!("Deleted {pkg_name}@{version}");
            } else {
                return Err(format!("Failed to delete {pkg_name}@{version}: {}", resp.status()).into());
            }
        }
        Commands::GenerateKeys { force } => {
            tls::generate_keys(*force || yes)?;
        }
        Commands::Config => {
            if yes {
                return Err("config is interactive — cannot be used with --yes".into());
            }
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

fn run_info(name: &str, version: Option<&str>, http: &client::HttpClient) -> Result<(), Box<dyn std::error::Error>> {
    client::validate_pkg_spec("package name", name)?;

    let version = if let Some(v) = version {
        v.to_string()
    } else {
        let index = install::fetch_index(http)?;
        index.get(name).ok_or_else(|| format!("Package {name} not found in index"))?.latest.clone()
    };

    let manifest = install::fetch_manifest(http, name, &version)?;
    let config = client::Config::load()?;

    println!("{name} {version}");
    if !manifest.description.is_empty() {
        println!("  {}", manifest.description);
    }
    if !manifest.dependencies.is_empty() {
        println!("  Dependencies: {}", manifest.dependencies.join(", "));
    }
    if manifest.files.is_empty() {
        println!("  (meta-package, no files)");
    } else {
        println!("  Files:");
        for (file, dest_dir) in &manifest.files {
            let dest = config.resolve_dest(dest_dir).join(file);
            println!("    {file} -> {}", dest.display());
        }
    }
    if !manifest.links.is_empty() {
        println!("  Links:");
        for (dest, target) in &manifest.links {
            let dest_path = config.resolve_dest(dest);
            let target_path = config.resolve_dest(target);
            println!("    {} -> {}", dest_path.display(), target_path.display());
        }
    }
    Ok(())
}

fn run_status(
    dir: &std::path::Path,
    db: &client::Database,
    show_all: bool,
    show_missing: bool,
    max_depth: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        println!(
            "\n{managed} managed, {unmanaged} unmanaged, {missing_count} missing, {} on disk",
            managed + unmanaged
        );
    } else {
        println!("\n{managed} managed, {unmanaged} unmanaged, {} on disk", managed + unmanaged);
    }
    Ok(())
}

fn collect_files(
    dir: &std::path::Path,
    out: &mut Vec<PathBuf>,
    current_depth: usize,
    max_depth: Option<usize>,
) -> std::io::Result<()> {
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
        server_url: "https://lueders.io:53777".to_string(),
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

    let base_dir = PathBuf::from(&base_dir);
    if !base_dir.is_absolute() {
        return Err(format!("Base directory must be an absolute path: {}", base_dir.display()).into());
    }
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
            if !path.is_absolute() {
                println!("  Path must be absolute: {}", path.display());
                continue;
            }
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

    // Offer to install blob itself from the server
    let answer = upload::prompt_line("Install blob from the server?", "Y")?;
    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        match client::HttpClient::new(&new_config, false) {
            Ok(http) => {
                let mut db = client::Database::load()?;
                if let Err(e) = install::install("blob", None, false, false, false, &http, &mut db) {
                    eprintln!("Could not install blob: {e}");
                }
            }
            Err(e) => eprintln!("Could not connect to server: {e}"),
        }
    }

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
