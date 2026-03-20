use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

mod client;
mod repo;
mod server;

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
    },
    /// Install a package
    Install {
        /// Package name
        name: String,
    },
    /// Remove an installed package
    Remove {
        /// Package name
        name: String,
    },
    /// Mark a package as manually installed
    Manual {
        /// Package name
        name: String,
    },
    /// Update all installed packages
    Update,
    /// List installed packages
    List,
    /// Configure blob settings
    Config,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Serve { repo, port } => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
            rt.block_on(server::run(repo.clone(), *port))
                .expect("Server error");
        }
        Commands::Install { name } => {
            let config = client::Config::load().expect("Failed to load config. Run 'blob config' first.");
            let mut db = client::Database::load().expect("Failed to load database");
            client::install(name, &config, &mut db).expect("Install failed");
        }
        Commands::Remove { name } => {
            println!("Removing {name}");
        }
        Commands::Manual { name } => {
            let mut db = client::Database::load().expect("Failed to load database");
            match db.packages.get_mut(name.as_str()) {
                Some(pkg) => {
                    if pkg.reason == client::InstallReason::Manual {
                        println!("{name} is already marked as manual");
                    } else {
                        pkg.reason = client::InstallReason::Manual;
                        db.save().expect("Failed to save database");
                        println!("{name} marked as manually installed");
                    }
                }
                None => {
                    eprintln!("{name} is not installed");
                }
            }
        }
        Commands::Update => {
            println!("Updating all packages");
        }
        Commands::List => {
            let db = client::Database::load().expect("Failed to load database");
            if db.packages.is_empty() {
                println!("No packages installed.");
            } else {
                for (name, pkg) in &db.packages {
                    let reason = match pkg.reason {
                        client::InstallReason::Manual => "manual",
                        client::InstallReason::Auto => "auto",
                    };
                    println!("{name} {} [{reason}]", pkg.version);
                }
            }
        }
        Commands::Config => {
            run_config();
        }
    }
}

fn prompt(label: &str, default: &str) -> String {
    print!("{label} [{default}]: ");
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();
    if input.is_empty() {
        default.to_string()
    } else {
        input.to_string()
    }
}

fn run_config() {
    let config = client::Config::load().unwrap_or_else(|_| client::Config {
        server_url: "http://localhost:8803".to_string(),
        base_dir: PathBuf::from("C:/"),
    });

    println!("blob configuration");
    println!("Press Enter to keep current value.\n");

    let server_url = prompt("Server URL", &config.server_url);
    let base_dir = prompt("Base install directory", &config.base_dir.display().to_string());

    let base_dir = PathBuf::from(base_dir);
    let base_dir = dunce::canonicalize(&base_dir).unwrap_or(base_dir);

    let new_config = client::Config {
        server_url,
        base_dir,
    };

    new_config.save().expect("Failed to save config");
    println!("\nConfig saved.");
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
