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

    if let Err(e) = run_command(&cli.command) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run_command(command: &Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Serve { repo, port } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(repo.clone(), *port))?;
        }
        Commands::Install { name } => {
            let config = client::Config::load()?;
            let mut db = client::Database::load()?;
            client::install(name, &config, &mut db)?;
        }
        Commands::Remove { name } => {
            println!("Removing {name}");
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
        Commands::Update => {
            println!("Updating all packages");
        }
        Commands::List => {
            let db = client::Database::load()?;
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
            run_config()?;
        }
    }
    Ok(())
}

fn prompt(label: &str, default: &str) -> std::io::Result<String> {
    print!("{label} [{default}]: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input.to_string())
    }
}

fn run_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = client::Config::load().unwrap_or_else(|_| client::Config {
        server_url: "http://localhost:8803".to_string(),
        base_dir: PathBuf::from("C:/"),
    });

    println!("blob configuration");
    println!("Press Enter to keep current value.\n");

    let server_url = prompt("Server URL", &config.server_url)?;
    let base_dir = prompt("Base install directory", &config.base_dir.display().to_string())?;

    let base_dir = PathBuf::from(base_dir);
    let base_dir = dunce::canonicalize(&base_dir).unwrap_or(base_dir);

    let new_config = client::Config {
        server_url,
        base_dir,
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
