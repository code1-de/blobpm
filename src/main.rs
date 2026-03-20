use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod repo;
mod server;

#[derive(Parser)]
#[command(name = "blob", about = "A simple package manager for Windows")]
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
        #[arg(long, default_value = "8080")]
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
    /// Update all installed packages
    Update,
    /// List installed packages
    List,
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
            println!("Installing {name}");
        }
        Commands::Remove { name } => {
            println!("Removing {name}");
        }
        Commands::Update => {
            println!("Updating all packages");
        }
        Commands::List => {
            println!("Listing installed packages");
        }
    }
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
