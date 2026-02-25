mod acl;
mod acl_cli;
mod auth;
mod config;
mod did_key;
#[cfg(feature = "setup")]
mod did_webvh;
mod error;
mod import_did;
mod keys;
mod messaging;
mod routes;
mod server;
#[cfg(feature = "setup")]
mod setup;
mod status;
mod store;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use config::{AppConfig, LogFormat};
use keys::seed_store::create_secret_store;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "vtc", about = "Verifiable Trust Community", version)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the interactive setup wizard
    Setup,
    /// Show VTC status and statistics
    Status,
    /// Create a did:key (offline, no server required)
    CreateDidKey {
        /// Also create an ACL entry with Admin role for the new DID
        #[arg(long)]
        admin: bool,
        /// Human-readable label for the ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Create a did:webvh DID (interactive wizard, no server required)
    CreateDidWebvh {
        /// Human-readable label prefix for key records
        #[arg(long)]
        label: Option<String>,
    },
    /// Import an external DID and create an ACL entry (offline, no server required)
    ImportDid {
        /// The DID to import
        #[arg(long)]
        did: String,
        /// Role to assign (admin, initiator, application)
        #[arg(long)]
        role: Option<String>,
        /// Human-readable label for the ACL entry
        #[arg(long)]
        label: Option<String>,
    },
    /// Manage Access Control List entries (offline, no server required)
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List all ACL entries
    List {
        /// Filter by context
        #[arg(long)]
        context: Option<String>,
        /// Filter by role (admin, initiator, application)
        #[arg(long)]
        role: Option<String>,
    },
    /// Show details of a single ACL entry
    Get {
        /// The DID to look up
        did: String,
    },
    /// Update an existing ACL entry
    Update {
        /// The DID to update
        did: String,
        /// New role (admin, initiator, application)
        #[arg(long)]
        role: Option<String>,
        /// New label (empty string to clear)
        #[arg(long)]
        label: Option<String>,
        /// New context list (comma-separated; omit flag to keep unchanged)
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
    },
    /// Delete an ACL entry
    Delete {
        /// The DID to delete
        did: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Some(Commands::Setup) => {
            #[cfg(feature = "setup")]
            {
                if let Err(e) = setup::run_setup_wizard(cli.config).await {
                    eprintln!("Setup failed: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                eprintln!("Setup wizard not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::Status) => {
            if let Err(e) = status::run_status(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidKey { admin, label }) => {
            let args = did_key::CreateDidKeyArgs {
                config_path: cli.config,
                admin,
                label,
            };
            if let Err(e) = did_key::run_create_did_key(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::CreateDidWebvh { label }) => {
            #[cfg(feature = "setup")]
            {
                let args = did_webvh::CreateDidWebvhArgs {
                    config_path: cli.config,
                    label,
                };
                if let Err(e) = did_webvh::run_create_did_webvh(args).await {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
            #[cfg(not(feature = "setup"))]
            {
                let _ = label;
                eprintln!("create-did-webvh is not available (compiled without 'setup' feature)");
                std::process::exit(1);
            }
        }
        Some(Commands::ImportDid { did, role, label }) => {
            let args = import_did::ImportDidArgs {
                config_path: cli.config,
                did,
                role,
                label,
            };
            if let Err(e) = import_did::run_import_did(args).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Acl { command }) => {
            let result = match command {
                AclCommands::List { context, role } => {
                    acl_cli::run_acl_list(cli.config, context, role).await
                }
                AclCommands::Get { did } => acl_cli::run_acl_get(cli.config, did).await,
                AclCommands::Update {
                    did,
                    role,
                    label,
                    contexts,
                } => acl_cli::run_acl_update(cli.config, did, role, label, contexts).await,
                AclCommands::Delete { did, yes } => {
                    acl_cli::run_acl_delete(cli.config, did, yes).await
                }
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => {
            let config = match AppConfig::load(cli.config) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error: {e}");
                    eprintln!();
                    eprintln!("To set up a new VTC instance, run:");
                    eprintln!("  vtc setup");
                    eprintln!();
                    eprintln!("Or specify a config file:");
                    eprintln!("  vtc --config <path>");
                    std::process::exit(1);
                }
            };

            init_tracing(&config);

            let store = store::Store::open(&config.store).expect("failed to open store");
            let secret_store = create_secret_store(&config).expect("failed to create secret store");

            if let Err(e) = server::run(config, store, secret_store).await {
                tracing::error!("server error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} ██████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔════╝{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}██║     {reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██║     {reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}╚██████╗{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow} ╚═════╝{reset}
{dim}  Verifiable Trust Community v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

fn init_tracing(config: &AppConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    match config.log.format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Text => subscriber.init(),
    }
}
