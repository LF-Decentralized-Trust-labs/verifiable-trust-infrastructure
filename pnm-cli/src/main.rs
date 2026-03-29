mod auth;
mod config;
mod setup;

use clap::{Parser, Subcommand};
use vta_sdk::client::VtaClient;

use vta_cli_common::commands::{acl, audit, config as config_cmd, contexts, credentials, keys, webvh};
use vta_cli_common::render::{CYAN, DIM, GREEN, RED, RESET};

#[derive(Parser)]
#[command(
    name = "pnm-cli",
    about = "CLI for managing a personal Verifiable Trust Agent"
)]
struct Cli {
    /// Base URL of the VTA service (overrides config)
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// VTA slug to use (overrides default)
    #[arg(short, long, env = "PNM_VTA", global = true)]
    vta: Option<String>,

    /// Enable verbose debug output (can also set RUST_LOG=debug)
    #[arg(short = 'V', long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Configure VTA URL and credentials
    Setup {
        /// Base64-encoded credential string (prompted interactively if omitted)
        #[arg(long)]
        credential: Option<String>,
    },

    /// Check service health
    Health,

    /// Authentication management
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Key management
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Application context management
    Contexts {
        #[command(subcommand)]
        command: ContextCommands,
    },

    /// Access control list management
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },

    /// Generate auth credentials for applications and services
    AuthCredential {
        #[command(subcommand)]
        command: AuthCredentialCommands,
    },

    /// WebVH server management
    Webvh {
        #[command(subcommand)]
        command: WebvhCommands,
    },

    /// Audit log management
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },

    /// Backup and restore VTA data
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },

    /// VTA connection management
    Vta {
        #[command(subcommand)]
        command: VtaCommands,
    },
}

#[derive(Subcommand)]
enum BackupCommands {
    /// Export VTA state to an encrypted backup file
    Export {
        /// Include audit logs in the backup
        #[arg(long)]
        include_audit: bool,
        /// Output file path (default: vta-backup-<timestamp>.vtabak)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Import VTA state from an encrypted backup file
    Import {
        /// Path to the .vtabak backup file
        file: std::path::PathBuf,
        /// Preview only — show what would be imported without applying
        #[arg(long)]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum VtaCommands {
    /// List configured VTAs
    List,
    /// Set the default VTA
    Use { slug: String },
    /// Remove a VTA connection
    Remove { slug: String },
    /// Show current VTA details
    Info,
    /// Restart the VTA service (soft restart — reloads config and reconnects)
    Restart,
}

#[derive(Subcommand)]
enum WebvhCommands {
    /// Add a WebVH server
    AddServer {
        /// Server identifier
        #[arg(long)]
        id: String,
        /// Server DID (must resolve to a DID document with a WebVHHostingService endpoint)
        #[arg(long)]
        did: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
    },
    /// List configured WebVH servers
    ListServers,
    /// Update a WebVH server
    UpdateServer {
        /// Server identifier to update
        id: String,
        /// New label (empty string to clear)
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a WebVH server
    RemoveServer {
        /// Server identifier to remove
        id: String,
    },
    /// Create a WebVH DID
    CreateDid {
        /// Application context ID
        #[arg(long)]
        context: String,
        /// WebVH server ID (mutually exclusive with --did-url)
        #[arg(long)]
        server: Option<String>,
        /// DID URL for serverless creation (mutually exclusive with --server)
        #[arg(long)]
        did_url: Option<String>,
        /// Optional path on the WebVH server
        #[arg(long)]
        path: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value = "true")]
        portable: bool,
        /// Add a mediator service endpoint
        #[arg(long)]
        mediator_service: bool,
        /// Additional service endpoints (JSON array)
        #[arg(long)]
        services: Option<String>,
        /// Number of pre-rotation keys to generate
        #[arg(long, default_value = "0")]
        pre_rotation: u32,
    },
    /// List WebVH DIDs
    ListDids {
        /// Filter by context ID
        #[arg(long)]
        context: Option<String>,
        /// Filter by server ID
        #[arg(long)]
        server: Option<String>,
    },
    /// Get details of a WebVH DID
    GetDid {
        /// The DID to look up
        did: String,
    },
    /// Delete a WebVH DID
    DeleteDid {
        /// The DID to delete
        did: String,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Import a credential and authenticate
    Login {
        /// Base64-encoded credential string from VTA administrator
        credential: String,
    },
    /// Clear stored credentials and tokens
    Logout,
    /// Show current authentication status
    Status,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Get current configuration
    Get,
    /// Update configuration
    Update {
        /// VTA DID
        #[arg(long)]
        community_vta_did: Option<String>,
        /// VTA name
        #[arg(long)]
        community_vta_name: Option<String>,
        /// Public URL for this VTA
        #[arg(long)]
        public_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum ContextCommands {
    /// List all application contexts
    List,
    /// Get a context by ID
    Get {
        /// Context ID (e.g. "vta")
        id: String,
    },
    /// Create a new application context
    Create {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
    },
    /// Update an existing context
    Update {
        /// Context ID
        id: String,
        /// New name
        #[arg(long)]
        name: Option<String>,
        /// Set the DID for this context
        #[arg(long)]
        did: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
    },
    /// Delete an application context and all associated resources
    Delete {
        /// Context ID
        id: String,
        /// Skip confirmation and delete immediately
        #[arg(long, short)]
        force: bool,
    },
    /// Create a context and generate credentials for its first admin
    Bootstrap {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Admin label
        #[arg(long)]
        admin_label: Option<String>,
    },
    /// Provision a new application context with a portable config bundle
    ///
    /// Creates a context, generates admin credentials, and optionally creates a
    /// WebVH DID. Outputs a single base64-encoded bundle that contains
    /// everything an application needs to connect, authenticate, and
    /// self-administer its context.
    Provision {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Admin label
        #[arg(long)]
        admin_label: Option<String>,
        /// Create a DID using this WebVH server (mutually exclusive with --did-url)
        #[arg(long)]
        server: Option<String>,
        /// Create a DID at this URL for self-hosting (mutually exclusive with --server)
        #[arg(long)]
        did_url: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value = "true")]
        portable: bool,
        /// Add a mediator service endpoint to the DID
        #[arg(long)]
        mediator_service: bool,
        /// Number of pre-rotation keys to generate
        #[arg(long, default_value = "0")]
        pre_rotation: u32,
    },
    /// Regenerate a provision bundle for an existing context
    ///
    /// Builds a new provision bundle using a VTA-stored key as the admin
    /// credential. Pass --key to specify a key ID directly, or omit it
    /// to interactively select from existing keys or create a new one.
    Reprovision {
        /// Context ID to reprovision
        #[arg(long)]
        id: String,
        /// Key ID of an existing VTA-stored Ed25519 key to use as admin credential
        #[arg(long)]
        key: Option<String>,
        /// Label for a newly created admin key (used when no --key is provided)
        #[arg(long)]
        admin_label: Option<String>,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List ACL entries
    List {
        /// Filter by context ID
        #[arg(long)]
        context: Option<String>,
    },
    /// Get an ACL entry by DID
    Get {
        /// DID to look up
        did: String,
    },
    /// Create an ACL entry
    Create {
        /// DID to grant access to
        #[arg(long)]
        did: String,
        /// Role: admin, initiator, or application
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
    },
    /// Update an ACL entry
    Update {
        /// DID of the entry to update
        did: String,
        /// New role
        #[arg(long)]
        role: Option<String>,
        /// New label
        #[arg(long)]
        label: Option<String>,
        /// New comma-separated context IDs
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
    },
    /// Delete an ACL entry
    Delete {
        /// DID of the entry to delete
        did: String,
    },
}

#[derive(Subcommand)]
enum AuthCredentialCommands {
    /// Generate a new auth credential (did:key + ACL entry) for a service or application
    Create {
        /// Role: admin, initiator, or application
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// List audit log entries with optional filtering
    List {
        /// Start time (unix epoch seconds)
        #[arg(long)]
        from: Option<u64>,
        /// End time (unix epoch seconds)
        #[arg(long)]
        to: Option<u64>,
        /// Filter by action (e.g. "auth.challenge", "key.create")
        #[arg(long)]
        action: Option<String>,
        /// Filter by actor DID
        #[arg(long)]
        actor: Option<String>,
        /// Filter by outcome (e.g. "success", "denied")
        #[arg(long)]
        outcome: Option<String>,
        /// Filter by context ID
        #[arg(long)]
        context_id: Option<String>,
        /// Page number (default 1)
        #[arg(long, default_value_t = 1)]
        page: u64,
        /// Page size (default 50, max 500)
        #[arg(long, default_value_t = 50)]
        page_size: u64,
    },
    /// Manage audit log retention
    Retention {
        #[command(subcommand)]
        command: RetentionCommands,
    },
}

#[derive(Subcommand, Debug)]
enum RetentionCommands {
    /// Get the current retention period
    Get,
    /// Set the retention period (super-admin only)
    Set {
        /// Number of days to retain audit logs (1-365)
        #[arg(long)]
        days: u32,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new key
    Create {
        /// Key type: ed25519 or x25519
        #[arg(long)]
        key_type: String,
        /// BIP-32 derivation path (auto-derived from context if omitted)
        #[arg(long)]
        derivation_path: Option<String>,
        /// BIP-39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Application context ID
        #[arg(long)]
        context_id: Option<String>,
    },
    /// Get a key by ID
    Get {
        /// Key ID
        key_id: String,
        /// Reveal private key material (multibase)
        #[arg(long)]
        secret: bool,
    },
    /// Revoke (invalidate) a key
    Revoke {
        /// Key ID
        key_id: String,
    },
    /// Rename a key
    Rename {
        /// Current key ID
        key_id: String,
        /// New key ID
        new_key_id: String,
    },
    /// List all keys
    List {
        /// Maximum number of keys to return
        #[arg(long, default_value = "50")]
        limit: u64,
        /// Number of keys to skip
        #[arg(long, default_value = "0")]
        offset: u64,
        /// Filter by status (active or revoked)
        #[arg(long)]
        status: Option<String>,
        /// Filter by application context ID
        #[arg(long)]
        context: Option<String>,
    },
    /// Export secret key material for one or more keys
    Secrets {
        /// Key IDs to export (omit to export all active keys in --context)
        key_ids: Vec<String>,
        /// Export all active keys in this context
        #[arg(long)]
        context: Option<String>,
    },
    /// Export a portable DID secrets bundle for a context
    Bundle {
        /// Application context ID whose DID and keys to bundle
        context: String,
    },
    /// List seed generations
    Seeds,
    /// Rotate to a new seed generation
    RotateSeed {
        /// BIP-39 mnemonic phrase for the new seed (random if omitted)
        #[arg(long)]
        mnemonic: Option<String>,
    },
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██████╗  {magenta}███╗   ██╗ {yellow}███╗   ███╗{reset}
{cyan} ██╔══██╗ {magenta}████╗  ██║ {yellow}████╗ ████║{reset}
{cyan} ██████╔╝ {magenta}██╔██╗ ██║ {yellow}██╔████╔██║{reset}
{cyan} ██╔═══╝  {magenta}██║╚██╗██║ {yellow}██║╚██╔╝██║{reset}
{cyan} ██║      {magenta}██║ ╚████║ {yellow}██║ ╚═╝ ██║{reset}
{cyan} ╚═╝      {magenta}╚═╝  ╚═══╝ {yellow}╚═╝     ╚═╝{reset}
{dim}  Personal Network Manager v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Returns true if this command requires authentication.
fn requires_auth(cmd: &Commands) -> bool {
    // VTA restart requires auth; other VTA subcommands don't
    if matches!(cmd, Commands::Vta { command: VtaCommands::Restart }) {
        return true;
    }
    !matches!(
        cmd,
        Commands::Health
            | Commands::Auth { .. }
            | Commands::Setup { .. }
            | Commands::Vta { .. }
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing: --verbose sets pnm_cli=debug, or respect RUST_LOG
    let filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("pnm_cli=debug")
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();

    print_banner();

    // Load PNM config
    let mut pnm_config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config: {e}");
            config::PnmConfig::default()
        }
    };

    // Save overrides before consuming
    let url_override = cli.url.clone();
    let vta_override = cli.vta.clone();

    // Handle commands that don't need VTA resolution
    match &cli.command {
        Commands::Setup { credential } => {
            let result = setup::run_setup(credential.as_deref(), &mut pnm_config).await;
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Vta { command } => {
            match command {
                VtaCommands::List => {
                    if pnm_config.vtas.is_empty() {
                        println!("No VTAs configured.");
                        println!("\nRun `pnm setup` to configure your first VTA.");
                    } else {
                        let default = pnm_config.default_vta.as_deref().unwrap_or("");
                        for (slug, vta) in &pnm_config.vtas {
                            let marker = if slug == default { " (default)" } else { "" };
                            println!("  {slug}{marker}");
                            println!("    Name: {}", vta.name);
                            if let Some(ref url) = vta.url {
                                println!("    URL:  {url}");
                            }
                            if let Some(ref did) = vta.vta_did {
                                println!("    DID:  {did}");
                            }
                            println!();
                        }
                    }
                }
                VtaCommands::Use { slug } => {
                    if !pnm_config.vtas.contains_key(slug) {
                        eprintln!(
                            "Error: VTA '{slug}' not found.\n\nConfigured VTAs: {}",
                            pnm_config
                                .vtas
                                .keys()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        std::process::exit(1);
                    }
                    pnm_config.default_vta = Some(slug.clone());
                    if let Err(e) = config::save_config(&pnm_config) {
                        eprintln!("Error saving config: {e}");
                        std::process::exit(1);
                    }
                    println!("Default VTA set to '{slug}'.");
                }
                VtaCommands::Remove { slug } => {
                    if !pnm_config.vtas.contains_key(slug) {
                        eprintln!("Error: VTA '{slug}' not found.");
                        std::process::exit(1);
                    }
                    pnm_config.vtas.remove(slug);
                    // Clear default if it was the removed VTA
                    if pnm_config.default_vta.as_deref() == Some(slug.as_str()) {
                        pnm_config.default_vta = pnm_config.vtas.keys().next().cloned();
                    }
                    // Clear the keyring entry
                    let key = config::vta_keyring_key(slug);
                    auth::logout(&key);
                    if let Err(e) = config::save_config(&pnm_config) {
                        eprintln!("Error saving config: {e}");
                        std::process::exit(1);
                    }
                    println!("VTA '{slug}' removed.");
                }
                VtaCommands::Info => {
                    match config::resolve_vta(vta_override.as_deref(), &pnm_config) {
                        Ok((slug, vta)) => {
                            println!("Active VTA: {slug}");
                            println!("  Name: {}", vta.name);
                            if let Some(ref url) = vta.url {
                                println!("  URL:  {url}");
                            }
                            if let Some(ref did) = vta.vta_did {
                                println!("  DID:  {did}");
                            }
                            let key = config::vta_keyring_key(&slug);
                            auth::status(&key);
                        }
                        Err(e) => {
                            eprintln!("Error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                VtaCommands::Restart => {
                    // Fall through to authenticated command handling below
                }
            }
            // Restart needs VTA connectivity — don't return early
            if !matches!(cli.command, Commands::Vta { command: VtaCommands::Restart }) {
                return;
            }
        }
        _ => {}
    }

    // Resolve active VTA
    let (slug, vta_config) = match config::resolve_vta(vta_override.as_deref(), &pnm_config) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    let keyring_key = config::vta_keyring_key(&slug);

    // Print VTA info banner
    eprintln!("  {DIM}VTA: {slug}{RESET}");
    if let Some(ref did) = vta_config.vta_did {
        eprintln!("  {DIM}DID: {did}{RESET}");
    }
    eprintln!();

    // Build client
    let client = if requires_auth(&cli.command) {
        match auth::connect(url_override.as_deref(), &keyring_key).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        let url = url_override
            .or(vta_config.url.clone())
            .unwrap_or_default();
        VtaClient::new(&url)
    };

    let result = match cli.command {
        Commands::Setup { .. } => unreachable!(),
        Commands::Vta { command: VtaCommands::Restart } => cmd_restart(&client).await,
        Commands::Vta { .. } => unreachable!(),
        Commands::Health => cmd_health(&client, &keyring_key).await,
        Commands::Auth { command } => match command {
            AuthCommands::Login { credential } => {
                auth::login(&credential, client.base_url(), &keyring_key).await
            }
            AuthCommands::Logout => {
                auth::logout(&keyring_key);
                Ok(())
            }
            AuthCommands::Status => {
                auth::status(&keyring_key);
                Ok(())
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Get => config_cmd::cmd_config_get(&client, "").await,
            ConfigCommands::Update {
                community_vta_did,
                community_vta_name,
                public_url,
            } => {
                config_cmd::cmd_config_update(
                    &client,
                    "",
                    community_vta_did,
                    community_vta_name,
                    public_url,
                )
                .await
            }
        },
        Commands::Contexts { command } => match command {
            ContextCommands::List => contexts::cmd_context_list(&client).await,
            ContextCommands::Get { id } => contexts::cmd_context_get(&client, &id).await,
            ContextCommands::Create {
                id,
                name,
                description,
            } => contexts::cmd_context_create(&client, &id, &name, description).await,
            ContextCommands::Update {
                id,
                name,
                did,
                description,
            } => contexts::cmd_context_update(&client, &id, name, did, description).await,
            ContextCommands::Delete { id, force } => {
                contexts::cmd_context_delete(&client, &id, force).await
            }
            ContextCommands::Bootstrap {
                id,
                name,
                description,
                admin_label,
            } => {
                contexts::cmd_context_bootstrap(&client, &id, &name, description, admin_label).await
            }
            ContextCommands::Provision {
                id,
                name,
                description,
                admin_label,
                server,
                did_url,
                portable,
                mediator_service,
                pre_rotation,
            } => {
                if server.is_some() && did_url.is_some() {
                    Err("--server and --did-url are mutually exclusive".into())
                } else {
                    let did_opts = match (&server, &did_url) {
                        (None, None) => None,
                        _ => Some(contexts::ProvisionDidOptions {
                            server_id: server,
                            did_url,
                            portable,
                            add_mediator_service: mediator_service,
                            pre_rotation_count: pre_rotation,
                        }),
                    };
                    contexts::cmd_context_provision(
                        &client,
                        &id,
                        &name,
                        description,
                        admin_label,
                        did_opts,
                    )
                    .await
                }
            }
            ContextCommands::Reprovision {
                id,
                key,
                admin_label,
            } => {
                contexts::cmd_context_reprovision(&client, &id, key, admin_label)
                    .await
            }
        },
        Commands::Acl { command } => match command {
            AclCommands::List { context } => acl::cmd_acl_list(&client, context.as_deref()).await,
            AclCommands::Get { did } => acl::cmd_acl_get(&client, &did).await,
            AclCommands::Create {
                did,
                role,
                label,
                contexts,
            } => acl::cmd_acl_create(&client, did, role, label, contexts).await,
            AclCommands::Update {
                did,
                role,
                label,
                contexts,
            } => acl::cmd_acl_update(&client, &did, role, label, contexts).await,
            AclCommands::Delete { did } => acl::cmd_acl_delete(&client, &did).await,
        },
        Commands::AuthCredential { command } => match command {
            AuthCredentialCommands::Create {
                role,
                label,
                contexts,
            } => credentials::cmd_auth_credential_create(&client, role, label, contexts).await,
        },
        Commands::Webvh { command } => match command {
            WebvhCommands::AddServer { id, did, label } => {
                webvh::cmd_webvh_server_add(&client, id, did, label).await
            }
            WebvhCommands::ListServers => webvh::cmd_webvh_server_list(&client).await,
            WebvhCommands::UpdateServer { id, label } => {
                webvh::cmd_webvh_server_update(&client, &id, label).await
            }
            WebvhCommands::RemoveServer { id } => {
                webvh::cmd_webvh_server_remove(&client, &id).await
            }
            WebvhCommands::CreateDid {
                context,
                server,
                did_url,
                path,
                label,
                portable,
                mediator_service,
                services,
                pre_rotation,
            } => {
                if server.is_none() && did_url.is_none() {
                    Err("either --server or --did-url is required".into())
                } else if server.is_some() && did_url.is_some() {
                    Err("--server and --did-url are mutually exclusive".into())
                } else {
                    match services
                        .map(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s))
                        .transpose()
                    {
                        Err(e) => Err(format!("invalid --services JSON: {e}").into()),
                        Ok(additional_services) => {
                            let req = vta_sdk::client::CreateDidWebvhRequest {
                                context_id: context,
                                server_id: server,
                                url: did_url,
                                path,
                                label,
                                portable,
                                add_mediator_service: mediator_service,
                                additional_services,
                                pre_rotation_count: pre_rotation,
                            };
                            webvh::cmd_webvh_did_create(&client, req).await
                        }
                    }
                }
            }
            WebvhCommands::ListDids { context, server } => {
                webvh::cmd_webvh_did_list(&client, context.as_deref(), server.as_deref()).await
            }
            WebvhCommands::GetDid { did } => webvh::cmd_webvh_did_get(&client, &did).await,
            WebvhCommands::DeleteDid { did } => webvh::cmd_webvh_did_delete(&client, &did).await,
        },
        Commands::Audit { command } => match command {
            AuditCommands::List {
                from,
                to,
                action,
                actor,
                outcome,
                context_id,
                page,
                page_size,
            } => {
                let params = vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
                    from,
                    to,
                    action,
                    actor,
                    outcome,
                    context_id,
                    page,
                    page_size,
                };
                audit::cmd_list_audit_logs(&client, &params).await
            }
            AuditCommands::Retention { command } => match command {
                RetentionCommands::Get => audit::cmd_get_retention(&client).await,
                RetentionCommands::Set { days } => {
                    audit::cmd_update_retention(&client, days).await
                }
            },
        },
        Commands::Backup { command } => match command {
            BackupCommands::Export { include_audit, output } => {
                cmd_backup_export(&client, include_audit, output).await
            }
            BackupCommands::Import { file, preview } => {
                cmd_backup_import(&client, file, preview).await
            }
        },
        Commands::Keys { command } => match command {
            KeyCommands::Create {
                key_type,
                derivation_path,
                mnemonic,
                label,
                context_id,
            } => {
                keys::cmd_key_create(
                    &client,
                    &key_type,
                    derivation_path,
                    mnemonic,
                    label,
                    context_id,
                )
                .await
            }
            KeyCommands::Get { key_id, secret } => {
                keys::cmd_key_get(&client, &key_id, secret).await
            }
            KeyCommands::Revoke { key_id } => keys::cmd_key_revoke(&client, &key_id).await,
            KeyCommands::Rename { key_id, new_key_id } => {
                keys::cmd_key_rename(&client, &key_id, &new_key_id).await
            }
            KeyCommands::List {
                limit,
                offset,
                status,
                context,
            } => keys::cmd_key_list(&client, offset, limit, status, context).await,
            KeyCommands::Secrets { key_ids, context } => {
                keys::cmd_key_secrets(&client, key_ids, context).await
            }
            KeyCommands::Bundle { context } => {
                keys::cmd_key_bundle(&client, &context).await
            }
            KeyCommands::Seeds => keys::cmd_seeds_list(&client).await,
            KeyCommands::RotateSeed { mnemonic } => keys::cmd_seeds_rotate(&client, mnemonic).await,
        },
    };

    client.shutdown().await;

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_restart(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting VTA restart...");
    client.restart().await?;
    println!("{GREEN}✓{RESET} Restart initiated");

    // Wait briefly, then check health
    println!("Waiting for VTA to come back...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    for attempt in 1..=5 {
        match client.health().await {
            Ok(resp) => {
                println!("{GREEN}✓{RESET} VTA is back (v{})", resp.version);
                return Ok(());
            }
            Err(_) if attempt < 5 => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                println!("{RED}✗{RESET} VTA did not come back after restart: {e}");
                println!("  The VTA may still be restarting. Try `pnm health` in a few seconds.");
            }
        }
    }
    Ok(())
}

async fn cmd_backup_export(
    client: &VtaClient,
    include_audit: bool,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    let password = dialoguer::Password::new()
        .with_prompt("Backup password (min 12 chars)")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;
    if password.len() < 12 {
        return Err("password must be at least 12 characters".into());
    }

    println!("Exporting backup...");
    let envelope = client.backup_export(&password, include_audit).await?;

    // Determine output path
    let path = output.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let slug = envelope
            .source_did
            .as_deref()
            .and_then(|d| d.rsplit(':').next())
            .unwrap_or("vta");
        std::path::PathBuf::from(format!("vta-backup-{slug}-{ts}.vtabak"))
    });

    let json = serde_json::to_string_pretty(&envelope)?;
    std::fs::write(&path, &json)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!("  Source DID: {}", envelope.source_did.as_deref().unwrap_or("(none)"));
    println!("  Includes audit: {}", envelope.includes_audit);
    println!("  File size: {} bytes", json.len());
    Ok(())
}

async fn cmd_backup_import(
    client: &VtaClient,
    file: std::path::PathBuf,
    preview_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(&file)?;
    let envelope: vta_sdk::protocols::backup_management::types::BackupEnvelope =
        serde_json::from_str(&json)?;

    println!("Backup file: {}", file.display());
    println!("  Source DID:  {}", envelope.source_did.as_deref().unwrap_or("(none)"));
    println!("  Created:     {}", envelope.created_at);
    println!("  Version:     {}", envelope.source_version);
    println!("  Audit:       {}", envelope.includes_audit);

    let password = dialoguer::Password::new()
        .with_prompt("Backup password")
        .interact()?;

    // Preview first
    let preview = client.backup_import(&envelope, &password, false).await?;
    println!();
    println!("  Keys:        {}", preview.key_count);
    println!("  ACL entries: {}", preview.acl_count);
    println!("  Contexts:    {}", preview.context_count);
    println!("  Audit logs:  {}", preview.audit_count);

    if preview_only {
        println!("\n{DIM}Preview only — no changes applied.{RESET}");
        return Ok(());
    }

    // Confirm
    println!();
    println!("{RED}WARNING: This will REPLACE ALL DATA in the VTA.{RESET}");
    print!("Type 'yes' to confirm: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("Import cancelled.");
        return Ok(());
    }

    println!("Importing...");
    let result = client.backup_import(&envelope, &password, true).await?;
    println!("{GREEN}✓{RESET} {}", result.message.as_deref().unwrap_or("Import complete"));

    if result.status == "imported" {
        println!("  VTA is restarting with the new identity.");
        println!("  You may need to re-authenticate if the VTA DID changed.");
    }
    Ok(())
}

use vta_cli_common::render::print_section;

// ── Command handlers ────────────────────────────────────────────────

async fn cmd_health(client: &VtaClient, keyring_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    let session = auth::loaded_session(keyring_key);

    // Single shared DID resolver — cached across all resolutions
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok();

    // ── VTA ────────────────────────────────────────────────────────
    print_section("VTA");

    if let Some(ref info) = session {
        println!("  {CYAN}{:<13}{RESET} {}", "DID", info.vta_did);
        if let Some(ref resolver) = did_resolver {
            match resolver.resolve(&info.vta_did).await {
                Ok(_) => {
                    let method = info
                        .vta_did
                        .strip_prefix("did:")
                        .and_then(|s| s.split(':').next())
                        .unwrap_or("?");
                    println!("                {GREEN}✓{RESET} resolves ({method})");
                }
                Err(e) => println!("                {RED}✗{RESET} resolution failed: {e}"),
            }
        }
    }

    let has_rest = !client.base_url().is_empty();

    if has_rest {
        println!("  {CYAN}{:<13}{RESET} {}", "URL", client.base_url());

        match client.health().await {
            Ok(resp) => {
                println!(
                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok (v{})",
                    "Service", resp.version
                );
            }
            Err(e) => {
                println!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                    "Service"
                );
            }
        }
    } else {
        println!("  {CYAN}{:<13}{RESET} DIDComm-only", "Mode");
    }

    // ── Authentication ─────────────────────────────────────────────
    print_section("Authentication");

    if has_rest {
        if let Some(ref info) = session {
            println!("  {CYAN}{:<13}{RESET} {}", "Client DID", info.client_did);
            match auth::ensure_authenticated(client.base_url(), keyring_key).await {
                Ok(_token) => {
                    if let Some(status) = auth::session_status(keyring_key) {
                        match status.token_status {
                            vta_sdk::session::TokenStatus::Valid { expires_in_secs } => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid (expires in {expires_in_secs}s)",
                                    "Token"
                                );
                            }
                            _ => {
                                println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid", "Token");
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("  {CYAN}{:<13}{RESET} {RED}✗{RESET} {e}", "Token");
                }
            }
        } else {
            println!("  {DIM}Not authenticated{RESET}");
        }
    } else {
        println!("  {DIM}DIDComm — no REST auth{RESET}");
    }

    // ── Mediator + DIDComm pings ──────────────────────────────────
    print_section("Mediator");

    if let Some(ref info) = session {
        // Resolve mediator DID using the shared resolver (avoids creating a second one)
        let mediator_result = if let Some(ref resolver) = did_resolver {
            vta_sdk::session::resolve_mediator_did_with_resolver(&info.vta_did, resolver).await
        } else {
            vta_sdk::session::resolve_mediator_did(&info.vta_did).await
        };

        match mediator_result {
            Ok(Some(mediator_did)) => {
                println!("  {CYAN}{:<13}{RESET} {mediator_did}", "DID");

                // Resolve mediator DID document (uses cached resolver)
                if let Some(ref resolver) = did_resolver {
                    match resolver.resolve(&mediator_did).await {
                        Ok(_) => {
                            let method = mediator_did
                                .strip_prefix("did:")
                                .and_then(|s| s.split(':').next())
                                .unwrap_or("?");
                            println!("                {GREEN}✓{RESET} resolves ({method})");
                        }
                        Err(e) => {
                            println!("                {RED}✗{RESET} resolution failed: {e}");
                        }
                    }
                }

                // Set up a single DIDComm session and reuse for both pings
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    vta_sdk::session::TrustPingSession::new(
                        &info.client_did,
                        &info.private_key_multibase,
                        &mediator_did,
                    ),
                )
                .await
                {
                    Ok(Ok(session)) => {
                        // Ping mediator
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            session.ping(None),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                println!("                {GREEN}✓{RESET} pong ({latency}ms)");
                            }
                            Ok(Err(e)) => {
                                println!("                {RED}✗{RESET} trust-ping failed: {e}");
                            }
                            Err(_) => {
                                println!("                {RED}✗{RESET} trust-ping timed out");
                            }
                        }

                        // Ping VTA through the same session
                        print_section("VTA DIDComm");

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(15),
                            session.ping(Some(&info.vta_did)),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                                    "Trust-ping"
                                );
                            }
                            Ok(Err(e)) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                                    "Trust-ping"
                                );
                            }
                            Err(_) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                                    "Trust-ping"
                                );
                            }
                        }

                        session.shutdown().await;
                    }
                    Ok(Err(e)) => {
                        println!("                {RED}✗{RESET} DIDComm setup failed: {e}");
                    }
                    Err(_) => {
                        println!("                {RED}✗{RESET} DIDComm setup timed out");
                    }
                }
            }
            Ok(None) => {
                println!("  {DIM}(not configured){RESET}");
            }
            Err(e) => {
                println!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} could not resolve VTA DID: {e}",
                    "DID"
                );
            }
        }
    } else {
        println!("  {DIM}(no session){RESET}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── requires_auth ──────────────────────────────────────────────

    #[test]
    fn test_requires_auth_health_false() {
        assert!(!requires_auth(&Commands::Health));
    }

    #[test]
    fn test_requires_auth_auth_login_false() {
        let cmd = Commands::Auth {
            command: AuthCommands::Login {
                credential: "test".into(),
            },
        };
        assert!(!requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_setup_false() {
        let cmd = Commands::Setup { credential: None };
        assert!(!requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_keys_true() {
        let cmd = Commands::Keys {
            command: KeyCommands::List {
                limit: 50,
                offset: 0,
                status: None,
                context: None,
            },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_config_true() {
        let cmd = Commands::Config {
            command: ConfigCommands::Get,
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_acl_true() {
        let cmd = Commands::Acl {
            command: AclCommands::List { context: None },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_contexts_true() {
        let cmd = Commands::Contexts {
            command: ContextCommands::List,
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_vta_false() {
        let cmd = Commands::Vta {
            command: VtaCommands::List,
        };
        assert!(!requires_auth(&cmd));
    }
}
