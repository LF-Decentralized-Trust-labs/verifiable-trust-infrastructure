mod auth;
mod config;
mod setup;

use clap::{Parser, Subcommand};
use vta_sdk::client::VtaClient;

use vta_cli_common::commands::{acl, config as config_cmd, contexts, credentials, keys, webvh};
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

    /// Enable verbose debug output (can also set RUST_LOG=debug)
    #[arg(short, long, global = true)]
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
        /// WebVH server ID
        #[arg(long)]
        server: String,
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
    /// Delete an application context
    Delete {
        /// Context ID
        id: String,
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
    !matches!(
        cmd,
        Commands::Health | Commands::Auth { .. } | Commands::Setup { .. }
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
    let pnm_config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config: {e}");
            config::PnmConfig::default()
        }
    };

    // Save the CLI URL override (before it's consumed)
    let url_override = cli.url.clone();

    // Resolve URL: CLI flag > config > error (not needed for setup)
    let url = cli.url.or(pnm_config.url.clone()).unwrap_or_else(|| {
        if !matches!(cli.command, Commands::Setup { .. }) {
            // For auth-required commands, auth::connect resolves the URL from
            // the session store — so only error when we actually need a URL.
            if !requires_auth(&cli.command) {
                eprintln!("Error: no VTA URL configured and no --url provided.\n");
                eprintln!("Run setup first, or provide a URL:");
                eprintln!("  pnm setup --credential <CREDENTIAL>");
                eprintln!("  pnm health --url http://localhost:8100");
                std::process::exit(1);
            }
        }
        String::new()
    });
    let client = if requires_auth(&cli.command) {
        match auth::connect(url_override.as_deref()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    } else {
        VtaClient::new(&url)
    };

    let result = match cli.command {
        Commands::Setup { credential } => setup::run_setup(credential.as_deref()).await,
        Commands::Health => cmd_health(&client).await,
        Commands::Auth { command } => match command {
            AuthCommands::Login { credential } => auth::login(&credential, client.base_url()).await,
            AuthCommands::Logout => {
                auth::logout();
                Ok(())
            }
            AuthCommands::Status => {
                auth::status();
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
            ContextCommands::Delete { id } => contexts::cmd_context_delete(&client, &id).await,
            ContextCommands::Bootstrap {
                id,
                name,
                description,
                admin_label,
            } => {
                contexts::cmd_context_bootstrap(&client, &id, &name, description, admin_label).await
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
                path,
                label,
                portable,
                mediator_service,
                services,
                pre_rotation,
            } => match services
                .map(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s))
                .transpose()
            {
                Err(e) => Err(format!("invalid --services JSON: {e}").into()),
                Ok(additional_services) => {
                    let req = vta_sdk::client::CreateDidWebvhRequest {
                        context_id: context,
                        server_id: server,
                        path,
                        label,
                        portable,
                        add_mediator_service: mediator_service,
                        additional_services,
                        pre_rotation_count: pre_rotation,
                    };
                    webvh::cmd_webvh_did_create(&client, req).await
                }
            },
            WebvhCommands::ListDids { context, server } => {
                webvh::cmd_webvh_did_list(&client, context.as_deref(), server.as_deref()).await
            }
            WebvhCommands::GetDid { did } => webvh::cmd_webvh_did_get(&client, &did).await,
            WebvhCommands::DeleteDid { did } => webvh::cmd_webvh_did_delete(&client, &did).await,
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

use vta_cli_common::render::print_section;

// ── Command handlers ────────────────────────────────────────────────

async fn cmd_health(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    let session = auth::loaded_session();

    // ── VTA ────────────────────────────────────────────────────────
    print_section("VTA");

    // DID resolution
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok();

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

    // URL
    println!("  {CYAN}{:<13}{RESET} {}", "URL", client.base_url());

    // REST health check
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

    // ── Authentication ─────────────────────────────────────────────
    print_section("Authentication");

    if let Some(ref info) = session {
        println!("  {CYAN}{:<13}{RESET} {}", "Client DID", info.client_did);
        match auth::ensure_authenticated(client.base_url()).await {
            Ok(_token) => {
                // Re-check token status for display
                if let Some(status) = auth::session_status() {
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

    // ── Mediator ───────────────────────────────────────────────────
    print_section("Mediator");

    if let Some(ref info) = session {
        match vta_sdk::session::resolve_mediator_did(&info.vta_did).await {
            Ok(Some(mediator_did)) => {
                println!("  {CYAN}{:<13}{RESET} {mediator_did}", "DID");

                // Resolve mediator DID
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

                // Trust-ping
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    vta_sdk::session::send_trust_ping(
                        &info.client_did,
                        &info.private_key_multibase,
                        &mediator_did,
                        None,
                    ),
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
}
