mod auth;
mod config;
mod setup;

use clap::{Parser, Subcommand};
use config::{community_keyring_key, resolve_community};
use vta_sdk::client::VtaClient;

use vta_cli_common::commands::{acl, config as config_cmd, contexts, credentials, keys};
use vta_cli_common::render::{CYAN, DIM, GREEN, RED, RESET, YELLOW, print_section};

#[derive(Parser)]
#[command(name = "cnm-cli", about = "CLI for VTC Verifiable Trust Agents")]
struct Cli {
    /// Base URL of the VTA service (overrides config)
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// Override the active community for this command
    #[arg(short = 'c', long, global = true)]
    community: Option<String>,

    /// Enable verbose debug output (can also set RUST_LOG=debug)
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initial setup wizard
    Setup,

    /// Community management
    Community {
        #[command(subcommand)]
        command: CommunityCommands,
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
}

#[derive(Subcommand)]
enum CommunityCommands {
    /// List configured communities
    List,
    /// Switch default community
    Use {
        /// Community slug to set as default
        name: String,
    },
    /// Add a new community
    Add,
    /// Remove a community
    Remove {
        /// Community slug to remove
        name: String,
    },
    /// Show current community info
    Status,
    /// Send a DIDComm trust-ping to the community VTA
    Ping,
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
    let green = "\x1b[32m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{green}  ██████╗ {magenta}███╗   ██╗ {yellow}███╗   ███╗{reset}
{green} ██╔════╝ {magenta}████╗  ██║ {yellow}████╗ ████║{reset}
{green} ██║      {magenta}██╔██╗ ██║ {yellow}██╔████╔██║{reset}
{green} ██║      {magenta}██║╚██╗██║ {yellow}██║╚██╔╝██║{reset}
{green} ╚██████╗ {magenta}██║ ╚████║ {yellow}██║ ╚═╝ ██║{reset}
{green}  ╚═════╝ {magenta}╚═╝  ╚═══╝ {yellow}╚═╝     ╚═╝{reset}
{dim}  Community Network Manager v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Returns true if this command requires authentication.
fn requires_auth(cmd: &Commands) -> bool {
    !matches!(
        cmd,
        Commands::Health | Commands::Auth { .. } | Commands::Setup | Commands::Community { .. }
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing: --verbose sets cnm_cli=debug, or respect RUST_LOG
    let filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("cnm_cli=debug")
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

    // Load CNM config (multi-community)
    let cnm_config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config: {e}");
            config::CnmConfig::default()
        }
    };

    // Legacy migration notice
    if cnm_config.communities.is_empty() && auth::has_legacy_session() {
        eprintln!(
            "{YELLOW}Detected legacy single-community session.\n\
             Legacy sessions are no longer used. Run `cnm setup` to configure a community.{RESET}\n"
        );
    }

    // Save the URL override before it's consumed by URL resolution
    let url_override = cli.url.clone();

    // Resolve community URL and keyring key for commands that need a VTA connection.
    // Setup and Community commands handle their own URL resolution.
    let (url, keyring_key): (String, String) =
        if requires_auth(&cli.command) || matches!(cli.command, Commands::Auth { .. }) {
            // Auth-required and Auth commands always need a community
            match resolve_community(cli.community.as_deref(), &cnm_config) {
                Ok((slug, community)) => {
                    let url = cli.url.unwrap_or_else(|| community.url.clone());
                    let key = community_keyring_key(&slug);
                    (url, key)
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        } else if matches!(cli.command, Commands::Health) {
            // Health: use community if available, otherwise require --url
            match resolve_community(cli.community.as_deref(), &cnm_config) {
                Ok((slug, community)) => {
                    let url = cli.url.unwrap_or_else(|| community.url.clone());
                    let key = community_keyring_key(&slug);
                    (url, key)
                }
                Err(_) => {
                    let url = match cli.url {
                        Some(url) => url,
                        None => {
                            eprintln!("Error: no community configured and no --url provided.\n");
                            eprintln!(
                                "Either configure a community with `cnm setup`, or provide a URL:"
                            );
                            eprintln!("  cnm health --url http://localhost:8100");
                            std::process::exit(1);
                        }
                    };
                    (url, String::new())
                }
            }
        } else {
            // Setup/Community commands don't need a pre-resolved URL
            let url = cli
                .url
                .unwrap_or_else(|| "http://localhost:8100".to_string());
            (url, String::new())
        };

    // Build client: DIDComm-preferred for authenticated commands, REST for others
    let client = if requires_auth(&cli.command) {
        // Bootstrap session from personal VTA if needed
        if auth::loaded_session(&keyring_key).is_none()
            && let Ok((slug, community)) = resolve_community(cli.community.as_deref(), &cnm_config)
            && community.context_id.is_some()
            && let Some(ref personal) = cnm_config.personal_vta
            && let Err(e) =
                setup::bootstrap_community_session(&slug, community, &personal.url).await
        {
            eprintln!(
                "Error: could not bootstrap session from personal VTA: {e}\n\n\
                         To fix this, either:\n  \
                         1. Import a credential: cnm auth login <credential>\n  \
                         2. Re-run setup: cnm setup"
            );
            std::process::exit(1);
        }

        match auth::connect(url_override.as_deref(), &keyring_key).await {
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
        Commands::Setup => setup::run_setup_wizard().await,
        Commands::Community { command } => cmd_community(command, &cnm_config).await,
        Commands::Health => cmd_health(&client, &keyring_key, &cnm_config).await,
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
            ConfigCommands::Get => config_cmd::cmd_config_get(&client, "Community ").await,
            ConfigCommands::Update {
                community_vta_did,
                community_vta_name,
                public_url,
            } => {
                config_cmd::cmd_config_update(
                    &client,
                    "Community ",
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

async fn cmd_community(
    command: CommunityCommands,
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        CommunityCommands::List => {
            if cnm_config.communities.is_empty() {
                println!("No communities configured.");
                println!("\nRun `cnm setup` to configure your first community.");
                return Ok(());
            }
            let default = cnm_config.default_community.as_deref().unwrap_or("");
            for (slug, community) in &cnm_config.communities {
                let marker = if slug == default { " (default)" } else { "" };
                println!("  {slug}{marker}");
                println!("    Name: {}", community.name);
                println!("    URL:  {}", community.url);
                if let Some(ref ctx) = community.context_id {
                    println!("    Context: {ctx}");
                }
                println!();
            }
            Ok(())
        }
        CommunityCommands::Use { name } => {
            if !cnm_config.communities.contains_key(&name) {
                return Err(format!(
                    "community '{name}' not found.\n\nConfigured communities: {}",
                    cnm_config
                        .communities
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into());
            }
            let mut config = config::load_config()?;
            config.default_community = Some(name.clone());
            config::save_config(&config)?;
            println!("Default community set to '{name}'.");
            Ok(())
        }
        CommunityCommands::Add => setup::add_community().await,
        CommunityCommands::Remove { name } => {
            let config = config::load_config()?;
            if !config.communities.contains_key(&name) {
                return Err(format!("community '{name}' not found.").into());
            }

            let confirm = dialoguer::Confirm::new()
                .with_prompt(format!(
                    "Remove community '{name}'? This will delete its stored credentials."
                ))
                .default(false)
                .interact()?;

            if !confirm {
                println!("Cancelled.");
                return Ok(());
            }

            let mut config = config;
            config.communities.remove(&name);
            // Clear default if it was the removed community
            if config.default_community.as_deref() == Some(&name) {
                config.default_community = config.communities.keys().next().cloned();
            }
            // Clear the keyring entry
            auth::logout(&community_keyring_key(&name));
            config::save_config(&config)?;
            println!("Community '{name}' removed.");
            Ok(())
        }
        CommunityCommands::Status => {
            match resolve_community(None, cnm_config) {
                Ok((slug, community)) => {
                    println!("Active community: {slug}");
                    println!("  Name: {}", community.name);
                    println!("  URL:  {}", community.url);
                    if let Some(ref ctx) = community.context_id {
                        println!("  Context: {ctx}");
                    }
                    let key = community_keyring_key(&slug);
                    auth::status(&key);
                }
                Err(_) => {
                    println!("No community configured.");
                    println!("\nRun `cnm setup` to get started.");
                }
            }
            Ok(())
        }
        CommunityCommands::Ping => cmd_community_ping(cnm_config).await,
    }
}

async fn cmd_community_ping(
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (slug, community) = resolve_community(None, cnm_config)?;
    println!("Community: {} ({slug})", community.name);

    // Need a session to get client DID + VTA DID
    let key = community_keyring_key(&slug);
    let session = match auth::loaded_session(&key) {
        Some(s) => s,
        None => {
            return Err("not authenticated — run `cnm auth login` first".into());
        }
    };

    let mediator_did = match vta_sdk::session::resolve_mediator_did(&session.vta_did).await? {
        Some(did) => did,
        None => {
            println!("  This community is not using DIDComm Messaging.");
            return Ok(());
        }
    };

    println!("  {CYAN}{:<13}{RESET} {}", "VTA DID", session.vta_did);
    println!("  {CYAN}{:<13}{RESET} {mediator_did}", "Mediator DID");

    let timeout = std::time::Duration::from_secs(10);
    match tokio::time::timeout(
        timeout,
        vta_sdk::session::send_trust_ping(
            &session.client_did,
            &session.private_key_multibase,
            &mediator_did,
            Some(&session.vta_did),
        ),
    )
    .await
    {
        Ok(Ok(latency)) => println!(
            "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
            "Trust-ping"
        ),
        Ok(Err(e)) => println!(
            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} failed: {e}",
            "Trust-ping"
        ),
        Err(_) => println!(
            "  {CYAN}{:<13}{RESET} {RED}✗{RESET} timed out",
            "Trust-ping"
        ),
    }
    Ok(())
}

async fn cmd_health(
    client: &VtaClient,
    keyring_key: &str,
    cnm_config: &config::CnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use std::time::Duration;

    let ping_timeout = Duration::from_secs(10);

    // ── Community VTA ──────────────────────────────────────────────
    print_section("Community VTA");

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
            // Continue to personal VTA section instead of returning error
            print_personal_vta_section(cnm_config, None, ping_timeout).await;
            return Ok(());
        }
    }
    println!("  {CYAN}{:<13}{RESET} {}", "URL", client.base_url());

    // Create a shared DID resolver for both sections
    let resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => Some(r),
        Err(e) => {
            println!("  {DIM}DID resolution skipped (resolver unavailable: {e}){RESET}");
            None
        }
    };

    // Community DID resolution + trust-ping
    let session = if keyring_key.is_empty() {
        None
    } else {
        auth::loaded_session(keyring_key)
    };
    if let Some(ref session) = session {
        if let Some(ref resolver) = resolver {
            print_did_resolution(resolver, "Client DID", &session.client_did, false).await;

            let mediator_did =
                print_did_resolution(resolver, "VTA DID", &session.vta_did, true).await;

            if let Some(ref mediator_did) = mediator_did {
                print_did_resolution(resolver, "Mediator DID", mediator_did, false).await;
                match tokio::time::timeout(
                    ping_timeout,
                    vta_sdk::session::send_trust_ping(
                        &session.client_did,
                        &session.private_key_multibase,
                        mediator_did,
                        None,
                    ),
                )
                .await
                {
                    Ok(Ok(latency)) => println!(
                        "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                        "Trust-ping"
                    ),
                    Ok(Err(e)) => println!(
                        "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                        "Trust-ping"
                    ),
                    Err(_) => println!(
                        "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                        "Trust-ping"
                    ),
                }
            }
        }
    } else {
        println!("  {DIM}(not authenticated — DID resolution skipped){RESET}");
    }

    // ── Personal VTA ───────────────────────────────────────────────
    print_personal_vta_section(cnm_config, resolver.as_ref(), ping_timeout).await;

    Ok(())
}

async fn print_personal_vta_section(
    cnm_config: &config::CnmConfig,
    resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    ping_timeout: std::time::Duration,
) {
    print_section("Personal VTA");

    let Some(ref personal) = cnm_config.personal_vta else {
        println!("  {DIM}Not configured.{RESET}");
        return;
    };

    let personal_client = VtaClient::new(&personal.url);
    match personal_client.health().await {
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
            return;
        }
    };
    println!("  {CYAN}{:<13}{RESET} {}", "URL", personal.url);

    // Personal DID resolution + trust-ping
    let personal_session = auth::loaded_session(config::PERSONAL_KEYRING_KEY);
    if let Some(ref session) = personal_session {
        if let Some(resolver) = resolver {
            print_did_resolution(resolver, "Client DID", &session.client_did, false).await;

            let mediator_did =
                print_did_resolution(resolver, "VTA DID", &session.vta_did, true).await;

            if let Some(ref mediator_did) = mediator_did {
                print_did_resolution(resolver, "Mediator DID", mediator_did, false).await;
                match tokio::time::timeout(
                    ping_timeout,
                    vta_sdk::session::send_trust_ping(
                        &session.client_did,
                        &session.private_key_multibase,
                        mediator_did,
                        None,
                    ),
                )
                .await
                {
                    Ok(Ok(latency)) => println!(
                        "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                        "Trust-ping"
                    ),
                    Ok(Err(e)) => println!(
                        "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                        "Trust-ping"
                    ),
                    Err(_) => println!(
                        "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                        "Trust-ping"
                    ),
                }
            }
        }
    } else {
        println!("  {DIM}(not authenticated — DID resolution skipped){RESET}");
    }
}

/// Resolve a DID and print the result with colored ✓/✗.
///
/// Prints label + DID, then resolution status and detail lines.
/// When `find_mediator` is true, looks for a DIDCommMessaging service and
/// extracts the mediator DID from its endpoint URI (if the URI is a `did:`).
async fn print_did_resolution(
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    label: &str,
    did: &str,
    find_mediator: bool,
) -> Option<String> {
    let method = did
        .strip_prefix("did:")
        .and_then(|s| s.split(':').next())
        .unwrap_or("unknown");

    println!("  {CYAN}{:<13}{RESET} {did}", label);

    let resolved = match resolver.resolve(did).await {
        Ok(r) => r,
        Err(e) => {
            println!("                {RED}✗{RESET} resolution failed: {e}");
            return None;
        }
    };

    println!("                {GREEN}✓{RESET} resolves ({method})");

    for ka in &resolved.doc.key_agreement {
        println!("                {DIM}keyAgreement: {}{RESET}", ka.get_id());
    }

    let mut mediator_did: Option<String> = None;
    for svc in &resolved.doc.service {
        let types = svc.type_.join(", ");
        // Endpoint::get_uris() wraps Map-sourced values in JSON quotes; strip them.
        let uris: Vec<String> = svc
            .service_endpoint
            .get_uris()
            .into_iter()
            .map(|u| u.trim_matches('"').to_string())
            .collect();

        if uris.is_empty() {
            println!("                {DIM}service: {types}{RESET}");
        } else {
            for uri in &uris {
                println!("                {DIM}service: {types} -> {uri}{RESET}");
            }
        }

        if find_mediator
            && svc.type_.iter().any(|t| t == "DIDCommMessaging")
            && mediator_did.is_none()
        {
            mediator_did = uris.into_iter().find(|u| u.starts_with("did:"));
            if let Some(ref m) = mediator_did {
                println!("                mediator {GREEN}✓{RESET} {m}");
            } else {
                println!("                mediator {RED}✗{RESET} no DID found in service endpoint");
            }
        }
    }
    mediator_did
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
    fn test_requires_auth_setup_false() {
        assert!(!requires_auth(&Commands::Setup));
    }

    #[test]
    fn test_requires_auth_community_false() {
        let cmd = Commands::Community {
            command: CommunityCommands::List,
        };
        assert!(!requires_auth(&cmd));
    }
}
