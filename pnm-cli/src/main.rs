mod auth;
mod bootstrap;
mod config;
mod setup;

use clap::{Parser, Subcommand};
use vta_sdk::client::VtaClient;

use vta_cli_common::commands::{
    acl, audit, config as config_cmd, contexts, credentials, keys, webvh,
};
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
        /// Path to an armored sealed bundle file (prompted interactively if omitted).
        #[arg(long)]
        credential_bundle: Option<std::path::PathBuf>,
        /// Expected SHA-256 digest of the sealed bundle.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        #[arg(long)]
        no_verify_digest: bool,
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

    /// Sealed-transfer bootstrap (consumer side).
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommands,
    },
}

#[derive(Subcommand)]
enum BootstrapCommands {
    /// Generate an ephemeral keypair and emit a BootstrapRequest for the producer.
    ///
    /// The X25519 secret is stored on disk under
    /// `~/.config/pnm/bootstrap-secrets/<bundle_id>.key` (mode 0600). The
    /// emitted JSON file contains only the public key, a fresh nonce, and an
    /// optional label — no secrets cross the boundary.
    Request {
        /// Output path for the BootstrapRequest JSON.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Optional human-readable label visible to the operator.
        #[arg(long)]
        label: Option<String>,
    },
    /// Open an armored sealed bundle returned by the producer.
    ///
    /// `--expect-digest <hex>` is required by default. Use `--no-verify-digest`
    /// to opt out (with a warning) — there is no silent TOFU.
    Open {
        /// Path to the armored bundle file.
        #[arg(long)]
        bundle: std::path::PathBuf,
        /// Expected SHA-256 digest, communicated out-of-band by the producer.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        #[arg(long)]
        no_verify_digest: bool,
    },

    /// One-command online bootstrap against a running VTA.
    ///
    /// Generates an ephemeral keypair, POSTs to `/bootstrap/request`, opens
    /// the returned sealed bundle, and installs the minted credential via
    /// `pnm auth login`.
    ///
    /// Mode depends on `--token`:
    /// - With token: Mode A — consumes a one-time token issued by the operator.
    /// - Without: Mode B — TEE first-boot attestation (only for brand-new
    ///   unadministered TEE VTAs; the carve-out closes on first success).
    Connect {
        /// Base URL of the target VTA.
        #[arg(long)]
        vta_url: String,
        /// One-time bootstrap token (Mode A). Omit for Mode B (TEE first-boot).
        #[arg(long)]
        token: Option<String>,
        /// Optional out-of-band digest anchor. Compared against the server's
        /// reported digest and the locally computed one.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Slug to register this VTA under in pnm config (default: tail of the
        /// VTA DID).
        #[arg(long)]
        slug: Option<String>,
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
        /// Path to a JSON file containing a DID Document template (template mode)
        #[arg(long)]
        did_document: Option<String>,
        /// Path to a did.jsonl file containing a pre-signed log entry (final mode)
        #[arg(long)]
        did_log: Option<String>,
        /// Do not set this DID as the primary DID for the context
        #[arg(long)]
        no_primary: bool,
        /// Use an existing key ID as the signing verification method
        #[arg(long)]
        signing_key: Option<String>,
        /// Use an existing key ID as the key-agreement verification method
        #[arg(long)]
        ka_key: Option<String>,
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
    /// Import a credential from an armored sealed bundle and authenticate.
    ///
    /// Expects an armored `VTA SEALED BUNDLE` produced by the operator (e.g.
    /// via `vta context provision --recipient <request>`). The local secret
    /// must already exist under `~/.config/pnm/bootstrap-secrets/` — produce
    /// one with `pnm bootstrap request --out <request>.json` beforehand.
    Login {
        /// Path to the armored sealed bundle file.
        #[arg(long)]
        credential_bundle: std::path::PathBuf,
        /// Expected SHA-256 digest, communicated out-of-band by the producer.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        #[arg(long)]
        no_verify_digest: bool,
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
    /// Update the DID for a context (context admin or super admin)
    UpdateDid {
        /// Context ID
        id: String,
        /// The new DID to assign
        did: String,
    },
    /// Delete an application context and all associated resources
    Delete {
        /// Context ID
        id: String,
        /// Skip confirmation and delete immediately
        #[arg(long, short)]
        force: bool,
    },
    /// Create a context and mint a sealed admin credential for its first admin.
    ///
    /// The admin did:key is generated locally by the CLI and registered via
    /// `POST /acl`; the VTA never sees the private key. The minted credential
    /// is sealed to the `--recipient` and printed as an armored bundle.
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
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_pubkey", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's base64url X25519 public key.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_pubkey: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_pubkey", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
    /// Provision a new application context with a portable config bundle
    ///
    /// Creates a context, generates admin credentials, and optionally creates a
    /// WebVH DID. Emits an armored sealed bundle (`-----BEGIN VTA SEALED BUNDLE-----`)
    /// containing everything an application needs to connect, authenticate,
    /// and self-administer its context. Pass `--recipient <file>` with a
    /// `BootstrapRequest` JSON (produced by `pnm bootstrap request --out`) or
    /// `--recipient-pubkey` + `--recipient-nonce` inline.
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
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_pubkey", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's base64url X25519 public key (32 bytes).
        /// Requires --recipient-nonce. Mutually exclusive with --recipient.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_pubkey: Option<String>,
        /// Recipient's 16-byte nonce in hex (32 chars).
        /// Requires --recipient-pubkey. Mutually exclusive with --recipient.
        #[arg(long, requires = "recipient_pubkey", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
    /// Regenerate a provision bundle for an existing context
    ///
    /// Builds a new provision bundle using a VTA-stored key as the admin
    /// credential and seals it to the given recipient. Pass --key to specify a
    /// key ID directly, or omit it to interactively select from existing keys
    /// or create a new one.
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
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_pubkey", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's base64url X25519 public key.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_pubkey: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_pubkey", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
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
        /// Role: admin, initiator, application, or reader
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
    /// Generate a new auth credential (did:key minted locally + ACL entry)
    /// and seal it to the given recipient.
    Create {
        /// Role: admin, initiator, application, or reader
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_pubkey", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's base64url X25519 public key.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_pubkey: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_pubkey", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
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
    /// Import an externally-created private key
    Import {
        /// Key type: ed25519, x25519, or p256
        #[arg(long)]
        key_type: String,
        /// Multibase-encoded private key
        #[arg(long)]
        private_key: Option<String>,
        /// Path to private key file
        #[arg(long)]
        private_key_file: Option<std::path::PathBuf>,
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
    /// Export a portable DID secrets bundle for a context as an armored
    /// sealed bundle. The recipient runs `pnm bootstrap open` to decrypt.
    Bundle {
        /// Application context ID whose DID and keys to bundle
        context: String,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_pubkey", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's base64url X25519 public key.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_pubkey: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_pubkey", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
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
/// Implementation of `pnm auth login --credential-bundle <file>`.
///
/// Opens an armored sealed bundle (matching a secret persisted earlier by
/// `pnm bootstrap request`), extracts the admin credential from the payload,
/// and installs it via `auth::login`.
async fn auth_login_sealed(
    client: &VtaClient,
    keyring_key: &str,
    credential_bundle: &std::path::Path,
    expect_digest: Option<&str>,
    no_verify_digest: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir =
        config::config_dir().map_err(|e| format!("could not resolve config dir: {e}"))?;
    if no_verify_digest {
        eprintln!(
            "WARNING: --no-verify-digest disables out-of-band integrity verification.\n\
             You are trusting the producer pubkey embedded in the bundle without\n\
             any external anchor. Use only for testing."
        );
    }
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
        credential_bundle,
        &config_dir,
        expect_digest,
        no_verify_digest,
    )?;
    eprintln!(
        "Sealed bundle opened ({} — digest {}).",
        opened.bundle_id_hex, opened.digest
    );
    let bundle = vta_cli_common::sealed_consumer::extract_admin_credential(opened.payload)?;
    auth::login(&bundle, client.base_url(), keyring_key).await
}

/// Resolve CLI `--recipient` / `--recipient-pubkey` / `--recipient-nonce`
/// arguments into a [`vta_cli_common::sealed_producer::SealedRecipient`].
///
/// Clap's `conflicts_with` + `requires` already guarantee at most one mode is
/// populated; this function enforces that at least one is, and produces a
/// consistent error message.
fn resolve_recipient(
    recipient: Option<&std::path::Path>,
    recipient_pubkey: Option<&str>,
    recipient_nonce: Option<&str>,
) -> Result<vta_cli_common::sealed_producer::SealedRecipient, Box<dyn std::error::Error>> {
    use vta_cli_common::sealed_producer::SealedRecipient;
    if let Some(path) = recipient {
        SealedRecipient::from_file(path)
    } else if let (Some(pk), Some(nonce)) = (recipient_pubkey, recipient_nonce) {
        SealedRecipient::from_inline(pk, nonce)
    } else {
        Err(
            "a recipient is required: pass --recipient <file> or both --recipient-pubkey and --recipient-nonce"
                .into(),
        )
    }
}

fn requires_auth(cmd: &Commands) -> bool {
    // VTA restart requires auth; other VTA subcommands don't
    if matches!(
        cmd,
        Commands::Vta {
            command: VtaCommands::Restart
        }
    ) {
        return true;
    }
    !matches!(
        cmd,
        Commands::Health
            | Commands::Auth { .. }
            | Commands::Setup { .. }
            | Commands::Vta { .. }
            | Commands::Bootstrap { .. }
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
        Commands::Setup {
            credential_bundle,
            expect_digest,
            no_verify_digest,
        } => {
            let result = setup::run_setup(
                setup::SetupOptions {
                    credential_bundle: credential_bundle.clone(),
                    expect_digest: expect_digest.clone(),
                    no_verify_digest: *no_verify_digest,
                },
                &mut pnm_config,
            )
            .await;
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Bootstrap { command } => {
            let result = match command {
                BootstrapCommands::Request { out, label } => {
                    bootstrap::run_request(out.clone(), label.clone()).await
                }
                BootstrapCommands::Open {
                    bundle,
                    expect_digest,
                    no_verify_digest,
                } => {
                    bootstrap::run_open(bundle.clone(), expect_digest.clone(), *no_verify_digest)
                        .await
                }
                BootstrapCommands::Connect {
                    vta_url,
                    token,
                    expect_digest,
                    slug,
                } => {
                    bootstrap::run_connect(
                        vta_url.clone(),
                        token.clone(),
                        expect_digest.clone(),
                        slug.clone(),
                        &mut pnm_config,
                    )
                    .await
                }
            };
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
            if !matches!(
                cli.command,
                Commands::Vta {
                    command: VtaCommands::Restart
                }
            ) {
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
        let url = url_override.or(vta_config.url.clone()).unwrap_or_default();
        VtaClient::new(&url)
    };

    let result = match cli.command {
        Commands::Setup { .. } => unreachable!(),
        Commands::Bootstrap { .. } => unreachable!(),
        Commands::Vta {
            command: VtaCommands::Restart,
        } => cmd_restart(&client).await,
        Commands::Vta { .. } => unreachable!(),
        Commands::Health => cmd_health(&client, &keyring_key).await,
        Commands::Auth { command } => match command {
            AuthCommands::Login {
                credential_bundle,
                expect_digest,
                no_verify_digest,
            } => {
                auth_login_sealed(
                    &client,
                    &keyring_key,
                    &credential_bundle,
                    expect_digest.as_deref(),
                    no_verify_digest,
                )
                .await
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
            ContextCommands::UpdateDid { id, did } => {
                contexts::cmd_context_update_did(&client, &id, &did).await
            }
            ContextCommands::Delete { id, force } => {
                contexts::cmd_context_delete(&client, &id, force).await
            }
            ContextCommands::Bootstrap {
                id,
                name,
                description,
                admin_label,
                recipient,
                recipient_pubkey,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_pubkey.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    contexts::cmd_context_bootstrap(
                        &client,
                        &id,
                        &name,
                        description,
                        admin_label,
                        recipient,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
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
                recipient,
                recipient_pubkey,
                recipient_nonce,
            } => {
                if server.is_some() && did_url.is_some() {
                    Err("--server and --did-url are mutually exclusive".into())
                } else {
                    let recipient_spec = resolve_recipient(
                        recipient.as_deref(),
                        recipient_pubkey.as_deref(),
                        recipient_nonce.as_deref(),
                    );
                    match recipient_spec {
                        Ok(recipient) => {
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
                                recipient,
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            ContextCommands::Reprovision {
                id,
                key,
                admin_label,
                recipient,
                recipient_pubkey,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_pubkey.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    contexts::cmd_context_reprovision(&client, &id, key, admin_label, recipient)
                        .await
                }
                Err(e) => Err(e),
            },
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
                recipient,
                recipient_pubkey,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_pubkey.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    credentials::cmd_auth_credential_create(
                        &client, role, label, contexts, recipient,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
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
                did_document,
                did_log,
                no_primary,
                signing_key,
                ka_key,
            } => {
                if server.is_none() && did_url.is_none() {
                    Err("either --server or --did-url is required".into())
                } else if server.is_some() && did_url.is_some() {
                    Err("--server and --did-url are mutually exclusive".into())
                } else {
                    webvh::cmd_webvh_did_create_with_files(
                        &client,
                        context,
                        server,
                        did_url,
                        path,
                        label,
                        portable,
                        mediator_service,
                        services,
                        pre_rotation,
                        did_document,
                        did_log,
                        no_primary,
                        signing_key,
                        ka_key,
                    )
                    .await
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
                RetentionCommands::Set { days } => audit::cmd_update_retention(&client, days).await,
            },
        },
        Commands::Backup { command } => match command {
            BackupCommands::Export {
                include_audit,
                output,
            } => cmd_backup_export(&client, include_audit, output).await,
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
            KeyCommands::Import {
                key_type,
                private_key,
                private_key_file,
                label,
                context_id,
            } => {
                keys::cmd_key_import(
                    &client,
                    &key_type,
                    private_key,
                    private_key_file,
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
            KeyCommands::Bundle {
                context,
                recipient,
                recipient_pubkey,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_pubkey.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => keys::cmd_key_bundle(&client, &context, recipient).await,
                Err(e) => Err(e),
            },
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
                let ver = resp.version.as_deref().unwrap_or("?");
                println!("{GREEN}✓{RESET} VTA is back (v{ver})");
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
    println!(
        "  Source DID: {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
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
    println!(
        "  Source DID:  {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
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
    println!(
        "{GREEN}✓{RESET} {}",
        result.message.as_deref().unwrap_or("Import complete")
    );

    if result.status == "imported" {
        println!("  VTA is restarting with the new identity.");
        println!("  You may need to re-authenticate if the VTA DID changed.");
    }
    Ok(())
}

use vta_cli_common::render::print_section;

// ── Command handlers ────────────────────────────────────────────────

async fn cmd_health(
    client: &VtaClient,
    keyring_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
                let ver = resp
                    .version
                    .as_deref()
                    .map(|v| format!(" (v{v})"))
                    .unwrap_or_default();
                println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok{ver}", "Service");
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
                credential_bundle: std::path::PathBuf::from("/tmp/fake.armor"),
                expect_digest: None,
                no_verify_digest: false,
            },
        };
        assert!(!requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_setup_false() {
        let cmd = Commands::Setup {
            credential_bundle: None,
            expect_digest: None,
            no_verify_digest: false,
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
    fn test_requires_auth_vta_false() {
        let cmd = Commands::Vta {
            command: VtaCommands::List,
        };
        assert!(!requires_auth(&cmd));
    }
}
