use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types
pub use vti_common::config::{
    AuditConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, StoreConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub vta_did: Option<String>,
    #[serde(alias = "community_name")]
    pub vta_name: Option<String>,
    pub public_url: Option<String>,
    /// WebSocket URL of a remote DID resolver (network mode).
    /// When set, the VTA uses the remote resolver instead of resolving locally.
    /// Format: `ws://host:port/did/v1/ws`
    /// In TEE mode, this points to the affinidi-did-resolver-cache-server
    /// sidecar on the parent, bridged via vsock.
    #[serde(default)]
    pub resolver_url: Option<String>,
    #[serde(default = "default_server_config")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store_config")]
    pub store: StoreConfig,
    pub messaging: Option<MessagingConfig>,
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[cfg(feature = "tee")]
    #[serde(default)]
    pub tee: TeeConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    /// Hex-encoded BIP-32 seed (config-seed feature)
    pub seed: Option<String>,
    /// AWS Secrets Manager secret name (aws-secrets feature)
    pub aws_secret_name: Option<String>,
    /// AWS region override (aws-secrets feature)
    pub aws_region: Option<String>,
    /// GCP project ID (gcp-secrets feature)
    pub gcp_project: Option<String>,
    /// GCP secret name (gcp-secrets feature)
    pub gcp_secret_name: Option<String>,
    /// Azure Key Vault URL (azure-secrets feature)
    pub azure_vault_url: Option<String>,
    /// Azure Key Vault secret name (azure-secrets feature)
    pub azure_secret_name: Option<String>,
    /// OS keyring service name (keyring feature).
    /// Change this to run multiple VTA instances on the same machine.
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
}

fn default_keyring_service() -> String {
    "vta".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            seed: None,
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: default_keyring_service(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServicesConfig {
    #[serde(default = "default_true")]
    pub rest: bool,
    #[serde(default = "default_true")]
    pub didcomm: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ServicesConfig {
    fn default() -> Self {
        Self {
            rest: true,
            didcomm: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8100
}

fn default_server_config() -> ServerConfig {
    ServerConfig::default()
}

fn default_store_config() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/vta"),
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

/// TEE attestation configuration.
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeConfig {
    /// Enforcement mode: required, optional, disabled, simulated.
    #[serde(default)]
    pub mode: TeeMode,
    /// Whether to embed attestation info as a DID document service.
    #[serde(default)]
    pub embed_in_did: bool,
    /// Attestation report cache TTL in seconds (generation is expensive).
    #[serde(default = "default_attestation_cache_ttl")]
    pub attestation_cache_ttl: u64,
    /// KMS-based secret bootstrap configuration (for Nitro Enclaves).
    #[serde(default)]
    pub kms: Option<TeeKmsConfig>,
    /// Storage encryption salt (change to invalidate all stored data).
    /// WARNING: Changing this value invalidates all encrypted storage.
    #[serde(default = "default_storage_key_salt")]
    pub storage_key_salt: String,
    /// Restrict which DID methods are accepted for ACL entries and authentication.
    /// When set, only DIDs matching these prefixes are allowed (e.g., `["did:key", "did:webvh"]`).
    /// When `None`, all DID methods are accepted (less secure with parent-side resolver).
    #[serde(default)]
    pub allowed_did_methods: Option<Vec<String>>,
}

/// KMS configuration for TEE secret bootstrap.
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeKmsConfig {
    /// AWS region for KMS calls.
    pub region: String,
    /// KMS key ARN used to encrypt/decrypt VTA secrets.
    pub key_arn: String,
    /// Template for auto-generating a did:webvh identity on first boot.
    ///
    /// Use `{SCID}` as a placeholder for the self-certifying identifier:
    ///   `did:webvh:{SCID}:example.com:vta`
    ///
    /// On first boot, the VTA derives keys from the bootstrapped seed,
    /// creates the DID, and persists it in the encrypted store.
    ///
    /// Ignored if `vta_did` is already set in config or the store.
    #[serde(default)]
    pub vta_did_template: Option<String>,
    /// Context ID used for the auto-bootstrapped admin (default: "default").
    ///
    /// On first boot, the VTA auto-creates this context and grants the
    /// admin_did super-admin access.
    #[serde(default = "default_admin_context_id")]
    pub admin_context_id: String,
    /// DID to grant super-admin access on first boot.
    ///
    /// The operator generates a `did:key` locally (e.g., via `pnm setup`),
    /// sets it here before building the EIF, and connects to the VTA using
    /// the corresponding private key after boot. The private key never
    /// touches the TEE or the parent instance.
    ///
    /// If not set, the VTA auto-generates a random `did:key` and stores
    /// the credential in the bootstrap keyspace (retrievable via REST).
    #[serde(default)]
    pub admin_did: Option<String>,
}

// KMS ciphertexts (seed, JWT key, fingerprint) are stored as K/V entries
// in the "bootstrap" keyspace — no file paths needed.

#[cfg(feature = "tee")]
fn default_admin_context_id() -> String {
    "default".to_string()
}

#[cfg(feature = "tee")]
fn default_attestation_cache_ttl() -> u64 {
    300
}

#[cfg(feature = "tee")]
fn default_storage_key_salt() -> String {
    "vta-tee-storage-v1".to_string()
}

#[cfg(feature = "tee")]
impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            mode: TeeMode::default(),
            embed_in_did: false,
            attestation_cache_ttl: default_attestation_cache_ttl(),
            kms: None,
            storage_key_salt: default_storage_key_salt(),
            allowed_did_methods: None,
        }
    }
}

/// TEE enforcement mode.
#[cfg(feature = "tee")]
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TeeMode {
    /// TEE hardware required — VTA refuses to start without it.
    Required,
    /// TEE used if available, continues without it.
    #[default]
    Optional,
    /// Simulated TEE for development/testing (NOT for production).
    Simulated,
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("VTA_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        if !path.exists() {
            return Err(AppError::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;
        let mut config = toml::from_str::<AppConfig>(&contents)
            .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;

        config.config_path = path.clone();

        // =====================================================================
        // SECURITY: When KMS bootstrap is configured (TEE mode), the config
        // baked into the EIF is authoritative. ALL env var overrides are blocked
        // except VTA_LOG_LEVEL and VTA_LOG_FORMAT (operational, no security impact).
        //
        // This prevents an attacker with server access from overriding identity
        // (VTA_DID), endpoints (VTA_PUBLIC_URL, VTA_MESSAGING_*), secrets
        // (VTA_SECRETS_*, VTA_AUTH_JWT_SIGNING_KEY), or security settings
        // (VTA_TEE_MODE) via environment variables.
        //
        // In Nitro Enclaves, env var injection is already blocked by the enclave
        // model (no --env flag on nitro-cli run-enclave). This gate provides
        // defense in depth for non-Nitro TEE deployments (e.g., SEV-SNP).
        // =====================================================================
        #[cfg(feature = "tee")]
        let kms_locked = config.tee.kms.is_some();
        #[cfg(not(feature = "tee"))]
        let kms_locked = false;

        if kms_locked {
            // In KMS mode, only allow log settings
            if let Ok(level) = std::env::var("VTA_LOG_LEVEL") {
                config.log.level = level;
            }
            if let Ok(format) = std::env::var("VTA_LOG_FORMAT") {
                config.log.format = match format.to_lowercase().as_str() {
                    "json" => LogFormat::Json,
                    "text" => LogFormat::Text,
                    other => {
                        return Err(AppError::Config(format!(
                            "invalid VTA_LOG_FORMAT '{other}', expected 'text' or 'json'"
                        )));
                    }
                };
            }

            // Log warnings for any env vars that would have been applied
            let blocked_vars = [
                "VTA_DID",
                "VTA_SERVER_HOST",
                "VTA_SERVER_PORT",
                "VTA_PUBLIC_URL",
                "VTA_STORE_DATA_DIR",
                "VTA_MESSAGING_MEDIATOR_URL",
                "VTA_MESSAGING_MEDIATOR_DID",
                "VTA_SECRETS_SEED",
                "VTA_SECRETS_AWS_SECRET_NAME",
                "VTA_SECRETS_AWS_REGION",
                "VTA_SECRETS_GCP_PROJECT",
                "VTA_SECRETS_GCP_SECRET_NAME",
                "VTA_SECRETS_AZURE_VAULT_URL",
                "VTA_SECRETS_AZURE_SECRET_NAME",
                "VTA_SECRETS_KEYRING_SERVICE",
                "VTA_AUTH_ACCESS_EXPIRY",
                "VTA_AUTH_REFRESH_EXPIRY",
                "VTA_AUTH_CHALLENGE_TTL",
                "VTA_AUTH_SESSION_CLEANUP_INTERVAL",
                "VTA_AUTH_JWT_SIGNING_KEY",
                "VTA_TEE_MODE",
                "VTA_TEE_EMBED_IN_DID",
                "VTA_TEE_ATTESTATION_CACHE_TTL",
            ];
            for var in &blocked_vars {
                if std::env::var(var).is_ok() {
                    tracing::warn!(
                        "SECURITY: {var} env var ignored — config is locked when KMS bootstrap is active"
                    );
                }
            }
        } else {
            // Non-KMS mode: apply all env var overrides (existing behavior)
            Self::apply_env_overrides(&mut config)?;
        }

        Ok(config)
    }

    /// Apply environment variable overrides to the config.
    ///
    /// Only called in non-KMS mode. When KMS bootstrap is active,
    /// the baked-in config is authoritative and env overrides are blocked.
    fn apply_env_overrides(config: &mut AppConfig) -> Result<(), AppError> {
        if let Ok(vta_did) = std::env::var("VTA_DID") {
            config.vta_did = Some(vta_did);
        }
        if let Ok(host) = std::env::var("VTA_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("VTA_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("VTA_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("VTA_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid VTA_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(public_url) = std::env::var("VTA_PUBLIC_URL") {
            config.public_url = Some(public_url);
        }
        if let Ok(data_dir) = std::env::var("VTA_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        // Messaging
        match (
            std::env::var("VTA_MESSAGING_MEDIATOR_URL"),
            std::env::var("VTA_MESSAGING_MEDIATOR_DID"),
        ) {
            (Ok(url), Ok(did)) => {
                config.messaging = Some(MessagingConfig {
                    mediator_url: url,
                    mediator_did: did,
                    mediator_host: None,
                });
            }
            (Ok(url), Err(_)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                });
                messaging.mediator_url = url;
            }
            (Err(_), Ok(did)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                });
                messaging.mediator_did = did;
            }
            (Err(_), Err(_)) => {}
        }

        // Secrets
        if let Ok(seed) = std::env::var("VTA_SECRETS_SEED") {
            config.secrets.seed = Some(seed);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_AWS_SECRET_NAME") {
            config.secrets.aws_secret_name = Some(name);
        }
        if let Ok(region) = std::env::var("VTA_SECRETS_AWS_REGION") {
            config.secrets.aws_region = Some(region);
        }
        if let Ok(project) = std::env::var("VTA_SECRETS_GCP_PROJECT") {
            config.secrets.gcp_project = Some(project);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_GCP_SECRET_NAME") {
            config.secrets.gcp_secret_name = Some(name);
        }
        if let Ok(url) = std::env::var("VTA_SECRETS_AZURE_VAULT_URL") {
            config.secrets.azure_vault_url = Some(url);
        }
        if let Ok(name) = std::env::var("VTA_SECRETS_AZURE_SECRET_NAME") {
            config.secrets.azure_secret_name = Some(name);
        }
        if let Ok(service) = std::env::var("VTA_SECRETS_KEYRING_SERVICE") {
            config.secrets.keyring_service = service;
        }

        // Auth
        if let Ok(expiry) = std::env::var("VTA_AUTH_ACCESS_EXPIRY") {
            config.auth.access_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_ACCESS_EXPIRY: {e}")))?;
        }
        if let Ok(expiry) = std::env::var("VTA_AUTH_REFRESH_EXPIRY") {
            config.auth.refresh_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_REFRESH_EXPIRY: {e}")))?;
        }
        if let Ok(ttl) = std::env::var("VTA_AUTH_CHALLENGE_TTL") {
            config.auth.challenge_ttl = ttl
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_AUTH_CHALLENGE_TTL: {e}")))?;
        }
        if let Ok(interval) = std::env::var("VTA_AUTH_SESSION_CLEANUP_INTERVAL") {
            config.auth.session_cleanup_interval = interval.parse().map_err(|e| {
                AppError::Config(format!("invalid VTA_AUTH_SESSION_CLEANUP_INTERVAL: {e}"))
            })?;
        }
        if let Ok(key) = std::env::var("VTA_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
        }

        // Audit
        if let Ok(val) = std::env::var("VTA_AUDIT_RETENTION_DAYS")
            && let Ok(days) = val.parse::<u32>()
        {
            config.audit.retention_days = days;
        }

        // TEE (non-KMS mode — all overrides allowed)
        #[cfg(feature = "tee")]
        {
            if let Ok(mode) = std::env::var("VTA_TEE_MODE") {
                config.tee.mode = match mode.to_lowercase().as_str() {
                    "required" => TeeMode::Required,
                    "optional" => TeeMode::Optional,
                    "simulated" => TeeMode::Simulated,
                    "disabled" => {
                        tracing::warn!(
                            "VTA_TEE_MODE=disabled is deprecated — use 'optional' instead"
                        );
                        TeeMode::Optional
                    }
                    other => {
                        return Err(AppError::Config(format!(
                            "invalid VTA_TEE_MODE '{other}', expected 'required', 'optional', or 'simulated'"
                        )));
                    }
                };
            }
            if let Ok(val) = std::env::var("VTA_TEE_EMBED_IN_DID") {
                config.tee.embed_in_did = val
                    .parse()
                    .map_err(|e| AppError::Config(format!("invalid VTA_TEE_EMBED_IN_DID: {e}")))?;
            }
            if let Ok(val) = std::env::var("VTA_TEE_ATTESTATION_CACHE_TTL") {
                config.tee.attestation_cache_ttl = val.parse().map_err(|e| {
                    AppError::Config(format!("invalid VTA_TEE_ATTESTATION_CACHE_TTL: {e}"))
                })?;
            }
        }

        Ok(())
    }

    pub fn save(&self) -> Result<(), AppError> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        std::fs::write(&self.config_path, contents).map_err(AppError::Io)?;
        Ok(())
    }
}
