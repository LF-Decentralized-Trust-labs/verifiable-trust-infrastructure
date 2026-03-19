use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub vta_did: Option<String>,
    #[serde(alias = "community_name")]
    pub vta_name: Option<String>,
    pub public_url: Option<String>,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub store: StoreConfig,
    pub messaging: Option<MessagingConfig>,
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub auth: AuthConfig,
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
pub struct MessagingConfig {
    pub mediator_url: String,
    pub mediator_did: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoreConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry: u64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry: u64,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl: u64,
    #[serde(default = "default_session_cleanup_interval")]
    pub session_cleanup_interval: u64,
    /// Base64url-no-pad encoded 32-byte Ed25519 private key for JWT signing.
    pub jwt_signing_key: Option<String>,
}

fn default_access_token_expiry() -> u64 {
    900
}

fn default_refresh_token_expiry() -> u64 {
    86400
}

fn default_challenge_ttl() -> u64 {
    300
}

fn default_session_cleanup_interval() -> u64 {
    600
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
            session_cleanup_interval: default_session_cleanup_interval(),
            jwt_signing_key: None,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8100
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data/vta")
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
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
    #[serde(default = "default_storage_key_salt")]
    pub storage_key_salt: String,
}

/// KMS configuration for TEE secret bootstrap.
#[cfg(feature = "tee")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeKmsConfig {
    /// AWS region for KMS calls.
    pub region: String,
    /// KMS key ARN used to encrypt/decrypt VTA secrets.
    pub key_arn: String,
    /// Path to the encrypted seed ciphertext file.
    /// Written on first boot, read on subsequent boots.
    #[serde(default = "default_seed_ciphertext_path")]
    pub seed_ciphertext_path: String,
    /// Path to the encrypted JWT key ciphertext file.
    #[serde(default = "default_jwt_ciphertext_path")]
    pub jwt_ciphertext_path: String,
    /// Allow first-boot secret generation.
    ///
    /// When `true`, the VTA will generate new secrets if ciphertext files are
    /// missing (first boot). When `false` (default), missing ciphertexts cause
    /// a startup failure. This prevents an attacker from deleting ciphertext
    /// files to trigger a first-boot and hijack the VTA's identity.
    ///
    /// Set to `true` only for the initial deployment, then set back to `false`.
    #[serde(default)]
    pub allow_first_boot: bool,
}

#[cfg(feature = "tee")]
fn default_seed_ciphertext_path() -> String {
    "/mnt/vta-data/secrets/seed.enc".to_string()
}

#[cfg(feature = "tee")]
fn default_jwt_ciphertext_path() -> String {
    "/mnt/vta-data/secrets/jwt.enc".to_string()
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
        }
    }
}

/// TEE enforcement mode.
#[cfg(feature = "tee")]
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TeeMode {
    Required,
    Optional,
    #[default]
    Disabled,
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

        // Apply env var overrides
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

        // Messaging env var overrides
        match (
            std::env::var("VTA_MESSAGING_MEDIATOR_URL"),
            std::env::var("VTA_MESSAGING_MEDIATOR_DID"),
        ) {
            (Ok(url), Ok(did)) => {
                config.messaging = Some(MessagingConfig {
                    mediator_url: url,
                    mediator_did: did,
                });
            }
            (Ok(url), Err(_)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                });
                messaging.mediator_url = url;
            }
            (Err(_), Ok(did)) => {
                let messaging = config.messaging.get_or_insert(MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                });
                messaging.mediator_did = did;
            }
            (Err(_), Err(_)) => {}
        }

        // Secrets env var overrides
        // SECURITY: Seed env var is only applied when KMS bootstrap is NOT configured.
        if let Ok(seed) = std::env::var("VTA_SECRETS_SEED") {
            #[cfg(feature = "tee")]
            {
                if config.tee.kms.is_none() {
                    config.secrets.seed = Some(seed);
                }
                // If KMS is configured, the TEE block below will log the warning
            }
            #[cfg(not(feature = "tee"))]
            {
                config.secrets.seed = Some(seed);
            }
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

        // Auth env var overrides
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
        // SECURITY: JWT signing key env var is only applied when KMS bootstrap
        // is NOT configured. When KMS is active, the JWT key comes from KMS and
        // config/env overrides are blocked (see TEE block below).
        if let Ok(key) = std::env::var("VTA_AUTH_JWT_SIGNING_KEY") {
            #[cfg(feature = "tee")]
            {
                if config.tee.kms.is_none() {
                    config.auth.jwt_signing_key = Some(key);
                }
                // If KMS is configured, the TEE block below will log the warning
            }
            #[cfg(not(feature = "tee"))]
            {
                config.auth.jwt_signing_key = Some(key);
            }
        }

        // TEE env var overrides
        #[cfg(feature = "tee")]
        {
            if let Ok(mode) = std::env::var("VTA_TEE_MODE") {
                let requested = match mode.to_lowercase().as_str() {
                    "required" => TeeMode::Required,
                    "optional" => TeeMode::Optional,
                    "disabled" => TeeMode::Disabled,
                    "simulated" => TeeMode::Simulated,
                    other => {
                        return Err(AppError::Config(format!(
                            "invalid VTA_TEE_MODE '{other}', expected 'required', 'optional', 'disabled', or 'simulated'"
                        )));
                    }
                };

                // SECURITY: When KMS bootstrap is configured, TEE mode cannot be
                // downgraded to disabled/simulated via environment variable. An attacker
                // with server access could otherwise set VTA_TEE_MODE=disabled to bypass
                // all TEE protections. Only upgrades (optional → required) are allowed.
                if config.tee.kms.is_some() {
                    match (&config.tee.mode, &requested) {
                        // Upgrading security: always allowed
                        (_, TeeMode::Required) => config.tee.mode = requested,
                        // Downgrading when KMS is configured: blocked
                        (TeeMode::Required, TeeMode::Disabled | TeeMode::Simulated | TeeMode::Optional) => {
                            tracing::warn!(
                                "SECURITY: VTA_TEE_MODE={mode} rejected — cannot downgrade from 'required' when KMS is configured"
                            );
                        }
                        (_, TeeMode::Disabled | TeeMode::Simulated) => {
                            tracing::warn!(
                                "SECURITY: VTA_TEE_MODE={mode} rejected — cannot disable TEE when KMS is configured"
                            );
                        }
                        // Same or lateral: allowed
                        _ => config.tee.mode = requested,
                    }
                } else {
                    config.tee.mode = requested;
                }
            }

            // SECURITY: When KMS is configured, the JWT signing key and seed
            // are bootstrapped from KMS. Config/env overrides for these are
            // ignored to prevent an attacker from injecting their own keys.
            if config.tee.kms.is_some() {
                if std::env::var("VTA_AUTH_JWT_SIGNING_KEY").is_ok() {
                    tracing::warn!(
                        "SECURITY: VTA_AUTH_JWT_SIGNING_KEY env var ignored — JWT key is provided by KMS bootstrap in TEE mode"
                    );
                    config.auth.jwt_signing_key = None;
                }
                if std::env::var("VTA_SECRETS_SEED").is_ok() {
                    tracing::warn!(
                        "SECURITY: VTA_SECRETS_SEED env var ignored — seed is provided by KMS bootstrap in TEE mode"
                    );
                    config.secrets.seed = None;
                }
            }

            if let Ok(val) = std::env::var("VTA_TEE_EMBED_IN_DID") {
                config.tee.embed_in_did = val.parse().map_err(|e| {
                    AppError::Config(format!("invalid VTA_TEE_EMBED_IN_DID: {e}"))
                })?;
            }
            if let Ok(val) = std::env::var("VTA_TEE_ATTESTATION_CACHE_TTL") {
                config.tee.attestation_cache_ttl = val.parse().map_err(|e| {
                    AppError::Config(format!("invalid VTA_TEE_ATTESTATION_CACHE_TTL: {e}"))
                })?;
            }
        }

        Ok(config)
    }

    pub fn save(&self) -> Result<(), AppError> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        std::fs::write(&self.config_path, contents).map_err(AppError::Io)?;
        Ok(())
    }
}
