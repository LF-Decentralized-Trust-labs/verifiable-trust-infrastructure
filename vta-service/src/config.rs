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
        if let Ok(key) = std::env::var("VTA_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
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
