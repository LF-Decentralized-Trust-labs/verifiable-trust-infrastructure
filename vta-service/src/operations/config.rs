use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

use vta_sdk::protocols::vta_management::get_config::GetConfigResultBody;

use crate::auth::extractor::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;

pub struct UpdateConfigParams {
    pub vta_did: Option<String>,
    pub vta_name: Option<String>,
    pub public_url: Option<String>,
}

pub async fn get_config(
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    channel: &str,
) -> Result<GetConfigResultBody, AppError> {
    let config = config.read().await;
    info!(channel, caller = %auth.did, "config retrieved");
    Ok(GetConfigResultBody {
        vta_did: config.vta_did.clone(),
        vta_name: config.vta_name.clone(),
        public_url: config.public_url.clone(),
    })
}

pub async fn update_config(
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    params: UpdateConfigParams,
    channel: &str,
) -> Result<GetConfigResultBody, AppError> {
    auth.require_super_admin()?;

    let (result, contents, path) = {
        let mut config = config.write().await;

        if let Some(vta_did) = params.vta_did {
            config.vta_did = Some(vta_did);
        }
        if let Some(vta_name) = params.vta_name {
            config.vta_name = Some(vta_name);
        }
        if let Some(public_url) = params.public_url {
            config.public_url = Some(public_url);
        }

        let result = GetConfigResultBody {
            vta_did: config.vta_did.clone(),
            vta_name: config.vta_name.clone(),
            public_url: config.public_url.clone(),
        };
        let contents = toml::to_string_pretty(&*config)
            .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
        let path = config.config_path.clone();

        (result, contents, path)
    };

    std::fs::write(&path, contents).map_err(AppError::Io)?;

    info!(channel, caller = %auth.did, "config updated");
    Ok(result)
}
