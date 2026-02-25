use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

use vta_sdk::credentials::CredentialBundle;
use vta_sdk::protocols::credential_management::generate::GenerateCredentialsResultBody;

use crate::acl::{AclEntry, Role, store_acl_entry, validate_acl_modification};
use crate::auth::credentials::generate_did_key;
use crate::auth::extractor::AuthClaims;
use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

pub async fn generate_credentials(
    acl_ks: &KeyspaceHandle,
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    role: Role,
    label: Option<String>,
    allowed_contexts: Vec<String>,
    channel: &str,
) -> Result<GenerateCredentialsResultBody, AppError> {
    auth.require_manage()?;
    validate_acl_modification(auth, &allowed_contexts)?;

    let cfg = config.read().await;
    let vta_did = cfg
        .vta_did
        .as_ref()
        .ok_or_else(|| AppError::Internal("VTA DID not configured".into()))?
        .clone();
    let vta_url = cfg.public_url.clone();
    drop(cfg);

    let (did, private_key_multibase) = generate_did_key();

    let entry = AclEntry {
        did: did.clone(),
        role: role.clone(),
        label,
        allowed_contexts,
        created_at: now_epoch(),
        created_by: auth.did.clone(),
    };
    store_acl_entry(acl_ks, &entry).await?;

    let bundle = CredentialBundle {
        did: did.clone(),
        private_key_multibase,
        vta_did,
        vta_url,
    };
    let credential = bundle
        .encode()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    info!(channel, did = %did, role = %role, caller = %auth.did, "credentials generated");

    Ok(GenerateCredentialsResultBody {
        did,
        credential,
        role: role.to_string(),
    })
}
