use std::sync::Arc;

use chrono::Utc;
use tracing::info;

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody, list::ListKeysResultBody, rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody, secret::GetKeySecretResultBody,
};

use crate::auth::extractor::AuthClaims;
use crate::contexts::get_context;
use crate::error::AppError;
use crate::keys::derivation::Bip32Extension;
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyRecord, KeyStatus, KeyType};
use crate::store::KeyspaceHandle;

pub struct CreateKeyParams {
    pub key_type: KeyType,
    pub derivation_path: Option<String>,
    pub key_id: Option<String>,
    pub mnemonic: Option<String>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

pub struct ListKeysParams {
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<KeyStatus>,
    pub context_id: Option<String>,
}

pub async fn create_key(
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    params: CreateKeyParams,
    channel: &str,
) -> Result<CreateKeyResultBody, AppError> {
    // Resolve context: explicit > super-admin (None) > single-context default
    let context_id = if let Some(ref ctx) = params.context_id {
        auth.require_context(ctx)?;
        Some(ctx.clone())
    } else if auth.is_super_admin() {
        None
    } else if let Some(ctx) = auth.default_context() {
        Some(ctx.to_string())
    } else {
        return Err(AppError::Forbidden(
            "context_id required: admin has access to multiple contexts".into(),
        ));
    };

    // Resolve derivation path: use explicit value, or auto-derive from context
    let derivation_path = match params.derivation_path {
        Some(path) if !path.is_empty() => path,
        _ => {
            let ctx_id = context_id.as_ref().ok_or_else(|| {
                AppError::Validation(
                    "derivation_path is required when context_id is not provided".into(),
                )
            })?;
            let ctx = get_context(contexts_ks, ctx_id)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("context not found: {ctx_id}")))?;
            allocate_path(keys_ks, &ctx.base_path).await?
        }
    };

    if params.mnemonic.is_some() {
        return Err(AppError::Validation(
            "mnemonic is not accepted via the API — use seed rotation instead".into(),
        ));
    }

    let active_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(keys_ks, &**seed_store, Some(active_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| AppError::KeyDerivation(format!("failed to create BIP-32 root key: {e}")))?;

    let secret = match params.key_type {
        KeyType::Ed25519 => bip32.derive_ed25519(&derivation_path)?,
        KeyType::X25519 => bip32.derive_x25519(&derivation_path)?,
    };

    let now = Utc::now();
    let key_id = params.key_id.unwrap_or_else(|| derivation_path.clone());
    let public_key = secret.get_public_keymultibase()?;

    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: derivation_path.clone(),
        key_type: params.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: params.label.clone(),
        context_id: context_id.clone(),
        seed_id: Some(active_id),
        created_at: now,
        updated_at: now,
    };

    keys_ks.insert(keys::store_key(&key_id), &record).await?;

    info!(channel, key_id = %key_id, key_type = ?params.key_type, path = %derivation_path, "key created");

    Ok(CreateKeyResultBody {
        key_id,
        key_type: params.key_type,
        derivation_path,
        public_key,
        status: KeyStatus::Active,
        label: params.label,
        created_at: now,
    })
}

pub async fn get_key(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<KeyRecord, AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can access keys without a context".into(),
        ));
    }

    info!(channel, key_id = %key_id, "key retrieved");
    Ok(record)
}

pub async fn list_keys(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: ListKeysParams,
    channel: &str,
) -> Result<ListKeysResultBody, AppError> {
    let raw = keys_ks.prefix_iter_raw("key:").await?;

    let mut records: Vec<KeyRecord> = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: KeyRecord = serde_json::from_slice(&value)?;
        if let Some(ref status) = params.status
            && record.status != *status
        {
            continue;
        }
        if let Some(ref ctx) = params.context_id
            && record.context_id.as_deref() != Some(ctx.as_str())
        {
            continue;
        }
        if !auth.is_super_admin() {
            match record.context_id {
                Some(ref ctx) if auth.has_context_access(ctx) => {}
                _ => continue,
            }
        }
        records.push(record);
    }

    let total = records.len() as u64;
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50);

    let page: Vec<KeyRecord> = records
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    info!(channel, caller = %auth.did, count = page.len(), total, "keys listed");

    Ok(ListKeysResultBody {
        keys: page,
        total,
        offset,
        limit,
    })
}

pub async fn rename_key(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
    new_key_id: &str,
    channel: &str,
) -> Result<RenameKeyResultBody, AppError> {
    let old_store_key = keys::store_key(key_id);

    let mut record: KeyRecord = keys_ks
        .get(old_store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can rename keys without a context".into(),
        ));
    }

    let new_store_key = keys::store_key(new_key_id);
    record.key_id = new_key_id.to_string();
    record.updated_at = Utc::now();

    if !keys_ks.swap(old_store_key, new_store_key, &record).await? {
        return Err(AppError::Conflict(format!(
            "key {new_key_id} already exists"
        )));
    }

    info!(channel, old_id = %key_id, new_id = %new_key_id, "key renamed");

    Ok(RenameKeyResultBody {
        key_id: new_key_id.to_string(),
        updated_at: record.updated_at,
    })
}

pub async fn revoke_key(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<RevokeKeyResultBody, AppError> {
    let store_key = keys::store_key(key_id);

    let mut record: KeyRecord = keys_ks
        .get(store_key.clone())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can revoke keys without a context".into(),
        ));
    }

    if record.status == KeyStatus::Revoked {
        return Err(AppError::Conflict(format!(
            "key {key_id} is already revoked"
        )));
    }

    record.status = KeyStatus::Revoked;
    record.updated_at = Utc::now();

    keys_ks.insert(store_key, &record).await?;

    info!(channel, key_id = %key_id, "key revoked");

    Ok(RevokeKeyResultBody {
        key_id: key_id.to_string(),
        status: record.status,
        updated_at: record.updated_at,
    })
}

pub async fn get_key_secret(
    keys_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<GetKeySecretResultBody, AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can access keys without a context".into(),
        ));
    }

    let seed = load_seed_bytes(keys_ks, &**seed_store, record.seed_id)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
        .map_err(|e| AppError::KeyDerivation(format!("failed to create BIP-32 root key: {e}")))?;

    let secret = match record.key_type {
        KeyType::Ed25519 => bip32.derive_ed25519(&record.derivation_path)?,
        KeyType::X25519 => bip32.derive_x25519(&record.derivation_path)?,
    };

    info!(channel, key_id = %key_id, "key secret retrieved");

    Ok(GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase: secret.get_public_keymultibase()?,
        private_key_multibase: secret.get_private_keymultibase()?,
    })
}
