use std::sync::Arc;

use base64::Engine;
use chrono::Utc;
use multibase::Base;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tracing::info;
use zeroize::Zeroize;

use vta_sdk::protocols::key_management::{
    create::CreateKeyResultBody, list::ListKeysResultBody, rename::RenameKeyResultBody,
    revoke::RevokeKeyResultBody, secret::GetKeySecretResultBody,
    sign::{SignAlgorithm, SignResultBody},
};

use crate::audit::{self, audit};
use crate::auth::AuthClaims;
use crate::contexts::get_context;
use crate::error::{AppError, key_derivation_error};
use crate::keys::derivation::Bip32Extension;
use crate::keys::imported;
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{get_active_seed_id, load_seed_bytes};
use crate::keys::{self, KeyOrigin, KeyRecord, KeyStatus, KeyType};
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
    audit_ks: &KeyspaceHandle,
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
        .map_err(|e| key_derivation_error(format!("failed to create BIP-32 root key: {e}")))?;

    let public_key = match params.key_type {
        KeyType::Ed25519 => {
            let s = bip32.derive_ed25519(&derivation_path)?;
            s.get_public_keymultibase()?
        }
        KeyType::X25519 => {
            let s = bip32.derive_x25519(&derivation_path)?;
            s.get_public_keymultibase()?
        }
        KeyType::P256 => {
            let p256_secret = bip32.derive_p256(&derivation_path)?;
            let verifying_key = p256_secret.secret_key.public_key();
            let encoded = verifying_key.to_encoded_point(true);
            multibase::encode(Base::Base58Btc, encoded.as_bytes())
        }
    };

    let now = Utc::now();
    let key_id = params.key_id.unwrap_or_else(|| derivation_path.clone());

    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: derivation_path.clone(),
        key_type: params.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: params.label.clone(),
        context_id: context_id.clone(),
        seed_id: Some(active_id),
        origin: keys::KeyOrigin::Derived,
        created_at: now,
        updated_at: now,
    };

    keys_ks.insert(keys::store_key(&key_id), &record).await?;

    info!(channel, key_id = %key_id, key_type = ?params.key_type, path = %derivation_path, "key created");
    audit!("key.create", actor = &auth.did, resource = &key_id, outcome = "success");
    let _ = audit::record(audit_ks, "key.create", &auth.did, Some(&key_id), "success", Some(channel), context_id.as_deref()).await;

    Ok(CreateKeyResultBody {
        key_id,
        key_type: params.key_type,
        derivation_path,
        public_key,
        status: KeyStatus::Active,
        label: params.label,
        origin: keys::KeyOrigin::Derived,
        created_at: now,
    })
}

// ── Import key ─────────────────────────────────────────────────────

pub struct ImportKeyParams {
    pub key_type: KeyType,
    pub private_key_bytes: Vec<u8>,
    pub label: Option<String>,
    pub context_id: Option<String>,
}

pub async fn import_key(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: ImportKeyParams,
    channel: &str,
) -> Result<CreateKeyResultBody, AppError> {
    // Require admin role (stricter than create_key which allows initiator)
    auth.require_admin()?;

    // Resolve context
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

    // Validate key bytes and derive public key
    let mut private_bytes = params.private_key_bytes;
    let (public_key, key_type_str) = match params.key_type {
        KeyType::Ed25519 => {
            if private_bytes.len() != 32 {
                return Err(AppError::Validation(
                    format!("Ed25519 private key must be 32 bytes, got {}", private_bytes.len()),
                ));
            }
            let signing_key = ed25519_dalek::SigningKey::from_bytes(
                private_bytes.as_slice().try_into().unwrap(),
            );
            let pub_bytes = signing_key.verifying_key().to_bytes();
            let pub_multibase = keys::ed25519_multibase_pubkey(&pub_bytes);
            (pub_multibase, "ed25519")
        }
        KeyType::X25519 => {
            if private_bytes.len() != 32 {
                return Err(AppError::Validation(
                    format!("X25519 private key must be 32 bytes, got {}", private_bytes.len()),
                ));
            }
            let secret_bytes: [u8; 32] = private_bytes.as_slice().try_into().unwrap();
            let secret = x25519_dalek::StaticSecret::from(secret_bytes);
            let public = x25519_dalek::PublicKey::from(&secret);
            let pub_multibase = multibase::encode(Base::Base58Btc, public.as_bytes());
            (pub_multibase, "x25519")
        }
        KeyType::P256 => {
            let secret_key = p256::SecretKey::from_slice(&private_bytes)
                .map_err(|e| AppError::Validation(format!("invalid P-256 private key: {e}")))?;
            let public = secret_key.public_key();
            let encoded = public.to_encoded_point(true);
            let pub_multibase = multibase::encode(Base::Base58Btc, encoded.as_bytes());
            (pub_multibase, "p256")
        }
    };

    let now = Utc::now();
    let key_id = params.label.clone().unwrap_or_else(|| {
        format!("imported-{}-{}", key_type_str, now.format("%Y%m%d%H%M%S"))
    });

    // Encrypt and store the secret
    let active_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let seed = load_seed_bytes(keys_ks, &**seed_store, Some(active_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    imported::store_secret(imported_ks, keys_ks, &seed, &key_id, key_type_str, &private_bytes)
        .await?;

    // Zeroize private key material
    private_bytes.zeroize();

    // Create key record
    let record = KeyRecord {
        key_id: key_id.clone(),
        derivation_path: String::new(),
        key_type: params.key_type.clone(),
        status: KeyStatus::Active,
        public_key: public_key.clone(),
        label: params.label.clone(),
        context_id: context_id.clone(),
        seed_id: None,
        origin: KeyOrigin::Imported,
        created_at: now,
        updated_at: now,
    };
    keys_ks.insert(keys::store_key(&key_id), &record).await?;

    info!(channel, key_id = %key_id, key_type = ?params.key_type, "key imported");
    audit!("key.import", actor = &auth.did, resource = &key_id, outcome = "success");
    let _ = audit::record(audit_ks, "key.import", &auth.did, Some(&key_id), "success", Some(channel), context_id.as_deref()).await;

    Ok(CreateKeyResultBody {
        key_id,
        key_type: params.key_type,
        derivation_path: String::new(),
        public_key,
        status: KeyStatus::Active,
        label: params.label,
        origin: KeyOrigin::Imported,
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
    audit_ks: &KeyspaceHandle,
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
    audit!("key.rename", actor = &auth.did, resource = new_key_id, outcome = "success");
    let _ = audit::record(audit_ks, "key.rename", &auth.did, Some(new_key_id), "success", Some(channel), record.context_id.as_deref()).await;

    Ok(RenameKeyResultBody {
        key_id: new_key_id.to_string(),
        updated_at: record.updated_at,
    })
}

pub async fn revoke_key(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
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

    // Secure deletion for imported keys: destroy the encrypted secret
    if record.origin == KeyOrigin::Imported {
        imported::delete_secret(imported_ks, key_id).await?;
    }

    record.status = KeyStatus::Revoked;
    record.updated_at = Utc::now();

    keys_ks.insert(store_key, &record).await?;

    info!(channel, key_id = %key_id, "key revoked");
    audit!("key.revoke", actor = &auth.did, resource = key_id, outcome = "success");
    let _ = audit::record(audit_ks, "key.revoke", &auth.did, Some(key_id), "success", Some(channel), record.context_id.as_deref()).await;

    Ok(RevokeKeyResultBody {
        key_id: key_id.to_string(),
        status: record.status,
        updated_at: record.updated_at,
    })
}

pub async fn get_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit_ks: &KeyspaceHandle,
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

    let (public_key_multibase, private_key_multibase) = match record.origin {
        KeyOrigin::Imported => {
            // Decrypt from imported_secrets keyspace
            let seed = load_seed_bytes(keys_ks, &**seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks, keys_ks, &seed, key_id, &record.key_type.to_string(),
            ).await?;
            let priv_mb = multibase::encode(Base::Base58Btc, &secret_bytes);
            secret_bytes.zeroize();
            (record.public_key.clone(), priv_mb)
        }
        KeyOrigin::Derived => {
            let seed = load_seed_bytes(keys_ks, &**seed_store, record.seed_id)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
                .map_err(|e| key_derivation_error(format!("failed to create BIP-32 root key: {e}")))?;

            match record.key_type {
                KeyType::Ed25519 => {
                    let secret = bip32.derive_ed25519(&record.derivation_path)?;
                    (
                        secret.get_public_keymultibase()?,
                        secret.get_private_keymultibase()?,
                    )
                }
                KeyType::X25519 => {
                    let secret = bip32.derive_x25519(&record.derivation_path)?;
                    (
                        secret.get_public_keymultibase()?,
                        secret.get_private_keymultibase()?,
                    )
                }
                KeyType::P256 => {
                    let p256_secret = bip32.derive_p256(&record.derivation_path)?;
                    let public_key = p256_secret.secret_key.public_key();
                    let encoded = public_key.to_encoded_point(true);
                    let pub_mb = multibase::encode(Base::Base58Btc, encoded.as_bytes());
                    let priv_mb = multibase::encode(Base::Base58Btc, p256_secret.secret_key.to_bytes());
                    (pub_mb, priv_mb)
                }
            }
        }
    };

    info!(channel, key_id = %key_id, "key secret retrieved");
    audit!("key.secret_export", actor = &auth.did, resource = key_id, outcome = "success");
    let _ = audit::record(audit_ks, "key.secret_export", &auth.did, Some(key_id), "success", Some(channel), record.context_id.as_deref()).await;

    Ok(GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase,
        private_key_multibase,
    })
}

/// Sign a payload using a VTA-managed key.
///
/// For derived keys, re-derives from BIP-32 seed. For imported keys,
/// decrypts from the imported_secrets keyspace. Key material is zeroized
/// after signing.
pub async fn sign_payload(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    auth: &AuthClaims,
    key_id: &str,
    payload: &[u8],
    algorithm: &SignAlgorithm,
    channel: &str,
) -> Result<SignResultBody, AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    if record.status != KeyStatus::Active {
        return Err(AppError::Validation(
            "cannot sign with a revoked key".into(),
        ));
    }

    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can use unscoped keys".into(),
        ));
    }

    let signature_bytes = match record.origin {
        KeyOrigin::Imported => {
            // Decrypt imported secret and sign
            let seed = load_seed_bytes(keys_ks, &**seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks, keys_ks, &seed, key_id, &record.key_type.to_string(),
            ).await?;

            let sig = match (algorithm, &record.key_type) {
                (SignAlgorithm::EdDSA, KeyType::Ed25519) => {
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(
                        secret_bytes.as_slice().try_into().map_err(|_| {
                            AppError::Internal("invalid Ed25519 key length".into())
                        })?,
                    );
                    use ed25519_dalek::Signer;
                    signing_key.sign(payload).to_bytes().to_vec()
                }
                (SignAlgorithm::ES256, KeyType::P256) => {
                    let secret_key = p256::SecretKey::from_slice(&secret_bytes)
                        .map_err(|e| AppError::Internal(format!("invalid P-256 key: {e}")))?;
                    let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = signing_key.sign(payload);
                    sig.to_bytes().to_vec()
                }
                _ => {
                    secret_bytes.zeroize();
                    return Err(AppError::Validation(format!(
                        "algorithm {} incompatible with key type {}",
                        algorithm, record.key_type
                    )));
                }
            };
            secret_bytes.zeroize();
            sig
        }
        KeyOrigin::Derived => {
            let seed = load_seed_bytes(keys_ks, &**seed_store, record.seed_id)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let bip32 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed)
                .map_err(|e| key_derivation_error(format!("failed to create BIP-32 root key: {e}")))?;

            match (algorithm, &record.key_type) {
                (SignAlgorithm::EdDSA, KeyType::Ed25519) => {
                    let derivation_path: ed25519_dalek_bip32::DerivationPath = record
                        .derivation_path
                        .parse()
                        .map_err(|e| key_derivation_error(format!("invalid derivation path: {e}")))?;
                    let derived = bip32
                        .derive(&derivation_path)
                        .map_err(|e| key_derivation_error(format!("derivation failed: {e}")))?;
                    let signing_key =
                        ed25519_dalek::SigningKey::from_bytes(derived.signing_key.as_bytes());
                    use ed25519_dalek::Signer;
                    signing_key.sign(payload).to_bytes().to_vec()
                }
                (SignAlgorithm::ES256, KeyType::P256) => {
                    let p256_secret = bip32.derive_p256(&record.derivation_path)?;
                    let signing_key = p256::ecdsa::SigningKey::from(&p256_secret.secret_key);
                    use p256::ecdsa::signature::Signer;
                    let sig: p256::ecdsa::Signature = signing_key.sign(payload);
                    sig.to_bytes().to_vec()
                }
                _ => {
                    return Err(AppError::Validation(format!(
                        "algorithm {} incompatible with key type {}",
                        algorithm, record.key_type
                    )));
                }
            }
        }
    };

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

    info!(channel, key_id = %key_id, "payload signed");

    Ok(SignResultBody {
        key_id: key_id.to_string(),
        signature,
        algorithm: algorithm.clone(),
    })
}
