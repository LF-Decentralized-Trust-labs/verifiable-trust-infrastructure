//! VTA backup export and import operations.
//!
//! Export: reads all keyspaces + seed, assembles a `BackupPayload`, encrypts
//! with Argon2id + AES-256-GCM, and wraps in a `BackupEnvelope`.
//!
//! Import: decrypts the envelope, validates the payload, optionally previews,
//! then replaces all keyspace data and updates the seed store.

use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::keys::seeds::{SeedRecord, get_active_seed_id, save_seed_record, set_active_seed_id};
use crate::keys::seed_store::SeedStore;
use crate::seal::{SealRecord, get_seal};
use crate::store::KeyspaceHandle;

use vta_sdk::protocols::backup_management::types::*;

// ── Argon2id parameters (OWASP recommended) ────────────────────────

const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

// ── Export ──────────────────────────────────────────────────────────

/// Assemble and encrypt a backup of the entire VTA state.
pub async fn export_backup(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    config: &crate::config::AppConfig,
    auth: &AuthClaims,
    password: &str,
    include_audit: bool,
) -> Result<BackupEnvelope, AppError> {
    auth.require_admin()?;

    // 1. Collect the active seed
    let seed_bytes = seed_store
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("seed store: {e}")))?
        .ok_or_else(|| AppError::Internal("no active seed available".into()))?;
    let active_seed_hex = hex::encode(&seed_bytes);
    let active_seed_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("get active seed id: {e}")))?;

    // 2. Collect seed records (retired seeds)
    let seed_records: Vec<SeedRecordBackup> = {
        let raw = keys_ks.prefix_iter_raw("seed:").await?;
        let mut records = Vec::new();
        for (_, value) in raw {
            if let Ok(sr) = serde_json::from_slice::<SeedRecord>(&value) {
                records.push(SeedRecordBackup {
                    id: sr.id,
                    seed_hex: sr.seed_hex,
                    created_at: sr.created_at,
                    retired_at: sr.retired_at,
                });
            }
        }
        records
    };

    // 3. Collect key records
    let key_records: Vec<vta_sdk::keys::KeyRecord> = {
        let raw = keys_ks.prefix_iter_raw("key:").await?;
        raw.into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    };

    // 4. Collect context records + counter
    let context_records: Vec<vta_sdk::contexts::ContextRecord> = {
        let raw = contexts_ks.prefix_iter_raw("ctx:").await?;
        raw.into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    };
    let context_counter: u32 = contexts_ks
        .get_raw("ctx_counter")
        .await?
        .and_then(|b| b.try_into().ok().map(u32::from_le_bytes))
        .unwrap_or(0);

    // 5. Collect ACL entries
    let acl_entries: Vec<AclEntryBackup> = {
        let raw = acl_ks.prefix_iter_raw("acl:").await?;
        raw.into_iter()
            .filter_map(|(_, v)| {
                serde_json::from_slice::<serde_json::Value>(&v)
                    .ok()
                    .map(|val| AclEntryBackup {
                        did: val["did"].as_str().unwrap_or_default().to_string(),
                        role: val["role"].as_str().unwrap_or("Viewer").to_string(),
                        label: val["label"].as_str().map(String::from),
                        allowed_contexts: val["allowed_contexts"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        created_at: val["created_at"].as_u64().unwrap_or(0),
                        created_by: val["created_by"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                    })
            })
            .collect()
    };

    // 6. Collect seal record
    let seal = get_seal(acl_ks).await.ok().flatten().map(|s| SealRecordBackup {
        sealed_by: s.sealed_by,
        sealed_at: s.sealed_at,
        reason: s.reason,
    });

    // 7. Collect WebVH records
    #[cfg(feature = "webvh")]
    let (webvh_servers, webvh_dids, webvh_logs) = {
        let servers: Vec<vta_sdk::webvh::WebvhServerRecord> = webvh_ks
            .prefix_iter_raw("server:")
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        let dids: Vec<vta_sdk::webvh::WebvhDidRecord> = webvh_ks
            .prefix_iter_raw("did:")
            .await?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        let logs: Vec<WebvhLogBackup> = webvh_ks
            .prefix_iter_raw("log:")
            .await?
            .into_iter()
            .filter_map(|(k, v)| {
                let did = String::from_utf8(k).ok()?.strip_prefix("log:")?.to_string();
                let log_json = String::from_utf8(v).ok()?;
                Some(WebvhLogBackup { did, log_json })
            })
            .collect();
        (servers, dids, logs)
    };
    #[cfg(not(feature = "webvh"))]
    let (webvh_servers, webvh_dids, webvh_logs) = (Vec::new(), Vec::new(), Vec::new());

    // 8. Collect audit logs (optional)
    let audit_logs = if include_audit {
        let raw = audit_ks.prefix_iter_raw("log:").await?;
        raw.into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    } else {
        Vec::new()
    };

    // 9. Config snapshot
    let backup_config = BackupConfig {
        vta_did: config.vta_did.clone(),
        vta_name: config.vta_name.clone(),
        public_url: config.public_url.clone(),
        mediator_url: config.messaging.as_ref().map(|m| m.mediator_url.clone()),
        mediator_did: config.messaging.as_ref().map(|m| m.mediator_did.clone()),
    };

    // 10. JWT signing key
    let jwt_signing_key = config.auth.jwt_signing_key.clone();

    // Assemble payload
    let payload = BackupPayload {
        active_seed_hex,
        active_seed_id,
        seed_records,
        jwt_signing_key,
        key_records,
        context_records,
        context_counter,
        acl_entries,
        seal,
        webvh_servers,
        webvh_dids,
        webvh_logs,
        config: backup_config,
        audit_logs,
    };

    // Encrypt
    let envelope = encrypt_payload(&payload, password, include_audit, config)?;

    info!(
        keys = payload.key_records.len(),
        acls = payload.acl_entries.len(),
        contexts = payload.context_records.len(),
        audit = payload.audit_logs.len(),
        "backup exported"
    );

    Ok(envelope)
}

// ── Import ─────────────────────────────────────────────────────────

/// Decrypt and validate a backup, returning a preview without modifying state.
pub async fn preview_import(
    envelope: &BackupEnvelope,
    password: &str,
) -> Result<(BackupPayload, ImportResult), AppError> {
    let payload = decrypt_payload(envelope, password)?;

    let result = ImportResult {
        status: "preview".into(),
        source_did: payload.config.vta_did.clone(),
        key_count: payload.key_records.len(),
        acl_count: payload.acl_entries.len(),
        context_count: payload.context_records.len(),
        audit_count: payload.audit_logs.len(),
        message: Some("Preview only — no changes applied. Set confirm=true to import.".into()),
    };

    Ok((payload, result))
}

/// Apply an import: clears all keyspaces and writes the backup data.
///
/// When `store` and TEE KMS config are provided, re-encrypts the imported
/// seed and JWT key with KMS for the bootstrap keyspace.
///
/// The caller is responsible for triggering a soft restart after this returns.
pub async fn apply_import(
    payload: &BackupPayload,
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    #[cfg(feature = "webvh")] webvh_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    config: &tokio::sync::RwLock<crate::config::AppConfig>,
    store: Option<&crate::store::Store>,
) -> Result<ImportResult, AppError> {
    // 1. Clear all keyspaces
    clear_keyspace(keys_ks, &["key:", "seed:"]).await?;
    clear_keyspace(acl_ks, &["acl:", "vta:"]).await?;
    clear_keyspace(contexts_ks, &["ctx:"]).await?;
    clear_keyspace(audit_ks, &["log:"]).await?;
    #[cfg(feature = "webvh")]
    clear_keyspace(webvh_ks, &["server:", "did:", "log:"]).await?;

    // Also remove counters
    let _ = keys_ks.remove("active_seed_id").await;
    let _ = contexts_ks.remove("ctx_counter").await;

    // 2. Write seed to external store
    let seed_bytes = hex::decode(&payload.active_seed_hex)
        .map_err(|e| AppError::Internal(format!("invalid seed hex in backup: {e}")))?;
    seed_store
        .set(&seed_bytes)
        .await
        .map_err(|e| AppError::Internal(format!("seed store: {e}")))?;

    // 3. Write active_seed_id
    set_active_seed_id(keys_ks, payload.active_seed_id)
        .await
        .map_err(|e| AppError::Internal(format!("set active seed id: {e}")))?;

    // 4. Write seed records
    for sr in &payload.seed_records {
        let record = SeedRecord {
            id: sr.id,
            seed_hex: sr.seed_hex.clone(),
            created_at: sr.created_at,
            retired_at: sr.retired_at,
        };
        save_seed_record(keys_ks, &record)
            .await
            .map_err(|e| AppError::Internal(format!("save seed record: {e}")))?;
    }

    // 5. Write key records
    for kr in &payload.key_records {
        keys_ks
            .insert(crate::keys::store_key(&kr.key_id), kr)
            .await?;
    }

    // 6. Write context records + counter
    for cr in &payload.context_records {
        contexts_ks
            .insert(format!("ctx:{}", cr.id), cr)
            .await?;
    }
    contexts_ks
        .insert_raw("ctx_counter", &payload.context_counter.to_le_bytes())
        .await?;

    // 7. Write ACL entries
    for entry in &payload.acl_entries {
        acl_ks
            .insert(format!("acl:{}", entry.did), entry)
            .await?;
    }

    // 8. Write seal record
    if let Some(ref seal) = payload.seal {
        let record = SealRecord {
            sealed_by: seal.sealed_by.clone(),
            sealed_at: seal.sealed_at,
            reason: seal.reason.clone(),
        };
        acl_ks.insert("vta:sealed", &record).await?;
    }

    // 9. Write WebVH records
    #[cfg(feature = "webvh")]
    {
        for server in &payload.webvh_servers {
            webvh_ks
                .insert(format!("server:{}", server.id), server)
                .await?;
        }
        for did_rec in &payload.webvh_dids {
            webvh_ks
                .insert(format!("did:{}", did_rec.did), did_rec)
                .await?;
        }
        for log in &payload.webvh_logs {
            webvh_ks
                .insert_raw(format!("log:{}", log.did), log.log_json.as_bytes())
                .await?;
        }
    }

    // 10. Write audit logs
    for entry in &payload.audit_logs {
        audit_ks
            .insert(
                format!("log:{:020}:{}", entry.timestamp, entry.id),
                entry,
            )
            .await?;
    }

    // 11. Update config
    {
        let mut cfg = config.write().await;
        if let Some(ref did) = payload.config.vta_did {
            cfg.vta_did = Some(did.clone());
        }
        if let Some(ref name) = payload.config.vta_name {
            cfg.vta_name = Some(name.clone());
        }
        if let Some(ref url) = payload.config.public_url {
            cfg.public_url = Some(url.clone());
        }
        if let Some(ref jwt) = payload.jwt_signing_key {
            cfg.auth.jwt_signing_key = Some(jwt.clone());
        }
        if payload.config.mediator_url.is_some() || payload.config.mediator_did.is_some() {
            let messaging = cfg.messaging.get_or_insert_with(|| {
                vti_common::config::MessagingConfig {
                    mediator_url: String::new(),
                    mediator_did: String::new(),
                    mediator_host: None,
                }
            });
            if let Some(ref url) = payload.config.mediator_url {
                messaging.mediator_url = url.clone();
            }
            if let Some(ref did) = payload.config.mediator_did {
                messaging.mediator_did = did.clone();
            }
        }
    }

    // 12. TEE: re-encrypt seed + JWT key with KMS for bootstrap keyspace
    #[cfg(feature = "tee")]
    if let Some(store) = store {
        let cfg = config.read().await;
        if let crate::config::TeeMode::Required = cfg.tee.mode {
            if let Some(ref kms_config) = cfg.tee.kms {
                let jwt_key_bytes: Option<[u8; 32]> = payload.jwt_signing_key.as_ref().and_then(|b64| {
                    base64::Engine::decode(&BASE64, b64).ok().and_then(|b| b.try_into().ok())
                });
                if let Some(jwt_key) = jwt_key_bytes {
                    crate::tee::kms_bootstrap::re_encrypt_bootstrap_secrets(
                        kms_config, store, &seed_bytes, &jwt_key,
                    )
                    .await?;
                } else {
                    info!("no JWT key in backup — skipping KMS re-encryption");
                }
            }
        }
    }

    info!(
        keys = payload.key_records.len(),
        acls = payload.acl_entries.len(),
        contexts = payload.context_records.len(),
        audit = payload.audit_logs.len(),
        "backup imported — soft restart required"
    );

    Ok(ImportResult {
        status: "imported".into(),
        source_did: payload.config.vta_did.clone(),
        key_count: payload.key_records.len(),
        acl_count: payload.acl_entries.len(),
        context_count: payload.context_records.len(),
        audit_count: payload.audit_logs.len(),
        message: Some("Import complete. VTA will restart with new identity.".into()),
    })
}

// ── Crypto helpers ─────────────────────────────────────────────────

fn encrypt_payload(
    payload: &BackupPayload,
    password: &str,
    include_audit: bool,
    config: &crate::config::AppConfig,
) -> Result<BackupEnvelope, AppError> {
    let plaintext =
        serde_json::to_vec(payload).map_err(|e| AppError::Internal(format!("serialize: {e}")))?;

    use aes_gcm::aead::rand_core::RngCore;
    let mut rng = aes_gcm::aead::OsRng;
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    // Derive key via Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| AppError::Internal(format!("argon2 params: {e}")))?,
    );
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))?;

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| AppError::Internal(format!("aes encrypt: {e}")))?;

    Ok(BackupEnvelope {
        version: 1,
        format: "vta-backup-v1".into(),
        created_at: Utc::now(),
        source_did: config.vta_did.clone(),
        source_version: env!("CARGO_PKG_VERSION").into(),
        kdf: KdfParams {
            algorithm: "argon2id".into(),
            salt: BASE64.encode(&salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        },
        encryption: EncryptionParams {
            algorithm: "aes-256-gcm".into(),
            nonce: BASE64.encode(&nonce_bytes),
        },
        includes_audit: include_audit,
        ciphertext: BASE64.encode(&ciphertext),
    })
}

fn decrypt_payload(
    envelope: &BackupEnvelope,
    password: &str,
) -> Result<BackupPayload, AppError> {
    if envelope.version != 1 || envelope.format != "vta-backup-v1" {
        return Err(AppError::Validation(format!(
            "unsupported backup format: {} v{}",
            envelope.format, envelope.version
        )));
    }

    let salt = BASE64
        .decode(&envelope.kdf.salt)
        .map_err(|e| AppError::Validation(format!("invalid salt: {e}")))?;
    let nonce_bytes = BASE64
        .decode(&envelope.encryption.nonce)
        .map_err(|e| AppError::Validation(format!("invalid nonce: {e}")))?;
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|e| AppError::Validation(format!("invalid ciphertext: {e}")))?;

    // Derive key via Argon2id (using params from envelope)
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            envelope.kdf.m_cost,
            envelope.kdf.t_cost,
            envelope.kdf.p_cost,
            Some(32),
        )
        .map_err(|e| AppError::Validation(format!("argon2 params: {e}")))?,
    );
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))?;

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| AppError::Internal(format!("aes key: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| AppError::Authentication("incorrect backup password".into()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| AppError::Internal(format!("backup payload corrupt: {e}")))
}

/// Remove all entries under the given prefixes from a keyspace.
async fn clear_keyspace(ks: &KeyspaceHandle, prefixes: &[&str]) -> Result<(), AppError> {
    for prefix in prefixes {
        let keys = ks.prefix_keys(prefix.to_string()).await?;
        for key in keys {
            ks.remove(key).await?;
        }
    }
    Ok(())
}
