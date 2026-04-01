//! Auto-bootstrap a super-admin credential on first TEE boot.
//!
//! When KMS bootstrap is configured, the VTA auto-creates a default admin
//! context, generates a random `did:key` credential, stores an ACL entry
//! granting super-admin access, and writes the encoded `CredentialBundle`
//! to the unencrypted bootstrap keyspace so the parent instance (or
//! operator) can retrieve it via `GET /attestation/admin-credential`.
//!
//! On subsequent boots, the admin credential is already in the store
//! and this function is a no-op.

use tracing::info;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::credentials::generate_did_key;
use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::contexts;
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

use vta_sdk::credentials::CredentialBundle;

/// Well-known store key for the bootstrapped admin credential.
const ADMIN_CREDENTIAL_STORE_KEY: &str = "tee:admin_credential";

/// Bootstrap a super-admin credential on first boot.
///
/// - If an admin credential already exists in the store, this is a no-op.
/// - Otherwise: creates the admin context, generates a `did:key`, creates
///   an ACL entry, encodes a `CredentialBundle`, and writes it to both
///   the encrypted keys keyspace and the unencrypted bootstrap keyspace.
///
/// Returns `Ok(())` on success or if bootstrap is not needed.
pub async fn maybe_bootstrap_admin(
    config: &AppConfig,
    store: &Store,
    storage_encryption_key: Option<[u8; 32]>,
) -> Result<(), AppError> {
    // Guard: no KMS config means no TEE bootstrap
    let kms_config = match &config.tee.kms {
        Some(kms) => kms,
        None => return Ok(()),
    };

    // Open keyspaces
    let apply_enc = |ks: KeyspaceHandle| -> KeyspaceHandle {
        if let Some(key) = storage_encryption_key {
            ks.with_encryption(key)
        } else {
            ks
        }
    };
    let keys_ks = apply_enc(store.keyspace("keys")?);
    let contexts_ks = apply_enc(store.keyspace("contexts")?);
    let acl_ks = apply_enc(store.keyspace("acl")?);

    // Check if admin credential already exists (subsequent boot)
    if keys_ks.get_raw(ADMIN_CREDENTIAL_STORE_KEY).await?.is_some() {
        info!("admin credential already bootstrapped — skipping");
        return Ok(());
    }

    let context_id = &kms_config.admin_context_id;

    // Create admin context if it doesn't exist
    let _ctx = match contexts::get_context(&contexts_ks, context_id).await? {
        Some(ctx) => ctx,
        None => contexts::create_context(&contexts_ks, context_id, "Default Admin Context")
            .await
            .map_err(|e| AppError::Internal(format!("failed to create admin context: {e}")))?,
    };

    // Use the operator-provided admin DID if configured, otherwise generate one
    if let Some(ref admin_did) = kms_config.admin_did {
        // Operator-provided DID — just create the ACL entry.
        // The private key stays with the operator (never touches TEE or parent).
        info!(did = %admin_did, context_id, "bootstrapping super-admin from config admin_did");

        let entry = AclEntry {
            did: admin_did.clone(),
            role: Role::Admin,
            label: Some("TEE bootstrap admin".to_string()),
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "tee:bootstrap".to_string(),
        };
        store_acl_entry(&acl_ks, &entry).await?;

        // Persist sentinel so we don't re-run on next boot
        keys_ks
            .insert_raw(ADMIN_CREDENTIAL_STORE_KEY, admin_did.as_bytes().to_vec())
            .await?;

        store.persist().await?;

        info!(
            did = %admin_did,
            context_id,
            "super-admin ACL created — connect using the private key for this DID"
        );
    } else {
        // No admin_did configured — generate a random did:key and store the
        // credential bundle for retrieval via REST.
        info!(
            context_id,
            "no admin_did configured — generating random admin credential"
        );

        let (did, private_key_multibase) = generate_did_key();

        let entry = AclEntry {
            did: did.clone(),
            role: Role::Admin,
            label: Some("TEE bootstrap admin".to_string()),
            allowed_contexts: vec![],
            created_at: now_epoch(),
            created_by: "tee:bootstrap".to_string(),
        };
        store_acl_entry(&acl_ks, &entry).await?;

        let vta_did = config.vta_did.clone().unwrap_or_default();
        let bundle = CredentialBundle {
            did: did.clone(),
            private_key_multibase,
            vta_did,
            vta_url: config.public_url.clone(),
        };
        let credential = bundle
            .encode()
            .map_err(|e| AppError::Internal(format!("failed to encode credential bundle: {e}")))?;

        keys_ks
            .insert_raw(ADMIN_CREDENTIAL_STORE_KEY, credential.as_bytes().to_vec())
            .await?;

        // Also persist in unencrypted bootstrap keyspace for REST retrieval
        let bootstrap_ks = store.keyspace("bootstrap")?;
        bootstrap_ks
            .insert_raw(ADMIN_CREDENTIAL_STORE_KEY, credential.as_bytes().to_vec())
            .await?;

        store.persist().await?;

        info!(
            did = %did,
            context_id,
            "super-admin credential generated — retrieve via GET /attestation/admin-credential"
        );
    }

    Ok(())
}
