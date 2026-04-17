//! `PendingBootstrap` — operator-issued one-time tokens for the sealed
//! bootstrap swap (`POST /bootstrap/request`).
//!
//! Stored in the ACL keyspace under the `bootstrap:` key prefix so existing
//! `acl:` rows are untouched. The token itself is never persisted — only a
//! SHA-256 hash of it — and the operator sees it exactly once at issue time.
//!
//! When a consumer presents the token, the server hashes it, looks up the
//! entry by hash, atomically deletes the `PendingBootstrap` and inserts a new
//! `AclEntry` with the stored `target_role` / `target_contexts`. The expired
//! entries are additionally pruned by the background sweeper.

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

use super::Role;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// A pre-approved sealed-bootstrap swap. The `target_role` and
/// `target_contexts` freeze at issue time — the client presenting the token
/// has no say in minting parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBootstrap {
    /// SHA-256 of the opaque token (raw bytes). Lookup key.
    pub token_hash: [u8; 32],
    /// Role the minted `AclEntry` will carry. Must never be `Bootstrap`.
    pub target_role: Role,
    /// Contexts the minted entry will be restricted to. Empty = unrestricted
    /// (Admin only — [`crate::acl::validate_acl_modification`] gates this at
    /// issue time).
    #[serde(default)]
    pub target_contexts: Vec<String>,
    /// Unix-epoch seconds. After this, the sweeper prunes the entry.
    pub expires_at: u64,
    /// DID of the operator who issued the token.
    pub issued_by: String,
    /// Unix-epoch seconds when the token was issued.
    pub issued_at: u64,
    /// Optional human-readable label for operator management (list / revoke).
    #[serde(default)]
    pub label: Option<String>,
}

impl PendingBootstrap {
    /// Hash a raw token string into the lookup key.
    pub fn hash_token(token: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Lowercase-hex of the token hash, used as the keyspace row id.
    pub fn hash_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        const T: &[u8; 16] = b"0123456789abcdef";
        for &b in &self.token_hash {
            s.push(T[(b >> 4) as usize] as char);
            s.push(T[(b & 0xf) as usize] as char);
        }
        s
    }

    /// True if `now_unix >= expires_at`.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }
}

fn pb_key(hash_hex: &str) -> String {
    format!("bootstrap:{hash_hex}")
}

/// Insert or overwrite a `PendingBootstrap` row.
pub async fn store_pending_bootstrap(
    acl: &KeyspaceHandle,
    entry: &PendingBootstrap,
) -> Result<(), AppError> {
    acl.insert(pb_key(&entry.hash_hex()), entry).await
}

/// Fetch by the raw token string. Returns `None` if no row matches the hash.
pub async fn get_pending_bootstrap_by_token(
    acl: &KeyspaceHandle,
    token: &str,
) -> Result<Option<PendingBootstrap>, AppError> {
    let hash = PendingBootstrap::hash_token(token);
    let hex = PendingBootstrap {
        token_hash: hash,
        target_role: Role::Reader,
        target_contexts: vec![],
        expires_at: 0,
        issued_by: String::new(),
        issued_at: 0,
        label: None,
    }
    .hash_hex();
    acl.get(pb_key(&hex)).await
}

/// Fetch by the hex-encoded token hash (the form operators see in `list` /
/// `revoke`).
pub async fn get_pending_bootstrap_by_hash(
    acl: &KeyspaceHandle,
    hash_hex: &str,
) -> Result<Option<PendingBootstrap>, AppError> {
    acl.get(pb_key(hash_hex)).await
}

/// Delete by hex-encoded token hash.
pub async fn delete_pending_bootstrap(
    acl: &KeyspaceHandle,
    hash_hex: &str,
) -> Result<(), AppError> {
    acl.remove(pb_key(hash_hex)).await
}

/// List all pending bootstrap rows (metadata only — token hashes are
/// one-way).
pub async fn list_pending_bootstraps(
    acl: &KeyspaceHandle,
) -> Result<Vec<PendingBootstrap>, AppError> {
    let raw = acl.prefix_iter_raw("bootstrap:").await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let entry: PendingBootstrap = serde_json::from_slice(&value)?;
        out.push(entry);
    }
    Ok(out)
}

/// Atomic consume-and-replace: delete the `PendingBootstrap` keyed by
/// `token_hash_hex`, then insert the new `AclEntry`. The two mutations run
/// back-to-back on the same keyspace handle; if the ACL insert fails the
/// caller must treat the bootstrap as consumed (single-use).
///
/// This is the Phase 2 form — the underlying store doesn't expose a batch
/// transaction API yet, so we sequence the writes and rely on the nonce store
/// + consume-first ordering to prevent double-spend.
pub async fn consume_pending_bootstrap(
    acl: &KeyspaceHandle,
    token_hash_hex: &str,
    new_entry: &super::AclEntry,
) -> Result<(), AppError> {
    delete_pending_bootstrap(acl, token_hash_hex).await?;
    super::store_acl_entry(acl, new_entry).await?;
    Ok(())
}
