//! VTA Seal — prevents offline CLI commands from modifying state.
//!
//! After the initial admin is bootstrapped, the VTA is "sealed". In sealed
//! mode, all CLI commands that modify ACL, keys, config, or export secrets
//! are refused. Management is only possible via authenticated REST/DIDComm.
//!
//! The seal is a marker in the fjall `acl` keyspace. It records the DID of
//! the admin who sealed it and a timestamp.
//!
//! # Security Model
//!
//! - Without TEE: The seal is a strong deterrent but not absolute — an attacker
//!   with raw filesystem access could delete the seal marker from fjall. However,
//!   this requires knowledge of fjall's internal format, and the seal check runs
//!   before any command executes.
//!
//! - With TEE (encrypted storage): The seal marker is AES-256-GCM encrypted.
//!   An attacker cannot read or modify it without the storage key, which exists
//!   only inside the enclave. This makes the seal cryptographically enforced.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

const SEAL_KEY: &str = "vta:sealed";

/// Marker written to fjall when the VTA is sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealRecord {
    /// DID of the admin who sealed the VTA.
    pub sealed_by: String,
    /// When the VTA was sealed.
    pub sealed_at: chrono::DateTime<Utc>,
    /// Human-readable reason.
    pub reason: String,
}

/// Check if the VTA is sealed. Returns the seal record if so.
pub async fn get_seal(acl_ks: &KeyspaceHandle) -> Result<Option<SealRecord>, AppError> {
    acl_ks.get(SEAL_KEY).await
}

/// Check if the VTA is sealed, and exit with an error if it is.
///
/// Call this at the top of any CLI command that modifies state.
pub async fn require_unsealed(store: &Store) -> Result<(), AppError> {
    let acl_ks = store.keyspace("acl")?;
    if let Some(seal) = get_seal(&acl_ks).await? {
        return Err(AppError::Config(format!(
            "VTA is sealed (by {} on {}). \
             Offline CLI commands are disabled. \
             Manage the VTA via the REST API or DIDComm.\n\
             \n\
             To unseal (EMERGENCY ONLY): vta unseal --confirm-dangerous",
            seal.sealed_by,
            seal.sealed_at.format("%Y-%m-%d %H:%M:%S UTC"),
        )));
    }
    Ok(())
}

/// Seal the VTA, preventing further offline CLI modifications.
pub async fn seal(acl_ks: &KeyspaceHandle, admin_did: &str) -> Result<SealRecord, AppError> {
    // Check not already sealed
    if let Some(existing) = get_seal(acl_ks).await? {
        return Err(AppError::Conflict(format!(
            "VTA is already sealed (by {} on {})",
            existing.sealed_by,
            existing.sealed_at.format("%Y-%m-%d %H:%M:%S UTC"),
        )));
    }

    let record = SealRecord {
        sealed_by: admin_did.to_string(),
        sealed_at: Utc::now(),
        reason: "bootstrap-admin completed".to_string(),
    };

    acl_ks.insert(SEAL_KEY, &record).await?;
    Ok(record)
}

/// Remove the seal (emergency recovery only).
pub async fn unseal(acl_ks: &KeyspaceHandle) -> Result<(), AppError> {
    acl_ks.remove(SEAL_KEY).await
}
