use std::sync::Arc;

use tracing::info;

use crate::audit::{self, audit};
use vta_sdk::keys::KeyOrigin;
use vta_sdk::protocols::seed_management::{
    list::{ListSeedsResultBody, SeedInfo},
    rotate::RotateSeedResultBody,
};

use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::imported;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{self as seeds, get_active_seed_id, load_seed_bytes};
use crate::store::KeyspaceHandle;

pub async fn list_seeds(
    keys_ks: &KeyspaceHandle,
    channel: &str,
) -> Result<ListSeedsResultBody, AppError> {
    let active_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let records = seeds::list_seed_records(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let seeds_info: Vec<SeedInfo> = records
        .into_iter()
        .map(|r| SeedInfo {
            id: r.id,
            status: if r.retired_at.is_some() {
                "retired".into()
            } else {
                "active".into()
            },
            created_at: r.created_at,
            retired_at: r.retired_at,
        })
        .collect();

    info!(channel, count = seeds_info.len(), active_id, "seeds listed");

    Ok(ListSeedsResultBody {
        seeds: seeds_info,
        active_seed_id: active_id,
    })
}

pub async fn rotate_seed(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit_ks: &KeyspaceHandle,
    actor: &str,
    mnemonic: Option<&str>,
    channel: &str,
) -> Result<RotateSeedResultBody, AppError> {
    let previous_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Load old seed for re-encryption of imported secrets
    let old_seed = load_seed_bytes(keys_ks, &**seed_store, Some(previous_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let new_id = seeds::rotate_seed(keys_ks, &**seed_store, mnemonic)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Re-encrypt imported secrets with the new seed
    let new_seed = load_seed_bytes(keys_ks, &**seed_store, Some(new_id))
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    // Collect imported key records for AAD
    let raw = keys_ks.prefix_iter_raw("key:").await?;
    let imported_keys: Vec<(String, String)> = raw
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<KeyRecord>(&v).ok())
        .filter(|r| r.origin == KeyOrigin::Imported && r.status == vta_sdk::keys::KeyStatus::Active)
        .map(|r| (r.key_id, r.key_type.to_string()))
        .collect();

    if !imported_keys.is_empty() {
        let count =
            imported::reencrypt_all(imported_ks, keys_ks, &old_seed, &new_seed, &imported_keys)
                .await?;
        info!(
            channel,
            count, "re-encrypted imported secrets after seed rotation"
        );
    }

    info!(channel, previous_id, new_id, "seed rotated");
    audit!(
        "seed.rotate",
        actor = actor,
        resource = "seed",
        outcome = "success"
    );
    let _ = audit::record(
        audit_ks,
        "seed.rotate",
        actor,
        Some("seed"),
        "success",
        Some(channel),
        None,
    )
    .await;

    Ok(RotateSeedResultBody {
        previous_seed_id: previous_id,
        new_seed_id: new_id,
    })
}
