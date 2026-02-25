use std::sync::Arc;

use tracing::info;

use vta_sdk::protocols::seed_management::{
    list::{ListSeedsResultBody, SeedInfo},
    rotate::RotateSeedResultBody,
};

use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use crate::keys::seeds::{self as seeds, get_active_seed_id};
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
    seed_store: &Arc<dyn SeedStore>,
    mnemonic: Option<&str>,
    channel: &str,
) -> Result<RotateSeedResultBody, AppError> {
    let previous_id = get_active_seed_id(keys_ks)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    let new_id = seeds::rotate_seed(keys_ks, &**seed_store, mnemonic)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;

    info!(channel, previous_id, new_id, "seed rotated");

    Ok(RotateSeedResultBody {
        previous_seed_id: previous_id,
        new_seed_id: new_id,
    })
}
