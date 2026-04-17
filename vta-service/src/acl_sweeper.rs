//! Background pruning of expired ACL + pending-bootstrap rows.
//!
//! Called from the storage thread's interval loop. Walks the ACL keyspace
//! once, separating `acl:` rows from `bootstrap:` rows, and deletes any whose
//! `expires_at` has passed.

use tracing::{debug, info};

use crate::acl::{AclEntry, PendingBootstrap, delete_acl_entry, delete_pending_bootstrap};
use crate::error::AppError;
use crate::store::KeyspaceHandle;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn sweep_expired(acl_ks: &KeyspaceHandle) -> Result<(), AppError> {
    let now = now_epoch();

    let mut acl_pruned = 0usize;
    let mut pb_pruned = 0usize;

    let acl_rows = acl_ks.prefix_iter_raw("acl:").await?;
    for (key, value) in acl_rows {
        let entry: AclEntry = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(e) => {
                debug!(key = %String::from_utf8_lossy(&key), error = %e, "sweeper: skipping unreadable acl row");
                continue;
            }
        };
        if entry.is_expired(now) {
            delete_acl_entry(acl_ks, &entry.did).await?;
            acl_pruned += 1;
        }
    }

    let pb_rows = acl_ks.prefix_iter_raw("bootstrap:").await?;
    for (key, value) in pb_rows {
        let entry: PendingBootstrap = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(e) => {
                debug!(key = %String::from_utf8_lossy(&key), error = %e, "sweeper: skipping unreadable bootstrap row");
                continue;
            }
        };
        if entry.is_expired(now) {
            delete_pending_bootstrap(acl_ks, &entry.hash_hex()).await?;
            pb_pruned += 1;
        }
    }

    if acl_pruned > 0 || pb_pruned > 0 {
        info!(
            acl_pruned,
            bootstrap_pruned = pb_pruned,
            "acl sweeper pruned expired rows"
        );
    }
    Ok(())
}
