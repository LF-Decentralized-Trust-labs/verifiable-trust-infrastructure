use std::sync::Arc;
use tokio::sync::RwLock;
use vta_sdk::protocols::audit_management::list::{
    AuditLogEntry, ListAuditLogsBody, ListAuditLogsResultBody,
};
use vta_sdk::protocols::audit_management::retention::RetentionResultBody;

use crate::audit::{self, audit};
use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// List audit logs with filtering and pagination.
pub async fn list_audit_logs(
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    params: &ListAuditLogsBody,
    _channel: &str,
) -> Result<ListAuditLogsResultBody, AppError> {
    // Any authenticated user can read audit logs (admin-level info)
    auth.require_admin()?;

    let page_size = params.page_size.clamp(1, 500);
    let page = params.page.max(1);

    // Scan all audit entries
    let raw = audit_ks.prefix_iter_raw("log:").await?;
    let mut entries: Vec<AuditLogEntry> = Vec::new();

    for (_key, value) in raw {
        let entry: AuditLogEntry = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Apply filters
        if let Some(from) = params.from
            && entry.timestamp < from { continue; }
        if let Some(to) = params.to
            && entry.timestamp > to { continue; }
        if let Some(ref action) = params.action
            && !entry.action.contains(action.as_str()) { continue; }
        if let Some(ref actor) = params.actor
            && entry.actor != *actor { continue; }
        if let Some(ref outcome) = params.outcome
            && !entry.outcome.contains(outcome.as_str()) { continue; }
        if let Some(ref ctx) = params.context_id
            && entry.context_id.as_deref() != Some(ctx.as_str()) { continue; }

        entries.push(entry);
    }

    // Sort by timestamp descending (newest first)
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let total = entries.len() as u64;
    let total_pages = total.div_ceil(page_size);

    // Apply pagination
    let skip = ((page - 1) * page_size) as usize;
    let page_entries: Vec<AuditLogEntry> = entries
        .into_iter()
        .skip(skip)
        .take(page_size as usize)
        .collect();

    Ok(ListAuditLogsResultBody {
        entries: page_entries,
        total,
        page,
        page_size,
        total_pages,
    })
}

/// Get the current audit retention period.
pub async fn get_retention(
    config: &Arc<RwLock<AppConfig>>,
    auth: &AuthClaims,
    _channel: &str,
) -> Result<RetentionResultBody, AppError> {
    auth.require_admin()?;
    let config = config.read().await;
    Ok(RetentionResultBody {
        retention_days: config.audit.retention_days,
    })
}

/// Update the audit retention period (super-admin only).
pub async fn update_retention(
    config: &Arc<RwLock<AppConfig>>,
    audit_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    retention_days: u32,
    channel: &str,
) -> Result<RetentionResultBody, AppError> {
    auth.require_super_admin()?;

    if !(1..=365).contains(&retention_days) {
        return Err(AppError::Validation(
            "retention_days must be between 1 and 365".into(),
        ));
    }

    let (result, contents, path) = {
        let mut config = config.write().await;
        config.audit.retention_days = retention_days;
        let result = RetentionResultBody { retention_days };
        let contents = toml::to_string_pretty(&*config)
            .map_err(|e| AppError::Internal(format!("failed to serialize config: {e}")))?;
        let path = config.config_path.clone();
        (result, contents, path)
    };

    std::fs::write(&path, contents).map_err(AppError::Io)?;
    tracing::info!(channel, retention_days, "audit retention updated");
    audit!("audit.retention_update", actor = &auth.did, resource = retention_days, outcome = "success");
    let _ = audit::record(audit_ks, "audit.retention_update", &auth.did, Some(&retention_days.to_string()), "success", Some(channel), None).await;
    Ok(result)
}
