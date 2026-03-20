use std::sync::Arc;
use tokio::sync::RwLock;
use vta_sdk::protocols::audit_management::list::{
    AuditLogEntry, ListAuditLogsBody, ListAuditLogsResultBody,
};
use vta_sdk::protocols::audit_management::retention::RetentionResultBody;

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

    let page_size = params.page_size.min(500).max(1);
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
        if let Some(from) = params.from {
            if entry.timestamp < from { continue; }
        }
        if let Some(to) = params.to {
            if entry.timestamp > to { continue; }
        }
        if let Some(ref action) = params.action {
            if !entry.action.contains(action.as_str()) { continue; }
        }
        if let Some(ref actor) = params.actor {
            if entry.actor != *actor { continue; }
        }
        if let Some(ref outcome) = params.outcome {
            if !entry.outcome.contains(outcome.as_str()) { continue; }
        }
        if let Some(ref ctx) = params.context_id {
            if entry.context_id.as_deref() != Some(ctx.as_str()) { continue; }
        }

        entries.push(entry);
    }

    // Sort by timestamp descending (newest first)
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let total = entries.len() as u64;
    let total_pages = (total + page_size - 1) / page_size;

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
    auth: &AuthClaims,
    retention_days: u32,
    channel: &str,
) -> Result<RetentionResultBody, AppError> {
    auth.require_super_admin()?;

    if retention_days < 1 || retention_days > 365 {
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
    Ok(result)
}
