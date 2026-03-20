use axum::Json;
use axum::extract::{Query, State};

use vta_sdk::protocols::audit_management::list::{ListAuditLogsBody, ListAuditLogsResultBody};
use vta_sdk::protocols::audit_management::retention::{RetentionResultBody, UpdateRetentionBody};

use crate::audit::audit;
use crate::auth::{AdminAuth, SuperAdminAuth};
use crate::error::AppError;
use crate::operations;
use crate::server::AppState;

// ---------- GET /audit/logs ----------

pub async fn list_audit_logs(
    auth: AdminAuth,
    State(state): State<AppState>,
    Query(params): Query<ListAuditLogsBody>,
) -> Result<Json<ListAuditLogsResultBody>, AppError> {
    let result = operations::audit::list_audit_logs(
        &state.audit_ks, &auth.0, &params, "rest",
    ).await?;
    Ok(Json(result))
}

// ---------- GET /audit/retention ----------

pub async fn get_retention(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<RetentionResultBody>, AppError> {
    let result = operations::audit::get_retention(
        &state.config, &auth.0, "rest",
    ).await?;
    Ok(Json(result))
}

// ---------- PATCH /audit/retention ----------

pub async fn update_retention(
    auth: SuperAdminAuth,
    State(state): State<AppState>,
    Json(body): Json<UpdateRetentionBody>,
) -> Result<Json<RetentionResultBody>, AppError> {
    let result = operations::audit::update_retention(
        &state.config, &auth.0, body.retention_days, "rest",
    ).await?;
    audit!("audit.retention_update", actor = &auth.0.did, resource = body.retention_days, outcome = "success");
    Ok(Json(result))
}
