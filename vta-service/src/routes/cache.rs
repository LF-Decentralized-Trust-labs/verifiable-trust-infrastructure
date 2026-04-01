use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::operations;
use crate::operations::cache::{CacheGetResponse, CachePutRequest, CachePutResponse};
use crate::server::AppState;

/// GET /cache/{key} — retrieve a cached value by key. Auth: any authenticated user.
pub async fn get_cached(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<(StatusCode, Json<CacheGetResponse>), AppError> {
    match operations::cache::get_cached(&state.cache_ks, &auth, &key, "rest").await? {
        Some(resp) => Ok((StatusCode::OK, Json(resp))),
        None => Err(AppError::NotFound(format!("cache key {key} not found"))),
    }
}

/// PUT /cache/{key} — store or update a cached value. Auth: Application or higher.
pub async fn put_cached(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(req): Json<CachePutRequest>,
) -> Result<(StatusCode, Json<CachePutResponse>), AppError> {
    auth.require_write()?;
    let resp = operations::cache::put_cached(&state.cache_ks, &auth, &key, &req, "rest").await?;
    Ok((StatusCode::OK, Json(resp)))
}

/// DELETE /cache/{key} — remove a cached value. Auth: Application or higher.
pub async fn delete_cached(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require_write()?;
    operations::cache::delete_cached(&state.cache_ks, &auth, &key, "rest").await?;
    Ok(StatusCode::NO_CONTENT)
}
