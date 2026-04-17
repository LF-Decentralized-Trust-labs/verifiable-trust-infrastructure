mod acl;
#[cfg(feature = "tee")]
mod attestation;
mod audit;
mod auth;
mod backup;
mod bootstrap;
mod cache;
mod capabilities;
mod config;
mod contexts;
#[cfg(feature = "webvh")]
mod did_webvh;
mod health;
pub mod keys;
mod vta;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post, put};

use crate::server::AppState;

/// Maximum request body size (1 MB). Protects against memory exhaustion,
/// especially critical in TEE deployments where enclave memory is limited.
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Health-check route — served without the request/response trace layer.
/// Minimal response only; detailed info requires authentication.
pub fn health_router() -> Router<AppState> {
    Router::new().route("/health", get(health::health))
}

pub fn router() -> Router<AppState> {
    let router = Router::new()
        // Sealed-transfer bootstrap (unauthenticated — token or attestation gated)
        .route("/bootstrap/request", post(bootstrap::request))
        // Auth routes (flattened to avoid nest + root-route matching issues in Axum 0.8)
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/credentials", post(auth::generate_credentials))
        .route(
            "/auth/sessions",
            get(auth::session_list).delete(auth::revoke_sessions_by_did),
        )
        .route("/auth/sessions/{session_id}", delete(auth::revoke_session))
        .route(
            "/config",
            get(config::get_config).patch(config::update_config),
        )
        .route("/keys", get(keys::list_keys).post(keys::create_key))
        .route(
            "/keys/{key_id}",
            get(keys::get_key)
                .delete(keys::invalidate_key)
                .patch(keys::rename_key),
        )
        .route("/keys/{key_id}/secret", get(keys::get_key_secret))
        .route("/keys/{key_id}/sign", post(keys::sign_with_key))
        .route("/keys/import/wrapping-key", get(keys::get_wrapping_key))
        .route("/keys/import", post(keys::import_key))
        .route("/keys/seeds", get(keys::list_seeds))
        .route("/keys/seeds/rotate", post(keys::rotate_seed))
        // Context routes
        .route(
            "/contexts",
            get(contexts::list_contexts_handler).post(contexts::create_context_handler),
        )
        .route(
            "/contexts/{id}",
            get(contexts::get_context_handler)
                .patch(contexts::update_context_handler)
                .delete(contexts::delete_context_handler),
        )
        .route(
            "/contexts/{id}/did",
            put(contexts::update_context_did_handler),
        )
        .route(
            "/contexts/{id}/delete-preview",
            get(contexts::preview_delete_context_handler),
        )
        // ACL routes (flattened for consistency)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route(
            "/acl/{did}",
            get(acl::get_acl)
                .patch(acl::update_acl)
                .delete(acl::delete_acl),
        )
        // Audit log routes
        .route("/audit/logs", get(audit::list_audit_logs))
        .route(
            "/audit/retention",
            get(audit::get_retention).patch(audit::update_retention),
        )
        // Cache routes (token caching / key-value store)
        .route(
            "/cache/{key}",
            get(cache::get_cached)
                .put(cache::put_cached)
                .delete(cache::delete_cached),
        );

    // TEE attestation routes (feature-gated)
    #[cfg(feature = "tee")]
    let router = router
        .route("/attestation/status", get(attestation::status))
        .route(
            "/attestation/report",
            get(attestation::cached_report).post(attestation::generate_report),
        )
        // Mnemonic export (super admin only, time-limited)
        .route(
            "/attestation/mnemonic",
            get(attestation::mnemonic_status).post(attestation::mnemonic_export),
        )
        // Auto-generated DID log (unauthenticated — public data)
        .route("/attestation/did-log", get(attestation::did_log))
        // Bootstrapped admin credential (unauthenticated — one-time retrieval)
        .route(
            "/attestation/admin-credential",
            get(attestation::admin_credential),
        );

    // WebVH routes (feature-gated)
    #[cfg(feature = "webvh")]
    let router = router
        .route(
            "/webvh/servers",
            get(did_webvh::list_servers_handler).post(did_webvh::add_server_handler),
        )
        .route(
            "/webvh/servers/{id}",
            axum::routing::patch(did_webvh::update_server_handler)
                .delete(did_webvh::remove_server_handler),
        )
        .route(
            "/webvh/dids",
            get(did_webvh::list_dids_handler).post(did_webvh::create_did_handler),
        )
        .route(
            "/webvh/dids/{did}",
            get(did_webvh::get_did_handler).delete(did_webvh::delete_did_handler),
        )
        .route("/webvh/dids/{did}/log", get(did_webvh::get_did_log_handler));

    // VTA management routes
    let router = router
        .route("/vta/restart", post(vta::restart))
        .route("/metrics", get(vta::metrics))
        .route("/backup/export", post(backup::export))
        .route("/backup/import", post(backup::import));

    // Authenticated health details and capabilities
    let router = router
        .route("/health/details", get(health::health_details))
        .route("/capabilities", get(capabilities::capabilities));

    // Apply global request body size limit to protect enclave memory
    router.layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
}
