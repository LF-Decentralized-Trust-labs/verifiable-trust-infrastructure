mod acl;
mod auth;
mod config;
mod contexts;
#[cfg(feature = "webvh")]
mod did_webvh;
mod health;
pub mod keys;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    let router = Router::new()
        .route("/health", get(health::health))
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
        // ACL routes (flattened for consistency)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route(
            "/acl/{did}",
            get(acl::get_acl)
                .patch(acl::update_acl)
                .delete(acl::delete_acl),
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
        );

    router
}
