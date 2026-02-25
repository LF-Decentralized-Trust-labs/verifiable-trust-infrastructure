mod acl;
mod auth;
mod config;
mod health;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
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
        // ACL routes (flattened for consistency)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route(
            "/acl/{did}",
            get(acl::get_acl)
                .patch(acl::update_acl)
                .delete(acl::delete_acl),
        )
}
