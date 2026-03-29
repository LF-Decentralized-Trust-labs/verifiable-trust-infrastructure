//! DIDComm message router built on `affinidi-messaging-didcomm-service`.
//!
//! Replaces the manual `dispatch_message()` match statement with a typed
//! Router that maps message types to handler functions. Shared state is
//! injected via `Extension<Arc<VtaState>>`.

use std::sync::Arc;

use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, MessagePolicy, RequestLogging, Router,
    handler_fn, ignore_handler, trust_ping_handler, TRUST_PING_TYPE, MESSAGE_PICKUP_STATUS_TYPE,
};
use tokio::sync::RwLock;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;

use crate::config::AppConfig;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;

use super::handlers;

#[cfg(feature = "tee")]
use vta_sdk::protocols::attestation_management;
#[cfg(feature = "webvh")]
use vta_sdk::protocols::did_management;
use vta_sdk::protocols::{
    self, acl_management, audit_management, context_management, credential_management,
    key_management, seed_management, vta_management,
};

/// Shared state injected into all DIDComm handlers via `Extension<Arc<VtaState>>`.
#[derive(Clone)]
pub struct VtaState {
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: KeyspaceHandle,
    pub seed_store: Arc<dyn SeedStore>,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    #[cfg(feature = "tee")]
    pub tee_state: Option<crate::tee::TeeState>,
    /// Send `true` to trigger a soft restart.
    pub restart_tx: tokio::sync::watch::Sender<bool>,
}

/// Build the DIDComm message router with all VTA protocol handlers.
pub fn build_router(state: Arc<VtaState>) -> Result<Router, DIDCommServiceError> {
    let mut router = Router::new()
        .extension(state)
        // Built-in protocol handlers
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        // Key management
        .route(key_management::CREATE_KEY, handler_fn(handlers::handle_create_key))?
        .route(key_management::GET_KEY, handler_fn(handlers::handle_get_key))?
        .route(key_management::LIST_KEYS, handler_fn(handlers::handle_list_keys))?
        .route(key_management::RENAME_KEY, handler_fn(handlers::handle_rename_key))?
        .route(key_management::REVOKE_KEY, handler_fn(handlers::handle_revoke_key))?
        .route(key_management::GET_KEY_SECRET, handler_fn(handlers::handle_get_key_secret))?
        .route(key_management::SIGN_REQUEST, handler_fn(handlers::handle_sign_request))?
        // Seed management
        .route(seed_management::LIST_SEEDS, handler_fn(handlers::handle_list_seeds))?
        .route(seed_management::ROTATE_SEED, handler_fn(handlers::handle_rotate_seed))?
        // Context management
        .route(context_management::CREATE_CONTEXT, handler_fn(handlers::handle_create_context))?
        .route(context_management::GET_CONTEXT, handler_fn(handlers::handle_get_context))?
        .route(context_management::LIST_CONTEXTS, handler_fn(handlers::handle_list_contexts))?
        .route(context_management::UPDATE_CONTEXT, handler_fn(handlers::handle_update_context))?
        .route(context_management::PREVIEW_DELETE_CONTEXT, handler_fn(handlers::handle_preview_delete_context))?
        .route(context_management::DELETE_CONTEXT, handler_fn(handlers::handle_delete_context))?
        // ACL management
        .route(acl_management::CREATE_ACL, handler_fn(handlers::handle_create_acl))?
        .route(acl_management::GET_ACL, handler_fn(handlers::handle_get_acl))?
        .route(acl_management::LIST_ACL, handler_fn(handlers::handle_list_acl))?
        .route(acl_management::UPDATE_ACL, handler_fn(handlers::handle_update_acl))?
        .route(acl_management::DELETE_ACL, handler_fn(handlers::handle_delete_acl))?
        // Audit management
        .route(audit_management::LIST_LOGS, handler_fn(handlers::handle_list_logs))?
        .route(audit_management::GET_RETENTION, handler_fn(handlers::handle_get_retention))?
        .route(audit_management::UPDATE_RETENTION, handler_fn(handlers::handle_update_retention))?
        // VTA management
        .route(vta_management::GET_CONFIG, handler_fn(handlers::handle_get_config))?
        .route(vta_management::UPDATE_CONFIG, handler_fn(handlers::handle_update_config))?
        // Credential management
        .route(credential_management::GENERATE_CREDENTIALS, handler_fn(handlers::handle_generate_credentials))?
        // Problem reports
        .route(protocols::PROBLEM_REPORT_TYPE, handler_fn(handlers::handle_problem_report))?
        // VTA management — restart
        .route(vta_management::RESTART, handler_fn(handlers::handle_restart))?
        // Backup management
        .route(protocols::backup_management::EXPORT_BACKUP, handler_fn(handlers::handle_backup_export))?
        .route(protocols::backup_management::IMPORT_BACKUP, handler_fn(handlers::handle_backup_import))?;

    // WebVH handlers (feature-gated)
    #[cfg(feature = "webvh")]
    {
        router = router
            .route(did_management::CREATE_DID_WEBVH, handler_fn(handlers::handle_create_did_webvh))?
            .route(did_management::GET_DID_WEBVH, handler_fn(handlers::handle_get_did_webvh))?
            .route(did_management::GET_DID_WEBVH_LOG, handler_fn(handlers::handle_get_did_webvh_log))?
            .route(did_management::LIST_DIDS_WEBVH, handler_fn(handlers::handle_list_dids_webvh))?
            .route(did_management::DELETE_DID_WEBVH, handler_fn(handlers::handle_delete_did_webvh))?
            .route(did_management::ADD_WEBVH_SERVER, handler_fn(handlers::handle_add_webvh_server))?
            .route(did_management::LIST_WEBVH_SERVERS, handler_fn(handlers::handle_list_webvh_servers))?
            .route(did_management::UPDATE_WEBVH_SERVER, handler_fn(handlers::handle_update_webvh_server))?
            .route(did_management::REMOVE_WEBVH_SERVER, handler_fn(handlers::handle_remove_webvh_server))?;
    }

    // TEE attestation handlers (feature-gated)
    #[cfg(feature = "tee")]
    {
        router = router
            .route(attestation_management::GET_TEE_STATUS, handler_fn(handlers::handle_tee_status))?
            .route(attestation_management::REQUEST_ATTESTATION, handler_fn(handlers::handle_request_attestation))?;
    }

    // Fallback, middleware, error handling
    router = router
        .fallback(handler_fn(handlers::handle_unknown))
        .layer(MessagePolicy::new()
            .require_encrypted(true)
            .require_authenticated(true)
            .allow_anonymous_sender(false))
        .layer(RequestLogging);

    Ok(router)
}
