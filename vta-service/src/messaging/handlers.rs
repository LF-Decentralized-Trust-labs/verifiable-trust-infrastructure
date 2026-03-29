//! DIDComm handler functions for `affinidi-messaging-didcomm-service` Router.
//!
//! Each handler follows the `handler_fn()` pattern:
//!   - Extracts `HandlerContext`, `Message`, and `Extension<Arc<VtaState>>`
//!   - Performs auth via `auth_from_message()`
//!   - Calls the shared operation
//!   - Returns `Ok(Some(DIDCommResponse))` or `Ok(None)`

use std::sync::Arc;

use base64::Engine;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, ProblemReport,
    ServiceProblemReport,
};
use tracing::{info, warn};

use crate::acl::Role;
use crate::messaging::auth::auth_from_message;
use crate::operations;

use super::router::VtaState;

use vta_sdk::protocols::{
    acl_management, audit_management, context_management, credential_management,
    key_management, seed_management, vta_management,
};

type HandlerResult = Result<Option<DIDCommResponse>, DIDCommServiceError>;

/// Helper to convert AppError/Box<dyn Error> into DIDCommServiceError.
fn handler_err(e: impl std::fmt::Display) -> DIDCommServiceError {
    DIDCommServiceError::Handler(e.to_string())
}

/// Helper to build a typed response from a serializable result.
fn response<T: serde::Serialize>(
    msg_type: &str,
    result: &T,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let body = serde_json::to_value(result).map_err(handler_err)?;
    Ok(Some(DIDCommResponse::new(msg_type, body)))
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

pub async fn handle_create_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let body: vta_sdk::protocols::key_management::create::CreateKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::keys::create_key(
        &state.keys_ks, &state.contexts_ks, &state.seed_store, &state.audit_ks,
        &auth,
        operations::keys::CreateKeyParams {
            key_type: body.key_type,
            derivation_path: if body.derivation_path.is_empty() { None } else { Some(body.derivation_path) },
            key_id: None,
            mnemonic: body.mnemonic,
            label: body.label,
            context_id: body.context_id,
        },
        "didcomm",
    ).await.map_err(handler_err)?;
    response(key_management::CREATE_KEY_RESULT, &result)
}

pub async fn handle_get_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::key_management::get::GetKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::keys::get_key(&state.keys_ks, &auth, &body.key_id, "didcomm")
        .await.map_err(handler_err)?;
    response(key_management::GET_KEY_RESULT, &result)
}

pub async fn handle_list_keys(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::key_management::list::ListKeysBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::keys::list_keys(
        &state.keys_ks, &auth,
        operations::keys::ListKeysParams {
            offset: body.offset, limit: body.limit,
            status: body.status, context_id: body.context_id,
        },
        "didcomm",
    ).await.map_err(handler_err)?;
    response(key_management::LIST_KEYS_RESULT, &result)
}

pub async fn handle_rename_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let body: vta_sdk::protocols::key_management::rename::RenameKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::keys::rename_key(
        &state.keys_ks, &state.audit_ks, &auth, &body.key_id, &body.new_key_id, "didcomm",
    ).await.map_err(handler_err)?;
    response(key_management::RENAME_KEY_RESULT, &result)
}

pub async fn handle_revoke_key(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let body: vta_sdk::protocols::key_management::revoke::RevokeKeyBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::keys::revoke_key(
        &state.keys_ks, &state.audit_ks, &auth, &body.key_id, "didcomm",
    ).await.map_err(handler_err)?;
    response(key_management::REVOKE_KEY_RESULT, &result)
}

pub async fn handle_get_key_secret(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let body: vta_sdk::protocols::key_management::secret::GetKeySecretBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::keys::get_key_secret(
        &state.keys_ks, &state.seed_store, &state.audit_ks, &auth, &body.key_id, "didcomm",
    ).await.map_err(handler_err)?;
    response(key_management::GET_KEY_SECRET_RESULT, &result)
}

pub async fn handle_sign_request(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::key_management::sign::SignRequestBody =
        serde_json::from_value(message.body).map_err(handler_err)?;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&body.payload)
        .map_err(|e| handler_err(format!("invalid base64url payload: {e}")))?;

    let result = operations::keys::sign_payload(
        &state.keys_ks, &state.seed_store, &auth,
        &body.key_id, &payload, &body.algorithm, "didcomm",
    ).await.map_err(handler_err)?;
    response(key_management::SIGN_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Seed management
// ---------------------------------------------------------------------------

pub async fn handle_list_seeds(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let result = operations::seeds::list_seeds(&state.keys_ks, "didcomm")
        .await.map_err(handler_err)?;
    response(seed_management::LIST_SEEDS_RESULT, &result)
}

pub async fn handle_rotate_seed(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let body: vta_sdk::protocols::seed_management::rotate::RotateSeedBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::seeds::rotate_seed(
        &state.keys_ks, &state.seed_store, &state.audit_ks, &auth.did,
        body.mnemonic.as_deref(), "didcomm",
    ).await.map_err(handler_err)?;
    response(seed_management::ROTATE_SEED_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Context management
// ---------------------------------------------------------------------------

pub async fn handle_create_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::context_management::create::CreateContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::contexts::create_context(
        &state.contexts_ks, &auth, &body.id, body.name, body.description, "didcomm",
    ).await.map_err(handler_err)?;
    response(context_management::CREATE_CONTEXT_RESULT, &result)
}

pub async fn handle_get_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::context_management::get::GetContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::contexts::get_context_op(
        &state.contexts_ks, &auth, &body.id, "didcomm",
    ).await.map_err(handler_err)?;
    response(context_management::GET_CONTEXT_RESULT, &result)
}

pub async fn handle_list_contexts(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let result = operations::contexts::list_contexts(
        &state.contexts_ks, &auth, "didcomm",
    ).await.map_err(handler_err)?;
    response(context_management::LIST_CONTEXTS_RESULT, &result)
}

pub async fn handle_update_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::context_management::update::UpdateContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::contexts::update_context(
        &state.contexts_ks, &auth, &body.id,
        operations::contexts::UpdateContextParams {
            name: body.name, did: body.did, description: body.description,
        },
        "didcomm",
    ).await.map_err(handler_err)?;
    response(context_management::UPDATE_CONTEXT_RESULT, &result)
}

pub async fn handle_preview_delete_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::context_management::delete::DeleteContextPreviewBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::contexts::preview_delete_context(
        &state.contexts_ks, &state.keys_ks, &state.acl_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        &auth, &body.id, "didcomm",
    ).await.map_err(handler_err)?;
    response(context_management::PREVIEW_DELETE_CONTEXT_RESULT, &result)
}

pub async fn handle_delete_context(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::context_management::delete::DeleteContextBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::contexts::delete_context(
        &state.contexts_ks, &state.keys_ks, &state.acl_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        &auth, &body.id, body.force, "didcomm",
    ).await.map_err(handler_err)?;
    response(context_management::DELETE_CONTEXT_RESULT, &result)
}

// ---------------------------------------------------------------------------
// ACL management
// ---------------------------------------------------------------------------

pub async fn handle_create_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::acl_management::create::CreateAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let role = Role::from_str(&body.role).map_err(handler_err)?;
    let result = operations::acl::create_acl(
        &state.acl_ks, &state.audit_ks, &auth, &body.did, role, body.label, body.allowed_contexts, "didcomm",
    ).await.map_err(handler_err)?;
    response(acl_management::CREATE_ACL_RESULT, &result)
}

pub async fn handle_get_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::acl_management::get::GetAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::acl::get_acl(&state.acl_ks, &auth, &body.did, "didcomm")
        .await.map_err(handler_err)?;
    response(acl_management::GET_ACL_RESULT, &result)
}

pub async fn handle_list_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::acl_management::list::ListAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::acl::list_acl(&state.acl_ks, &auth, body.context.as_deref(), "didcomm")
        .await.map_err(handler_err)?;
    response(acl_management::LIST_ACL_RESULT, &result)
}

pub async fn handle_update_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::acl_management::update::UpdateAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let role = match body.role {
        Some(r) => Some(Role::from_str(&r).map_err(handler_err)?),
        None => None,
    };
    let result = operations::acl::update_acl(
        &state.acl_ks, &state.audit_ks, &auth, &body.did,
        operations::acl::UpdateAclParams { role, label: body.label, allowed_contexts: body.allowed_contexts },
        "didcomm",
    ).await.map_err(handler_err)?;
    response(acl_management::UPDATE_ACL_RESULT, &result)
}

pub async fn handle_delete_acl(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::acl_management::delete::DeleteAclBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::acl::delete_acl(
        &state.acl_ks, &state.audit_ks, &auth, &body.did, "didcomm",
    ).await.map_err(handler_err)?;
    response(acl_management::DELETE_ACL_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Audit management
// ---------------------------------------------------------------------------

pub async fn handle_list_logs(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::audit_management::list::ListAuditLogsBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::audit::list_audit_logs(&state.audit_ks, &auth, &body, "didcomm")
        .await.map_err(handler_err)?;
    response(audit_management::LIST_LOGS_RESULT, &result)
}

pub async fn handle_get_retention(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let result = operations::audit::get_retention(&state.config, &auth, "didcomm")
        .await.map_err(handler_err)?;
    response(audit_management::GET_RETENTION_RESULT, &result)
}

pub async fn handle_update_retention(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let body: vta_sdk::protocols::audit_management::retention::UpdateRetentionBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::audit::update_retention(
        &state.config, &state.audit_ks, &auth, body.retention_days, "didcomm",
    ).await.map_err(handler_err)?;
    response(audit_management::UPDATE_RETENTION_RESULT, &result)
}

// ---------------------------------------------------------------------------
// VTA management
// ---------------------------------------------------------------------------

pub async fn handle_get_config(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let result = operations::config::get_config(&state.config, &auth, "didcomm")
        .await.map_err(handler_err)?;
    response(vta_management::GET_CONFIG_RESULT, &result)
}

pub async fn handle_update_config(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::config::update_config(
        &state.config, &auth,
        operations::config::UpdateConfigParams {
            vta_did: body.vta_did, vta_name: body.vta_name, public_url: body.public_url,
        },
        "didcomm",
    ).await.map_err(handler_err)?;
    response(vta_management::UPDATE_CONFIG_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Credential management
// ---------------------------------------------------------------------------

pub async fn handle_generate_credentials(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::credential_management::generate::GenerateCredentialsBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let role = Role::from_str(&body.role).map_err(handler_err)?;
    let result = operations::credentials::generate_credentials(
        &state.acl_ks, &state.config, &auth, role, body.label, body.allowed_contexts, "didcomm",
    ).await.map_err(handler_err)?;
    response(credential_management::GENERATE_CREDENTIALS_RESULT, &result)
}

// ---------------------------------------------------------------------------
// DID WebVH management (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "webvh")]
pub async fn handle_create_did_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::create::CreateDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let config = state.config.read().await;
    let did_resolver = state.did_resolver.as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;

    // NOTE: The DIDComm bridge for WebVH server communication is not yet
    // available in the new service handler path. This will be wired in PR 3
    // when DIDCommService replaces the manual thread. For now, pass a dummy
    // empty bridge that will use REST fallback if available.
    let bridge = std::sync::Arc::new(tokio::sync::RwLock::new(None));

    let result = operations::did_webvh::create_did_webvh(
        &state.keys_ks, &state.contexts_ks, &state.webvh_ks, &*state.seed_store,
        &config, &auth,
        operations::did_webvh::CreateDidWebvhParams {
            context_id: body.context_id, server_id: body.server_id,
            url: body.url, path: body.path, label: body.label,
            portable: body.portable.unwrap_or(true),
            add_mediator_service: body.add_mediator_service.unwrap_or(false),
            additional_services: body.additional_services,
            pre_rotation_count: body.pre_rotation_count.unwrap_or(0),
        },
        did_resolver, &bridge, "didcomm",
    ).await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::CREATE_DID_WEBVH_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_get_did_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::get::GetDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::did_webvh::get_did_webvh(&state.webvh_ks, &auth, &body.did, "didcomm")
        .await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::GET_DID_WEBVH_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_get_did_webvh_log(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::get::GetDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::did_webvh::get_did_webvh_log(&state.webvh_ks, &auth, &body.did, "didcomm")
        .await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::GET_DID_WEBVH_LOG_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_list_dids_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::list::ListDidsWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::did_webvh::list_dids_webvh(
        &state.webvh_ks, &auth, body.context_id.as_deref(), body.server_id.as_deref(), "didcomm",
    ).await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::LIST_DIDS_WEBVH_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_delete_did_webvh(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::delete::DeleteDidWebvhBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let config = state.config.read().await;
    let did_resolver = state.did_resolver.as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;
    // NOTE: Bridge not yet wired — see handle_create_did_webvh comment
    let bridge = std::sync::Arc::new(tokio::sync::RwLock::new(None));
    let result = operations::did_webvh::delete_did_webvh(
        &state.webvh_ks, &state.keys_ks, &*state.seed_store, &config, &auth,
        &body.did, did_resolver, &bridge, "didcomm",
    ).await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::DELETE_DID_WEBVH_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_add_webvh_server(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::servers::AddWebvhServerBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let did_resolver = state.did_resolver.as_ref()
        .ok_or_else(|| handler_err("DID resolver not available"))?;
    let result = operations::did_webvh::add_webvh_server(
        &state.webvh_ks, &auth, &body.id, &body.did, body.label, did_resolver, "didcomm",
    ).await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::ADD_WEBVH_SERVER_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_list_webvh_servers(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let result = operations::did_webvh::list_webvh_servers(&state.webvh_ks, &auth, "didcomm")
        .await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::LIST_WEBVH_SERVERS_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_update_webvh_server(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::servers::UpdateWebvhServerBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::did_webvh::update_webvh_server(
        &state.webvh_ks, &auth, &body.id, body.label, "didcomm",
    ).await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::UPDATE_WEBVH_SERVER_RESULT, &result)
}

#[cfg(feature = "webvh")]
pub async fn handle_remove_webvh_server(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::did_management::servers::RemoveWebvhServerBody =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::did_webvh::remove_webvh_server(&state.webvh_ks, &auth, &body.id, "didcomm")
        .await.map_err(handler_err)?;
    response(vta_sdk::protocols::did_management::REMOVE_WEBVH_SERVER_RESULT, &result)
}

// ---------------------------------------------------------------------------
// TEE Attestation (feature-gated, unauthenticated)
// ---------------------------------------------------------------------------

#[cfg(feature = "tee")]
pub async fn handle_tee_status(
    _ctx: HandlerContext,
    _message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let tee_state = state.tee_state.as_ref()
        .ok_or_else(|| handler_err("TEE attestation is not enabled on this VTA"))?;
    let status = operations::attestation::get_tee_status(tee_state);
    response(vta_sdk::protocols::attestation_management::GET_TEE_STATUS_RESULT, &status)
}

#[cfg(feature = "tee")]
pub async fn handle_request_attestation(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let tee_state = state.tee_state.as_ref()
        .ok_or_else(|| handler_err("TEE attestation is not enabled on this VTA"))?;
    let body: crate::tee::types::AttestationRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let result = operations::attestation::generate_attestation_report(
        tee_state, &state.config, &body.nonce,
    ).await.map_err(handler_err)?;
    response(vta_sdk::protocols::attestation_management::ATTESTATION_RESULT, &result)
}

// ---------------------------------------------------------------------------
// VTA management — restart
// ---------------------------------------------------------------------------

pub async fn handle_restart(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let _ = crate::audit::record(
        &state.audit_ks, "vta.restart", &auth.did, None, "success", Some("didcomm"), None,
    ).await;
    // Trigger restart after a short delay so the response can be sent first
    let restart_tx = state.restart_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = restart_tx.send(true);
    });
    response(vta_sdk::protocols::vta_management::RESTART_RESULT, &vta_sdk::protocols::vta_management::restart::RestartResult {
        status: "restarting".into(),
    })
}

// ---------------------------------------------------------------------------
// Backup management
// ---------------------------------------------------------------------------

pub async fn handle_backup_export(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    let body: vta_sdk::protocols::backup_management::types::ExportRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;
    let config = state.config.read().await;
    let envelope = operations::backup::export_backup(
        &state.keys_ks, &state.acl_ks, &state.contexts_ks, &state.audit_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        &*state.seed_store, &config, &auth, &body.password, body.include_audit,
    ).await.map_err(handler_err)?;
    let _ = crate::audit::record(
        &state.audit_ks, "backup.export", &auth.did, None, "success", Some("didcomm"), None,
    ).await;
    let response_json = serde_json::to_string(&envelope).unwrap_or_default();
    info!(
        response_bytes = response_json.len(),
        "backup export DIDComm response size"
    );
    response(vta_sdk::protocols::backup_management::EXPORT_BACKUP_RESULT, &envelope)
}

pub async fn handle_backup_import(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<Arc<VtaState>>,
) -> HandlerResult {
    let auth = auth_from_message(&message, &state.acl_ks).await.map_err(handler_err)?;
    auth.require_admin().map_err(handler_err)?;
    let body: vta_sdk::protocols::backup_management::types::ImportRequest =
        serde_json::from_value(message.body).map_err(handler_err)?;

    if !body.confirm {
        let (_payload, preview) =
            operations::backup::preview_import(&body.backup, &body.password)
                .await.map_err(handler_err)?;
        return response(vta_sdk::protocols::backup_management::IMPORT_BACKUP_RESULT, &preview);
    }

    let (payload, _) =
        operations::backup::preview_import(&body.backup, &body.password)
            .await.map_err(handler_err)?;

    let result = operations::backup::apply_import(
        &payload,
        &state.keys_ks, &state.acl_ks, &state.contexts_ks, &state.audit_ks,
        #[cfg(feature = "webvh")]
        &state.webvh_ks,
        &state.seed_store, &state.config,
        None, // Store for TEE re-encryption (handled on restart)
    ).await.map_err(handler_err)?;

    let _ = crate::audit::record(
        &state.audit_ks, "backup.import", &auth.did,
        payload.config.vta_did.as_deref(), "success", Some("didcomm"), None,
    ).await;

    // Trigger soft restart after response is sent
    let restart_tx = state.restart_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = restart_tx.send(true);
    });

    response(vta_sdk::protocols::backup_management::IMPORT_BACKUP_RESULT, &result)
}

// ---------------------------------------------------------------------------
// Problem report & fallback
// ---------------------------------------------------------------------------

pub async fn handle_problem_report(
    _ctx: HandlerContext,
    message: Message,
) -> HandlerResult {
    let code = message.body.get("code").and_then(|v| v.as_str()).unwrap_or("unknown");
    let comment = message.body.get("comment").and_then(|v| v.as_str()).unwrap_or("");
    let from = message.from.as_deref().unwrap_or("unknown");
    let thid = message.thid.as_deref().unwrap_or("none");
    warn!(from, code, comment, thid, "received problem-report");
    Ok(None)
}

pub async fn handle_unknown(
    _ctx: HandlerContext,
    message: Message,
) -> HandlerResult {
    warn!(msg_type = %message.typ, "unknown message type — ignoring");
    Ok(Some(DIDCommResponse::problem_report(
        ProblemReport::bad_request(format!("unsupported message type: {}", message.typ)),
    )))
}
