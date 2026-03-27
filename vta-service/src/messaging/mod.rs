pub mod auth;
pub mod handlers;
pub mod response;

use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use tokio::sync::{RwLock, broadcast, watch};
use tracing::{debug, info, warn};

#[cfg(feature = "tee")]
use vta_sdk::protocols::attestation_management;
#[cfg(feature = "webvh")]
use vta_sdk::protocols::did_management;
use vta_sdk::protocols::{
    self, acl_management, audit_management, context_management, credential_management,
    key_management, seed_management, vta_management,
};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;

use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::SeedStore;
use crate::store::KeyspaceHandle;

/// Shared state passed to DIDComm message handlers.
pub struct DidcommState {
    pub keys_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub contexts_ks: KeyspaceHandle,
    pub audit_ks: KeyspaceHandle,
    #[cfg(feature = "webvh")]
    pub webvh_ks: KeyspaceHandle,
    pub seed_store: Arc<dyn SeedStore>,
    pub config: Arc<RwLock<AppConfig>>,
    pub did_resolver: Option<DIDCacheClient>,
    pub didcomm_bridge: Arc<tokio::sync::RwLock<Option<DIDCommBridge>>>,
    #[cfg(feature = "tee")]
    pub tee_state: Option<crate::tee::TeeState>,
}

/// Initialize the DIDComm connection to the mediator.
pub async fn init_didcomm_connection(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vta_did: &str,
) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
    let mediator_did = match &config.messaging {
        Some(m) => &m.mediator_did,
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            return None;
        }
    };
    vta_sdk::didcomm_init::init_didcomm_connection(
        mediator_did,
        secrets_resolver,
        vta_did,
        "VTA",
        config.resolver_url.as_deref(),
    )
    .await
}

/// Run the DIDComm inbound message loop until shutdown is signaled.
///
/// Receives messages from the ATM inbound channel and dispatches them to
/// protocol handlers. Messages matching a pending bridge request (by thread ID)
/// are routed directly to the waiting handler instead.
pub async fn run_didcomm_loop(
    bridge: &DIDCommBridge,
    vta_did: &str,
    state: Arc<DidcommState>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut rx: broadcast::Receiver<WebSocketResponses> = match bridge.atm.get_inbound_channel() {
        Some(rx) => rx,
        None => {
            warn!("no inbound channel available — messaging disabled");
            return;
        }
    };

    info!("DIDComm message loop started");

    loop {
        tokio::select! {
            result = rx.recv() => {
                let msg = match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _metadata)) => *msg,
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match bridge.atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => msg,
                            Err(e) => {
                                // Stale message encrypted with a previous key (e.g., after
                                // TEE reboot with new identity). Logged once per message;
                                // the mediator clears it after live delivery.
                                warn!("skipping undecryptable message (stale key?): {e}");
                                continue;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("inbound message channel lagged, missed {n} messages");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("inbound message channel closed — stopping message loop");
                        break;
                    }
                };

                // Check if this message completes a pending bridge request
                if bridge.try_complete(&msg) {
                    debug!(thid = ?msg.thid, "routed message to pending bridge request");
                    if let Err(e) = bridge.atm.delete_message_background(&bridge.profile, &msg.id).await {
                        warn!("failed to delete bridged message from mediator: {e}");
                    }
                    continue;
                }

                // Spawn handler as a separate task so the loop can continue
                // receiving messages (needed for bridge responses).
                let atm = Arc::clone(&bridge.atm);
                let profile = Arc::clone(&bridge.profile);
                let vta_did = vta_did.to_string();
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    dispatch_message(&atm, &profile, &vta_did, &state, &msg).await;
                });
            }
            _ = shutdown_rx.changed() => {
                info!("shutdown signal received — stopping DIDComm message loop");
                break;
            }
        }
    }
}

async fn dispatch_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    vta_did: &str,
    state: &DidcommState,
    msg: &Message,
) {
    if msg.typ != protocols::TRUST_PING_TYPE && msg.typ != protocols::MESSAGE_PICKUP_STATUS_TYPE
    {
        info!(
            channel = "didcomm",
            msg_type = %msg.typ,
            from = msg.from.as_deref().unwrap_or("unknown"),
            msg_id = %msg.id,
            "inbound request"
        );
    }

    let ctx = response::DIDCommCtx {
        atm,
        profile,
        vta_did,
    };

    let result = match msg.typ.as_str() {
        protocols::TRUST_PING_TYPE => {
            vta_sdk::didcomm_init::handle_trust_ping(atm, profile, vta_did, msg).await
        }
        protocols::MESSAGE_PICKUP_STATUS_TYPE => Ok(()),

        // Key management
        key_management::CREATE_KEY => handlers::keys::handle_create_key(state, &ctx, msg).await,
        key_management::GET_KEY => handlers::keys::handle_get_key(state, &ctx, msg).await,
        key_management::LIST_KEYS => handlers::keys::handle_list_keys(state, &ctx, msg).await,
        key_management::RENAME_KEY => handlers::keys::handle_rename_key(state, &ctx, msg).await,
        key_management::REVOKE_KEY => handlers::keys::handle_revoke_key(state, &ctx, msg).await,
        key_management::GET_KEY_SECRET => {
            handlers::keys::handle_get_key_secret(state, &ctx, msg).await
        }

        // Seed management
        seed_management::LIST_SEEDS => handlers::seeds::handle_list_seeds(state, &ctx, msg).await,
        seed_management::ROTATE_SEED => handlers::seeds::handle_rotate_seed(state, &ctx, msg).await,

        // Context management
        context_management::CREATE_CONTEXT => {
            handlers::contexts::handle_create_context(state, &ctx, msg).await
        }
        context_management::GET_CONTEXT => {
            handlers::contexts::handle_get_context(state, &ctx, msg).await
        }
        context_management::LIST_CONTEXTS => {
            handlers::contexts::handle_list_contexts(state, &ctx, msg).await
        }
        context_management::UPDATE_CONTEXT => {
            handlers::contexts::handle_update_context(state, &ctx, msg).await
        }
        context_management::PREVIEW_DELETE_CONTEXT => {
            handlers::contexts::handle_preview_delete_context(state, &ctx, msg).await
        }
        context_management::DELETE_CONTEXT => {
            handlers::contexts::handle_delete_context(state, &ctx, msg).await
        }

        // ACL management
        acl_management::CREATE_ACL => handlers::acl::handle_create_acl(state, &ctx, msg).await,
        acl_management::GET_ACL => handlers::acl::handle_get_acl(state, &ctx, msg).await,
        acl_management::LIST_ACL => handlers::acl::handle_list_acl(state, &ctx, msg).await,
        acl_management::UPDATE_ACL => handlers::acl::handle_update_acl(state, &ctx, msg).await,
        acl_management::DELETE_ACL => handlers::acl::handle_delete_acl(state, &ctx, msg).await,

        // Audit management
        audit_management::LIST_LOGS => handlers::audit::handle_list_logs(state, &ctx, msg).await,
        audit_management::GET_RETENTION => handlers::audit::handle_get_retention(state, &ctx, msg).await,
        audit_management::UPDATE_RETENTION => handlers::audit::handle_update_retention(state, &ctx, msg).await,

        // VTA management
        vta_management::GET_CONFIG => handlers::config::handle_get_config(state, &ctx, msg).await,
        vta_management::UPDATE_CONFIG => {
            handlers::config::handle_update_config(state, &ctx, msg).await
        }

        // Credential management
        credential_management::GENERATE_CREDENTIALS => {
            handlers::credentials::handle_generate_credentials(state, &ctx, msg).await
        }

        // DID management (webvh)
        #[cfg(feature = "webvh")]
        did_management::CREATE_DID_WEBVH => {
            handlers::did_webvh::handle_create_did_webvh(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::GET_DID_WEBVH => {
            handlers::did_webvh::handle_get_did_webvh(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::GET_DID_WEBVH_LOG => {
            handlers::did_webvh::handle_get_did_webvh_log(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::LIST_DIDS_WEBVH => {
            handlers::did_webvh::handle_list_dids_webvh(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::DELETE_DID_WEBVH => {
            handlers::did_webvh::handle_delete_did_webvh(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::ADD_WEBVH_SERVER => {
            handlers::did_webvh::handle_add_webvh_server(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::LIST_WEBVH_SERVERS => {
            handlers::did_webvh::handle_list_webvh_servers(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::UPDATE_WEBVH_SERVER => {
            handlers::did_webvh::handle_update_webvh_server(state, &ctx, msg).await
        }
        #[cfg(feature = "webvh")]
        did_management::REMOVE_WEBVH_SERVER => {
            handlers::did_webvh::handle_remove_webvh_server(state, &ctx, msg).await
        }

        // TEE attestation (unauthenticated — trust is established via attestation)
        #[cfg(feature = "tee")]
        attestation_management::GET_TEE_STATUS => {
            handlers::attestation::handle_tee_status(state, &ctx, msg).await
        }
        #[cfg(feature = "tee")]
        attestation_management::REQUEST_ATTESTATION => {
            handlers::attestation::handle_request_attestation(state, &ctx, msg).await
        }

        // Problem reports (standard DIDComm type)
        protocols::PROBLEM_REPORT_TYPE => {
            handle_problem_report(msg);
            Ok(())
        }

        other => {
            warn!(msg_type = other, "unknown message type — ignoring");
            Ok(())
        }
    };

    if let Err(e) = result {
        warn!(msg_type = %msg.typ, error = %e, "handler error");
        if let Some(sender) = msg.from.as_deref() {
            let sender = sender.split('#').next().unwrap_or(sender);
            let _ = ctx
                .send_error(sender, Some(&msg.id), "e.p.processing", &e.to_string())
                .await;
        }
    }

    // Always delete message from mediator
    if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
        warn!("failed to delete message from mediator: {e}");
    }
}

fn handle_problem_report(msg: &Message) {
    let (code, comment) = protocols::extract_problem_report(&msg.body);
    let from = msg.from.as_deref().unwrap_or("unknown");
    let thid = msg.thid.as_deref().unwrap_or("none");

    warn!(from, code, comment, thid, "received problem-report");
}
