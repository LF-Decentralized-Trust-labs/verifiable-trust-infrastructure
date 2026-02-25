use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use vta_sdk::protocols::{MESSAGE_PICKUP_STATUS_TYPE, TRUST_PING_TYPE};

use crate::config::AppConfig;

/// Initialize the DIDComm connection to the mediator.
pub async fn init_didcomm_connection(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    vtc_did: &str,
) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
    let mediator_did = match &config.messaging {
        Some(m) => &m.mediator_did,
        None => {
            warn!("messaging not configured — inbound message handling disabled");
            return None;
        }
    };
    vta_sdk::didcomm_init::init_didcomm_connection(mediator_did, secrets_resolver, vtc_did, "VTC")
        .await
}

/// Run the DIDComm inbound message loop until shutdown is signaled.
///
/// Receives messages from the ATM inbound channel and dispatches them to
/// protocol handlers. Exits when `shutdown_rx` fires or the channel closes.
pub async fn run_didcomm_loop(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    vtc_did: &str,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut rx: broadcast::Receiver<WebSocketResponses> = match atm.get_inbound_channel() {
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
                match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _metadata)) => {
                        dispatch_message(atm, profile, vtc_did, &msg).await;
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => {
                                dispatch_message(atm, profile, vtc_did, &msg).await;
                            }
                            Err(e) => {
                                warn!("failed to unpack inbound message: {e}");
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("inbound message channel lagged, missed {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("inbound message channel closed — stopping message loop");
                        break;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("shutdown signal received — stopping DIDComm message loop");
                break;
            }
        }
    }
}

async fn dispatch_message(atm: &ATM, profile: &Arc<ATMProfile>, vtc_did: &str, msg: &Message) {
    match msg.type_.as_str() {
        TRUST_PING_TYPE => {
            if let Err(e) =
                vta_sdk::didcomm_init::handle_trust_ping(atm, profile, vtc_did, msg).await
            {
                warn!("failed to handle trust-ping: {e}");
            }
        }
        MESSAGE_PICKUP_STATUS_TYPE => {
            // Mediator status notifications — safe to ignore
        }
        other => {
            warn!(msg_type = other, "unknown message type — ignoring");
        }
    }

    // Always delete the message from the mediator after processing
    if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
        warn!("failed to delete message from mediator: {e}");
    }
}
