use std::collections::HashMap;
use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use vta_sdk::didcomm_transport::{DIDCommSendParams, PendingMap, send_and_wait_raw};

use crate::error::{AppError, bad_gateway_error};

/// Bridge between REST/DIDComm handlers and the DIDComm listener's ATM.
///
/// Provides outbound request-response DIDComm messaging by registering
/// oneshot channels keyed by message ID. The [`BridgeHandler`] wrapper
/// calls [`try_complete`] on each inbound message to route responses
/// back to the waiting handler.
///
/// The bridge starts disconnected. The listener's ATM is captured via
/// [`update_connection`] when the first inbound message arrives.
///
/// [`BridgeHandler`]: crate::messaging::router::BridgeHandler
pub struct DIDCommBridge {
    connection: tokio::sync::RwLock<Option<(ATM, Arc<ATMProfile>)>>,
    pending: PendingMap,
}

impl DIDCommBridge {
    /// Create a new bridge in disconnected state.
    ///
    /// The connection will be populated by [`BridgeHandler`] once the
    /// DIDComm listener connects to the mediator.
    pub fn new() -> Self {
        Self {
            connection: tokio::sync::RwLock::new(None),
            pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Store the listener's ATM connection for outbound use.
    ///
    /// Called by [`BridgeHandler`] on every inbound message to keep
    /// the reference current across listener reconnects.
    pub async fn update_connection(&self, atm: ATM, profile: Arc<ATMProfile>) {
        let mut guard = self.connection.write().await;
        *guard = Some((atm, profile));
    }

    /// Try to complete a pending outbound request. Returns true if the
    /// message was routed to a waiting [`send_and_wait`] caller.
    pub fn try_complete(&self, msg: &Message) -> bool {
        if let Some(thid) = &msg.thid
            && let Some(tx) = self.pending.lock().unwrap().remove(thid)
        {
            let _ = tx.send(msg.clone());
            return true;
        }
        false
    }

    /// Send a DIDComm message and wait for a response matching the thread ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_and_wait(
        &self,
        vta_did: &str,
        server_did: &str,
        msg_type: &str,
        body: serde_json::Value,
        expected_type: &str,
        problem_report_type: &str,
        timeout_secs: u64,
    ) -> Result<Message, AppError> {
        let (atm, profile) = {
            let guard = self.connection.read().await;
            guard
                .as_ref()
                .map(|(a, p)| (a.clone(), p.clone()))
                .ok_or_else(|| {
                    AppError::Internal(
                        "DIDComm not available — mediator connection not established".into(),
                    )
                })?
        };

        send_and_wait_raw(DIDCommSendParams {
            atm: &atm,
            profile: &profile,
            pending: &self.pending,
            from_did: vta_did,
            to_did: server_did,
            msg_type,
            body,
            expected_type,
            problem_report_type,
            timeout_secs,
        })
        .await
        .map_err(bad_gateway_error)
    }
}
