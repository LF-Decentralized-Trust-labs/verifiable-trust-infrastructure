use std::collections::HashMap;
use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::didcomm_transport::{PendingMap, send_and_wait_raw};
use crate::protocols::PROBLEM_REPORT_TYPE;

/// Client-side DIDComm session for request-response messaging via ATM.
///
/// Mirrors the server's `DIDCommBridge` pattern but from the client side.
/// Maintains a persistent ATM connection with a spawned inbound routing task
/// that matches responses to pending requests by thread ID.
pub struct DIDCommSession {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    pub(crate) client_did: String,
    pub(crate) vta_did: String,
    pending: PendingMap,
    _inbound_task: JoinHandle<()>,
}

impl DIDCommSession {
    /// Connect to a VTA via DIDComm through a mediator.
    pub async fn connect(
        client_did: &str,
        private_key_multibase: &str,
        vta_did: &str,
        mediator_did: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Decode private key and build DIDComm secrets
        let seed = crate::did_key::decode_private_key_multibase(private_key_multibase)?;
        let secrets = crate::did_key::secrets_from_did_key(client_did, &seed)?;

        // Create TDK shared state and insert secrets
        let tdk = TDKSharedState::default().await;
        tdk.secrets_resolver.insert(secrets.signing).await;
        tdk.secrets_resolver.insert(secrets.key_agreement).await;

        // Build ATM with inbound message channel
        let atm_config = ATMConfig::builder()
            .with_inbound_message_channel(100)
            .build()?;
        let atm = ATM::new(atm_config, Arc::new(tdk)).await?;

        // Create profile with mediator
        let profile = ATMProfile::new(
            &atm,
            None,
            client_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await?;
        let profile = Arc::new(profile);

        // Enable WebSocket (starts live streaming from mediator)
        atm.profile_enable_websocket(&profile).await?;

        let atm = Arc::new(atm);
        let pending: PendingMap = Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Spawn inbound routing task
        let inbound_rx = atm
            .get_inbound_channel()
            .ok_or("no inbound channel available")?;
        let task_atm = atm.clone();
        let task_profile = profile.clone();
        let task_pending = pending.clone();
        let inbound_task = tokio::spawn(async move {
            run_inbound_loop(inbound_rx, &task_atm, &task_profile, &task_pending).await;
        });

        debug!("DIDComm session connected via mediator {mediator_did}");

        Ok(Self {
            atm,
            profile,
            client_did: client_did.to_string(),
            vta_did: vta_did.to_string(),
            pending,
            _inbound_task: inbound_task,
        })
    }

    /// Send a DIDComm message and wait for a matching response.
    ///
    /// Builds an encrypted message, sends it via ATM, waits for a response
    /// matching the thread ID, then deserializes the response body.
    pub async fn send_and_wait<T: serde::de::DeserializeOwned>(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        expected_result_type: &str,
        timeout_secs: u64,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let response = send_and_wait_raw(
            &self.atm,
            &self.profile,
            &self.pending,
            &self.client_did,
            &self.vta_did,
            msg_type,
            body,
            expected_result_type,
            PROBLEM_REPORT_TYPE,
            timeout_secs,
        )
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

        // Delete message from mediator (best-effort)
        if let Err(e) = self
            .atm
            .delete_message_background(&self.profile, &response.id)
            .await
        {
            warn!("failed to delete message from mediator: {e}");
        }

        // Deserialize response body
        serde_json::from_value(response.body)
            .map_err(|e| format!("failed to deserialize DIDComm response: {e}").into())
    }

    /// Gracefully shut down the DIDComm session.
    pub async fn shutdown(&self) {
        self.atm.graceful_shutdown().await;
        self._inbound_task.abort();
    }
}

/// Inbound message routing loop.
///
/// Receives messages from the ATM broadcast channel and routes them to
/// pending requests by matching thread ID.
async fn run_inbound_loop(
    mut rx: broadcast::Receiver<WebSocketResponses>,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    pending: &PendingMap,
) {
    loop {
        let msg = match rx.recv().await {
            Ok(WebSocketResponses::MessageReceived(msg, _metadata)) => *msg,
            Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                match atm.unpack(&packed).await {
                    Ok((msg, _metadata)) => msg,
                    Err(e) => {
                        warn!("failed to unpack inbound message: {e}");
                        continue;
                    }
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("inbound channel lagged, missed {n} messages");
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("inbound channel closed");
                break;
            }
        };

        // Try to complete a pending request by thread ID
        if let Some(thid) = &msg.thid {
            if let Some(tx) = pending.lock().unwrap().remove(thid) {
                let _ = tx.send(msg);
                continue;
            }
        }

        // Unexpected inbound message — delete from mediator
        if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
            warn!("failed to delete unexpected message from mediator: {e}");
        }
    }
}
