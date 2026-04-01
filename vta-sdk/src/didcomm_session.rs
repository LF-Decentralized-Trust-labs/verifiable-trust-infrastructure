use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use tracing::{debug, info, warn};

use crate::protocols::PROBLEM_REPORT_TYPE;

/// Client-side DIDComm session for request-response messaging via ATM.
///
/// Uses WebSocket streaming to receive responses from the mediator.
/// Designed for CLI tools that send a request and wait for a reply.
pub struct DIDCommSession {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    pub(crate) client_did: String,
    pub(crate) vta_did: String,
}

impl DIDCommSession {
    /// Connect to a VTA via DIDComm through a mediator.
    ///
    /// Sets up the ATM and profile for REST-based messaging. Does NOT open a
    /// WebSocket — all communication goes through the mediator's REST API,
    /// avoiding connection storms when the CLI is invoked repeatedly.
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

        // Build ATM (no inbound channel needed — we use REST polling)
        let atm_config = ATMConfig::builder().build()?;
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

        let atm = Arc::new(atm);

        // Flush stale messages from the inbox (accumulated between CLI runs)
        {
            use affinidi_tdk::messaging::messages::Folder;
            match atm.list_messages(&profile, Folder::Inbox).await {
                Ok(messages) if !messages.is_empty() => {
                    let ids: Vec<String> = messages.iter().map(|m| m.msg_id.clone()).collect();
                    info!(
                        count = ids.len(),
                        "flushing stale queued messages from inbox"
                    );
                    let delete_req = affinidi_tdk::messaging::messages::DeleteMessageRequest {
                        message_ids: ids,
                    };
                    match atm.delete_messages_direct(&profile, &delete_req).await {
                        Ok(resp) => {
                            debug!(
                                deleted = resp.success.len(),
                                errors = resp.errors.len(),
                                "inbox flushed"
                            );
                        }
                        Err(e) => warn!("failed to flush stale messages (non-fatal): {e}"),
                    }
                }
                Ok(_) => {} // Empty inbox
                Err(e) => warn!("could not list inbox (non-fatal): {e}"),
            }
        }

        // Enable WebSocket for streaming message delivery from mediator.
        // Without this, the ATM can only poll via REST and may miss responses
        // that arrive after the initial send_message call returns.
        atm.profile_enable_websocket(&profile).await?;

        debug!("DIDComm session connected via mediator {mediator_did} (WebSocket mode)");

        Ok(Self {
            atm,
            profile,
            client_did: client_did.to_string(),
            vta_did: vta_did.to_string(),
        })
    }

    /// Send a DIDComm message and wait for a matching response.
    ///
    /// Packs the message, sends it to the mediator, then uses the WebSocket
    /// live stream to wait for the response. This handles asynchronous
    /// processing where the VTA takes time to respond.
    pub async fn send_and_wait<T: serde::de::DeserializeOwned>(
        &self,
        msg_type: &str,
        body: serde_json::Value,
        expected_result_type: &str,
        timeout_secs: u64,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let msg_id = uuid::Uuid::new_v4().to_string();
        let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
            .from(self.client_did.clone())
            .to(self.vta_did.clone())
            .finalize();

        // Pack encrypted (signed + encrypted to recipient)
        let (packed, _) = self
            .atm
            .pack_encrypted(
                &msg,
                &self.vta_did,
                Some(&self.client_did),
                Some(&self.client_did),
            )
            .await
            .map_err(|e| format!("failed to pack message: {e}"))?;

        debug!(msg_type, msg_id, "sending via DIDComm");

        // Send the message (fire-and-forget to mediator, don't wait for response)
        self.atm
            .send_message(&self.profile, &packed, &msg_id, false, false)
            .await
            .map_err(|e| format!("failed to send message: {e}"))?;

        // Wait for the response via WebSocket live stream
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let wait_duration = std::time::Duration::from_secs(5);
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("timeout waiting for DIDComm response".into());
            }
            let wait = wait_duration.min(remaining);

            let next = self
                .atm
                .message_pickup()
                .live_stream_next(&self.profile, Some(wait), true)
                .await
                .map_err(|e| format!("message pickup error: {e}"))?;

            let (response_msg, _meta) = match next {
                Some(pair) => pair,
                None => continue, // No message yet, keep waiting
            };

            // Check if this is the response we're waiting for (matching thread ID)
            let response_thid = response_msg.thid.as_deref().unwrap_or("");
            if response_thid != msg_id {
                debug!(
                    response_thid,
                    expected = msg_id,
                    response_type = %response_msg.typ,
                    "received message with non-matching thread ID — skipping"
                );
                continue;
            }

            debug!(response_type = %response_msg.typ, "received DIDComm response");

            // Check for problem report
            if response_msg.typ == PROBLEM_REPORT_TYPE
                || response_msg.typ.contains("problem-report")
            {
                let code = response_msg
                    .body
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let comment = response_msg
                    .body
                    .get("comment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                return Err(format!("{code}: {comment}").into());
            }

            // Verify expected type
            if response_msg.typ != expected_result_type {
                return Err(format!(
                    "unexpected response type: expected {expected_result_type}, got {}",
                    response_msg.typ
                )
                .into());
            }

            // Deserialize response body
            return serde_json::from_value(response_msg.body)
                .map_err(|e| format!("failed to deserialize DIDComm response: {e}").into());
        }
    }

    /// Gracefully shut down the DIDComm session.
    pub async fn shutdown(&self) {
        self.atm.graceful_shutdown().await;
    }
}
