use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::webvh_client::RequestUriResponse;

// WebVH DIDComm protocol message types
const MSG_DID_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/request";
const MSG_DID_OFFER: &str = "https://affinidi.com/webvh/1.0/did/offer";
const MSG_DID_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/publish";
const MSG_DID_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/confirm";
const MSG_DELETE: &str = "https://affinidi.com/webvh/1.0/did/delete";
const MSG_DELETE_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/delete-confirm";
const MSG_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/did/problem-report";

/// DIDComm-based client for communicating with a WebVH server.
///
/// Routes messages through the main ATM connection via [`DIDCommBridge`],
/// avoiding duplicate WebSocket connections to the mediator.
pub struct WebvhDIDCommClient<'a> {
    bridge: &'a DIDCommBridge,
    vta_did: &'a str,
    server_did: &'a str,
}

impl<'a> WebvhDIDCommClient<'a> {
    pub fn new(bridge: &'a DIDCommBridge, vta_did: &'a str, server_did: &'a str) -> Self {
        Self {
            bridge,
            vta_did,
            server_did,
        }
    }

    /// Request a URI allocation from the WebVH server.
    pub async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse, AppError> {
        let body = match path {
            Some(p) => serde_json::json!({ "path": p }),
            None => serde_json::json!({}),
        };

        let response = self
            .bridge
            .send_and_wait(
                self.vta_did,
                self.server_did,
                MSG_DID_REQUEST,
                body,
                MSG_DID_OFFER,
                MSG_PROBLEM_REPORT,
                30,
            )
            .await?;

        serde_json::from_value(response.body)
            .map_err(|e| AppError::Internal(format!("failed to parse did/offer response: {e}")))
    }

    /// Publish a DID log to the WebVH server.
    pub async fn publish_did(&self, mnemonic: &str, log_content: &str) -> Result<(), AppError> {
        let body = serde_json::json!({
            "mnemonic": mnemonic,
            "did_log": log_content,
        });

        self.bridge
            .send_and_wait(
                self.vta_did,
                self.server_did,
                MSG_DID_PUBLISH,
                body,
                MSG_DID_CONFIRM,
                MSG_PROBLEM_REPORT,
                30,
            )
            .await?;
        Ok(())
    }

    /// Delete a DID from the WebVH server.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<(), AppError> {
        let body = serde_json::json!({ "mnemonic": mnemonic });

        self.bridge
            .send_and_wait(
                self.vta_did,
                self.server_did,
                MSG_DELETE,
                body,
                MSG_DELETE_CONFIRM,
                MSG_PROBLEM_REPORT,
                30,
            )
            .await?;
        Ok(())
    }
}
