use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use tokio::sync::oneshot;
use tracing::debug;

use crate::protocols::{PROBLEM_REPORT_TYPE, extract_problem_report};

/// Map of pending request IDs to oneshot senders for response routing.
pub type PendingMap = Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<Message>>>>;

/// Parameters for sending a DIDComm message and waiting for a response.
pub struct DIDCommSendParams<'a> {
    pub atm: &'a ATM,
    pub profile: &'a Arc<ATMProfile>,
    pub pending: &'a PendingMap,
    pub from_did: &'a str,
    pub to_did: &'a str,
    pub msg_type: &'a str,
    pub body: serde_json::Value,
    pub expected_type: &'a str,
    pub problem_report_type: &'a str,
    pub timeout_secs: u64,
}

/// Core send-and-wait logic shared by DIDCommSession (SDK) and DIDCommBridge (service).
///
/// Builds a message, registers a pending oneshot, packs/sends via ATM, and waits
/// for a response matching the thread ID. Returns `Err(String)` on failure —
/// callers map the error into their own type.
pub async fn send_and_wait_raw(params: DIDCommSendParams<'_>) -> Result<Message, String> {
    let DIDCommSendParams {
        atm,
        profile,
        pending,
        from_did,
        to_did,
        msg_type,
        body,
        expected_type,
        problem_report_type,
        timeout_secs,
    } = params;
    let msg_id = uuid::Uuid::new_v4().to_string();
    let msg = Message::build(msg_id.clone(), msg_type.to_string(), body)
        .from(from_did.to_string())
        .to(to_did.to_string())
        .finalize();

    // Register pending before sending
    let (tx, rx) = oneshot::channel();
    pending.lock().unwrap().insert(msg_id.clone(), tx);

    // Pack encrypted
    let (packed, _) = atm
        .pack_encrypted(&msg, to_did, Some(from_did), Some(from_did))
        .await
        .map_err(|e| {
            pending.lock().unwrap().remove(&msg_id);
            format!("failed to pack message: {e}")
        })?;

    // Send via ATM
    atm.send_message(profile, &packed, &msg_id, false, false)
        .await
        .map_err(|e| {
            pending.lock().unwrap().remove(&msg_id);
            format!("failed to send message: {e}")
        })?;

    debug!(msg_type, msg_id, "sent via DIDComm");

    // Wait for response with timeout
    let response = tokio::time::timeout(Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| {
            pending.lock().unwrap().remove(&msg_id);
            "timeout waiting for DIDComm response".to_string()
        })?
        .map_err(|_| "pending request channel dropped".to_string())?;

    // Check for problem report
    if response.typ == problem_report_type || response.typ == PROBLEM_REPORT_TYPE {
        let (code, comment) = extract_problem_report(&response.body);
        return Err(format!("{code}: {comment}"));
    }

    // Verify expected type
    if response.typ != expected_type {
        return Err(format!(
            "unexpected response type: expected {expected_type}, got {}",
            response.typ
        ));
    }

    debug!(response_type = %response.typ, "received DIDComm response");
    Ok(response)
}
