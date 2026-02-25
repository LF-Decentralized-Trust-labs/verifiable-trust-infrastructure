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

/// Core send-and-wait logic shared by DIDCommSession (SDK) and DIDCommBridge (service).
///
/// Builds a message, registers a pending oneshot, packs/sends via ATM, and waits
/// for a response matching the thread ID. Returns `Err(String)` on failure —
/// callers map the error into their own type.
pub async fn send_and_wait_raw(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    pending: &PendingMap,
    from_did: &str,
    to_did: &str,
    msg_type: &str,
    body: serde_json::Value,
    expected_type: &str,
    problem_report_type: &str,
    timeout_secs: u64,
) -> Result<Message, String> {
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
        .pack_encrypted(&msg, to_did, Some(from_did), Some(from_did), None)
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
    if response.type_ == problem_report_type || response.type_ == PROBLEM_REPORT_TYPE {
        let (code, comment) = extract_problem_report(&response.body);
        return Err(format!("{code}: {comment}"));
    }

    // Verify expected type
    if response.type_ != expected_type {
        return Err(format!(
            "unexpected response type: expected {expected_type}, got {}",
            response.type_
        ));
    }

    debug!(response_type = %response.type_, "received DIDComm response");
    Ok(response)
}
