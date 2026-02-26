use std::collections::HashMap;
use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use vta_sdk::didcomm_transport::{PendingMap, send_and_wait_raw};

use crate::error::AppError;

/// Bridge between REST/DIDComm handlers and the main ATM connection.
///
/// Provides request-response DIDComm messaging by registering oneshot channels
/// keyed by message ID. The main DIDComm loop checks incoming messages against
/// pending requests and routes matches directly to the waiting handler.
pub struct DIDCommBridge {
    pub atm: Arc<ATM>,
    pub profile: Arc<ATMProfile>,
    pending: PendingMap,
}

impl DIDCommBridge {
    pub fn new(atm: Arc<ATM>, profile: Arc<ATMProfile>) -> Self {
        Self {
            atm,
            profile,
            pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Try to complete a pending request. Returns true if the message was routed.
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
        send_and_wait_raw(
            &self.atm,
            &self.profile,
            &self.pending,
            vta_did,
            server_did,
            msg_type,
            body,
            expected_type,
            problem_report_type,
            timeout_secs,
        )
        .await
        .map_err(AppError::BadGateway)
    }
}
