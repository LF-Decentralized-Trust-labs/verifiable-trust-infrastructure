use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use serde::Serialize;
use tracing::warn;
use uuid::Uuid;
use vta_sdk::protocols::PROBLEM_REPORT_TYPE;

use super::handlers::HandlerResult;

/// Bundles the ATM connection info needed to send DIDComm responses.
pub struct DIDCommCtx<'a> {
    pub atm: &'a ATM,
    pub profile: &'a Arc<ATMProfile>,
    pub vta_did: &'a str,
}

impl DIDCommCtx<'_> {
    /// Build a DIDComm response message, pack it, and send it via the mediator.
    pub async fn send_response<T: Serialize>(
        &self,
        recipient_did: &str,
        msg_type: &str,
        thid: Option<&str>,
        body: &T,
    ) -> HandlerResult {
        let body_value = serde_json::to_value(body)?;

        let mut msg = Message::build(Uuid::new_v4().to_string(), msg_type.to_string(), body_value)
            .from(self.vta_did.to_string())
            .to(recipient_did.to_string());

        if let Some(thid) = thid {
            msg = msg.thid(thid.to_string());
        }

        let msg = msg.finalize();

        let (packed, _) = self
            .atm
            .pack_encrypted(
                &msg,
                recipient_did,
                Some(self.vta_did),
                Some(self.vta_did),
                None,
            )
            .await?;

        self.atm
            .send_message(self.profile, &packed, &msg.id, false, false)
            .await?;

        Ok(())
    }

    /// Send a problem-report error response.
    pub async fn send_error(
        &self,
        recipient_did: &str,
        thid: Option<&str>,
        code: &str,
        comment: &str,
    ) -> HandlerResult {
        let body = serde_json::json!({
            "code": code,
            "comment": comment,
        });

        let mut msg = Message::build(
            Uuid::new_v4().to_string(),
            PROBLEM_REPORT_TYPE.to_string(),
            body,
        )
        .from(self.vta_did.to_string())
        .to(recipient_did.to_string());

        if let Some(thid) = thid {
            msg = msg.thid(thid.to_string());
        }

        let msg = msg.finalize();

        let (packed, _) = self
            .atm
            .pack_encrypted(
                &msg,
                recipient_did,
                Some(self.vta_did),
                Some(self.vta_did),
                None,
            )
            .await?;

        if let Err(e) = self
            .atm
            .send_message(self.profile, &packed, &msg.id, false, false)
            .await
        {
            warn!("failed to send problem-report: {e}");
        }

        Ok(())
    }
}
