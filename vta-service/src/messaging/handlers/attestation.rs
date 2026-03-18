use affinidi_tdk::didcomm::Message;
use vta_sdk::protocols::attestation_management;

use crate::messaging::DidcommState;
use crate::messaging::response::DIDCommCtx;
use crate::operations;
use crate::tee::types::AttestationRequest;

use super::HandlerResult;

/// Handle GET_TEE_STATUS — returns TEE detection status.
/// Unauthenticated: attestation is used to establish trust before auth.
pub async fn handle_tee_status(
    state: &DidcommState,
    ctx: &DIDCommCtx<'_>,
    msg: &Message,
) -> HandlerResult {
    let sender = msg
        .from
        .as_deref()
        .ok_or("message has no sender")?
        .split('#')
        .next()
        .unwrap_or("");

    let tee_state = state
        .tee_state
        .as_ref()
        .ok_or("TEE attestation is not enabled on this VTA")?;

    let status = operations::attestation::get_tee_status(tee_state);

    ctx.send_response(
        sender,
        attestation_management::GET_TEE_STATUS_RESULT,
        Some(&msg.id),
        &status,
    )
    .await
}

/// Handle REQUEST_ATTESTATION — generates a fresh attestation report with client nonce.
/// Unauthenticated: attestation is used to establish trust before auth.
pub async fn handle_request_attestation(
    state: &DidcommState,
    ctx: &DIDCommCtx<'_>,
    msg: &Message,
) -> HandlerResult {
    let sender = msg
        .from
        .as_deref()
        .ok_or("message has no sender")?
        .split('#')
        .next()
        .unwrap_or("");

    let tee_state = state
        .tee_state
        .as_ref()
        .ok_or("TEE attestation is not enabled on this VTA")?;

    let body: AttestationRequest = serde_json::from_value(msg.body.clone())?;

    let response =
        operations::attestation::generate_attestation_report(tee_state, &state.config, &body.nonce)
            .await?;

    ctx.send_response(
        sender,
        attestation_management::ATTESTATION_RESULT,
        Some(&msg.id),
        &response,
    )
    .await
}
