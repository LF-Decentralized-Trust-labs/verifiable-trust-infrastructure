use affinidi_tdk::didcomm::Message;

use vta_sdk::protocols::credential_management;

use crate::acl::Role;
use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::DIDCommCtx;
use crate::operations;

use super::HandlerResult;

pub async fn handle_generate_credentials(
    state: &DidcommState,
    ctx: &DIDCommCtx<'_>,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::credential_management::generate::GenerateCredentialsBody =
        serde_json::from_value(msg.body.clone())?;

    let role = Role::from_str(&body.role)?;

    let result = operations::credentials::generate_credentials(
        &state.acl_ks,
        &state.config,
        &auth,
        role,
        body.label,
        body.allowed_contexts,
        "didcomm",
    )
    .await?;

    ctx.send_response(
        &auth.did,
        credential_management::GENERATE_CREDENTIALS_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}
