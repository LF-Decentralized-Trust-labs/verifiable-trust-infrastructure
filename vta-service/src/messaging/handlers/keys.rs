use affinidi_tdk::didcomm::Message;

use base64::Engine;

use vta_sdk::protocols::key_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::DIDCommCtx;
use crate::operations;

use super::{HandlerResult, didcomm_handler};

didcomm_handler!(handle_create_key,
    body: vta_sdk::protocols::key_management::create::CreateKeyBody,
    auth: admin,
    result: key_management::CREATE_KEY_RESULT,
    |state, auth, body| operations::keys::create_key(
        &state.keys_ks,
        &state.contexts_ks,
        &state.seed_store,
        &auth,
        operations::keys::CreateKeyParams {
            key_type: body.key_type,
            derivation_path: if body.derivation_path.is_empty() {
                None
            } else {
                Some(body.derivation_path)
            },
            key_id: None,
            mnemonic: body.mnemonic,
            label: body.label,
            context_id: body.context_id,
        },
        "didcomm",
    )
);

didcomm_handler!(handle_get_key,
    body: vta_sdk::protocols::key_management::get::GetKeyBody,
    result: key_management::GET_KEY_RESULT,
    |state, auth, body| operations::keys::get_key(
        &state.keys_ks, &auth, &body.key_id, "didcomm",
    )
);

didcomm_handler!(handle_list_keys,
    body: vta_sdk::protocols::key_management::list::ListKeysBody,
    result: key_management::LIST_KEYS_RESULT,
    |state, auth, body| operations::keys::list_keys(
        &state.keys_ks,
        &auth,
        operations::keys::ListKeysParams {
            offset: body.offset,
            limit: body.limit,
            status: body.status,
            context_id: body.context_id,
        },
        "didcomm",
    )
);

didcomm_handler!(handle_rename_key,
    body: vta_sdk::protocols::key_management::rename::RenameKeyBody,
    auth: admin,
    result: key_management::RENAME_KEY_RESULT,
    |state, auth, body| operations::keys::rename_key(
        &state.keys_ks, &auth, &body.key_id, &body.new_key_id, "didcomm",
    )
);

didcomm_handler!(handle_revoke_key,
    body: vta_sdk::protocols::key_management::revoke::RevokeKeyBody,
    auth: admin,
    result: key_management::REVOKE_KEY_RESULT,
    |state, auth, body| operations::keys::revoke_key(
        &state.keys_ks, &auth, &body.key_id, "didcomm",
    )
);

didcomm_handler!(handle_get_key_secret,
    body: vta_sdk::protocols::key_management::secret::GetKeySecretBody,
    auth: admin,
    result: key_management::GET_KEY_SECRET_RESULT,
    |state, auth, body| operations::keys::get_key_secret(
        &state.keys_ks, &state.seed_store, &auth, &body.key_id, "didcomm",
    )
);

/// DIDComm handler for sign-request. Written manually (not via macro)
/// because the base64url payload decode must outlive the sign future.
pub async fn handle_sign_request(
    state: &DidcommState,
    ctx: &DIDCommCtx<'_>,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;
    let body: vta_sdk::protocols::key_management::sign::SignRequestBody =
        serde_json::from_value(msg.body.clone())?;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&body.payload)
        .map_err(|e| {
            crate::error::AppError::Validation(format!("invalid base64url payload: {e}"))
        })?;

    let result = operations::keys::sign_payload(
        &state.keys_ks,
        &state.seed_store,
        &auth,
        &body.key_id,
        &payload,
        &body.algorithm,
        "didcomm",
    )
    .await?;

    ctx.send_response(&auth.did, key_management::SIGN_RESULT, Some(&msg.id), &result)
        .await
}
