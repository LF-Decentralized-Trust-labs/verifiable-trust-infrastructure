use affinidi_tdk::didcomm::Message;

use vta_sdk::protocols::acl_management;

use crate::acl::Role;
use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::DIDCommCtx;
use crate::operations;

use super::{HandlerResult, didcomm_handler};

// create_acl and update_acl have custom Role::from_str logic, kept as manual handlers.

pub async fn handle_create_acl(
    state: &DidcommState,
    ctx: &DIDCommCtx<'_>,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::acl_management::create::CreateAclBody =
        serde_json::from_value(msg.body.clone())?;

    let role = Role::from_str(&body.role)?;

    let result = operations::acl::create_acl(
        &state.acl_ks,
        &auth,
        &body.did,
        role,
        body.label,
        body.allowed_contexts,
        "didcomm",
    )
    .await?;

    ctx.send_response(
        &auth.did,
        acl_management::CREATE_ACL_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

didcomm_handler!(handle_get_acl,
    body: vta_sdk::protocols::acl_management::get::GetAclBody,
    result: acl_management::GET_ACL_RESULT,
    |state, auth, body| operations::acl::get_acl(
        &state.acl_ks, &auth, &body.did, "didcomm",
    )
);

didcomm_handler!(handle_list_acl,
    body: vta_sdk::protocols::acl_management::list::ListAclBody,
    result: acl_management::LIST_ACL_RESULT,
    |state, auth, body| operations::acl::list_acl(
        &state.acl_ks, &auth, body.context.as_deref(), "didcomm",
    )
);

pub async fn handle_update_acl(
    state: &DidcommState,
    ctx: &DIDCommCtx<'_>,
    msg: &Message,
) -> HandlerResult {
    let auth = auth_from_message(msg, &state.acl_ks).await?;

    let body: vta_sdk::protocols::acl_management::update::UpdateAclBody =
        serde_json::from_value(msg.body.clone())?;

    let role = match body.role {
        Some(r) => Some(Role::from_str(&r)?),
        None => None,
    };

    let result = operations::acl::update_acl(
        &state.acl_ks,
        &auth,
        &body.did,
        operations::acl::UpdateAclParams {
            role,
            label: body.label,
            allowed_contexts: body.allowed_contexts,
        },
        "didcomm",
    )
    .await?;

    ctx.send_response(
        &auth.did,
        acl_management::UPDATE_ACL_RESULT,
        Some(&msg.id),
        &result,
    )
    .await
}

didcomm_handler!(handle_delete_acl,
    body: vta_sdk::protocols::acl_management::delete::DeleteAclBody,
    result: acl_management::DELETE_ACL_RESULT,
    |state, auth, body| operations::acl::delete_acl(
        &state.acl_ks, &auth, &body.did, "didcomm",
    )
);
