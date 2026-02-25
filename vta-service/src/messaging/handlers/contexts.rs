use affinidi_tdk::didcomm::Message;

use vta_sdk::protocols::context_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::DIDCommCtx;
use crate::operations;

use super::{HandlerResult, didcomm_handler};

didcomm_handler!(handle_create_context,
    body: vta_sdk::protocols::context_management::create::CreateContextBody,
    result: context_management::CREATE_CONTEXT_RESULT,
    |state, auth, body| operations::contexts::create_context(
        &state.contexts_ks, &auth, &body.id, body.name, body.description, "didcomm",
    )
);

didcomm_handler!(handle_get_context,
    body: vta_sdk::protocols::context_management::get::GetContextBody,
    result: context_management::GET_CONTEXT_RESULT,
    |state, auth, body| operations::contexts::get_context_op(
        &state.contexts_ks, &auth, &body.id, "didcomm",
    )
);

didcomm_handler!(handle_list_contexts,
    result: context_management::LIST_CONTEXTS_RESULT,
    |state, auth| operations::contexts::list_contexts(
        &state.contexts_ks, &auth, "didcomm",
    )
);

didcomm_handler!(handle_update_context,
    body: vta_sdk::protocols::context_management::update::UpdateContextBody,
    result: context_management::UPDATE_CONTEXT_RESULT,
    |state, auth, body| operations::contexts::update_context(
        &state.contexts_ks,
        &auth,
        &body.id,
        operations::contexts::UpdateContextParams {
            name: body.name,
            did: body.did,
            description: body.description,
        },
        "didcomm",
    )
);

didcomm_handler!(handle_delete_context,
    body: vta_sdk::protocols::context_management::delete::DeleteContextBody,
    result: context_management::DELETE_CONTEXT_RESULT,
    |state, auth, body| operations::contexts::delete_context(
        &state.contexts_ks, &auth, &body.id, "didcomm",
    )
);
