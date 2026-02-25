use affinidi_tdk::didcomm::Message;

use vta_sdk::protocols::vta_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::DIDCommCtx;
use crate::operations;

use super::{HandlerResult, didcomm_handler};

didcomm_handler!(handle_get_config,
    result: vta_management::GET_CONFIG_RESULT,
    |state, auth| operations::config::get_config(&state.config, &auth, "didcomm")
);

didcomm_handler!(handle_update_config,
    body: vta_sdk::protocols::vta_management::update_config::UpdateConfigBody,
    result: vta_management::UPDATE_CONFIG_RESULT,
    |state, auth, body| operations::config::update_config(
        &state.config,
        &auth,
        operations::config::UpdateConfigParams {
            vta_did: body.vta_did,
            vta_name: body.vta_name,
            public_url: body.public_url,
        },
        "didcomm",
    )
);
