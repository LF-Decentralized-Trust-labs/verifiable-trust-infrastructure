use affinidi_tdk::didcomm::Message;

use vta_sdk::protocols::seed_management;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::DIDCommCtx;
use crate::operations;

use super::{HandlerResult, didcomm_handler};

didcomm_handler!(handle_list_seeds,
    auth: admin,
    result: seed_management::LIST_SEEDS_RESULT,
    |state, auth| operations::seeds::list_seeds(&state.keys_ks, "didcomm")
);

didcomm_handler!(handle_rotate_seed,
    body: vta_sdk::protocols::seed_management::rotate::RotateSeedBody,
    auth: admin,
    result: seed_management::ROTATE_SEED_RESULT,
    |state, auth, body| operations::seeds::rotate_seed(
        &state.keys_ks,
        &state.seed_store,
        body.mnemonic.as_deref(),
        "didcomm",
    )
);
