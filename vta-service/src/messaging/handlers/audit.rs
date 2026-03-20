use affinidi_tdk::didcomm::Message;

use vta_sdk::protocols::audit_management;
use vta_sdk::protocols::audit_management::list::ListAuditLogsBody;
use vta_sdk::protocols::audit_management::retention::UpdateRetentionBody;

use crate::messaging::DidcommState;
use crate::messaging::auth::auth_from_message;
use crate::messaging::response::DIDCommCtx;
use crate::operations;

use super::{HandlerResult, didcomm_handler};

didcomm_handler!(handle_list_logs,
    body: ListAuditLogsBody,
    result: audit_management::LIST_LOGS_RESULT,
    |state, auth, body| operations::audit::list_audit_logs(
        &state.audit_ks, &auth, &body, "didcomm"
    )
);

didcomm_handler!(handle_get_retention,
    result: audit_management::GET_RETENTION_RESULT,
    |state, auth| operations::audit::get_retention(
        &state.config, &auth, "didcomm"
    )
);

didcomm_handler!(handle_update_retention,
    body: UpdateRetentionBody,
    auth: admin,
    result: audit_management::UPDATE_RETENTION_RESULT,
    |state, auth, body| operations::audit::update_retention(
        &state.config, &auth, body.retention_days, "didcomm"
    )
);
