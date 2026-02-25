pub mod acl_management;
pub mod auth;
pub mod context_management;
pub mod credential_management;
pub mod did_management;
pub mod key_management;
pub mod seed_management;
pub mod vta_management;

// Standard DIDComm protocol types used across VTA/VTC services
pub const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";
pub const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
pub const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";

/// Extract code and comment from a problem-report message body.
pub fn extract_problem_report(body: &serde_json::Value) -> (String, String) {
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let comment = body
        .get("comment")
        .and_then(|v| v.as_str())
        .unwrap_or("no details provided")
        .to_string();
    (code, comment)
}
