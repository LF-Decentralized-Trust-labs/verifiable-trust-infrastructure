//! DIDComm protocol types for TEE attestation management.

/// Request TEE detection status.
pub const GET_TEE_STATUS: &str =
    "https://firstperson.network/vta/1.0/attestation/status";
/// Response with TEE detection status.
pub const GET_TEE_STATUS_RESULT: &str =
    "https://firstperson.network/vta/1.0/attestation/status-result";

/// Request a fresh attestation report (body includes nonce).
pub const REQUEST_ATTESTATION: &str =
    "https://firstperson.network/vta/1.0/attestation/request";
/// Response with attestation report.
pub const ATTESTATION_RESULT: &str =
    "https://firstperson.network/vta/1.0/attestation/result";
