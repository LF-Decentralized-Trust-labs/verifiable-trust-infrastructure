use crate::error::AppError;

use super::types::{AttestationReport, TeeStatus, TeeType};

/// Trait for TEE attestation providers.
///
/// Each supported TEE platform (AMD SEV-SNP, AWS Nitro, simulated)
/// implements this trait to provide detection, attestation, and
/// verification capabilities.
pub trait TeeProvider: Send + Sync {
    /// Return the TEE platform type.
    fn tee_type(&self) -> TeeType;

    /// Detect whether this TEE is available at runtime.
    fn detect(&self) -> Result<TeeStatus, AppError>;

    /// Generate an attestation report binding the given user_data and nonce.
    ///
    /// The `user_data` is typically the VTA DID (UTF-8 encoded).
    /// The `nonce` is a client-provided value for replay prevention.
    fn attest(
        &self,
        user_data: &[u8],
        nonce: &[u8],
    ) -> Result<AttestationReport, AppError>;

    /// Verify an attestation report (self-check).
    ///
    /// Performs structural validation only. Remote parties must verify
    /// against the platform vendor's root of trust (AMD ARK/ASK chain
    /// for SEV-SNP, AWS Nitro root certificate for Nitro).
    fn verify(&self, report: &AttestationReport) -> Result<bool, AppError>;
}
