//! Sealed bundle types — the producer-side artifact returned to the consumer.

use serde::{Deserialize, Serialize};

use crate::context_provision::ContextProvisionBundle;
use crate::credentials::CredentialBundle;
use crate::did_secrets::DidSecretsBundle;

/// A labeled key entry, used by the `AdminKeySet` payload variant for
/// multi-admin / future expansion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledKey {
    pub label: String,
    /// Key bytes, base64url-no-pad.
    pub key_b64: String,
    /// Optional key type tag for downstream interpretation (e.g. "ed25519").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
}

/// Tagged, extensible payload sealed inside a [`SealedBundle`].
///
/// Every sensitive bundle type in the workspace is a variant here — after the
/// final phase of the rollout, sealed-transfer is the only way these move.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedPayloadV1 {
    AdminCredential(CredentialBundle),
    ContextProvision(ContextProvisionBundle),
    DidSecrets(DidSecretsBundle),
    AdminKeySet(Vec<LabeledKey>),
    /// A single raw private key bound to its algorithm tag. Used by the
    /// `POST /keys/import` flow: the client seals the key material to the
    /// server's ephemeral wrapping pubkey via sealed-transfer; the server
    /// opens it and imports.
    RawPrivateKey(RawPrivateKey),
}

/// A single raw private key transferred inside a sealed bundle. The
/// `key_type` tag travels with the bytes so the server can reject a mismatch
/// between the outer request's declared key type and what was actually
/// sealed — a defence against a compromised client mis-declaring its key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPrivateKey {
    /// One of: `ed25519`, `x25519`, `p256`.
    pub key_type: String,
    /// Raw private key bytes, base64url-no-pad.
    pub key_bytes_b64: String,
}

/// A digital signature over the producer's pubkey + the bundle digest, by a
/// known DID. Used in Modes A and C when the consumer knows the VTA's DID up
/// front.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidSignedAssertion {
    pub did: String,
    /// Detached signature bytes (interpretation depends on the DID's key type),
    /// base64url-no-pad.
    pub signature_b64: String,
    /// Verification method id used (e.g. `did:webvh:.../keys#key-0`).
    pub verification_method: String,
}

/// An attestation quote (e.g. AWS Nitro CBOR document) committing to the
/// producer's pubkey + nonce + VTA pubkey. Used in Mode B (TEE first-boot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationQuoteAssertion {
    /// Vendor / format tag, e.g. "aws-nitro-v1".
    pub format: String,
    /// Raw attestation document, base64url-no-pad.
    pub quote_b64: String,
}

/// How the consumer establishes that the producer pubkey it pinned is the right
/// one for this bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AssertionProof {
    /// DID-signed assertion. The consumer resolves the DID and verifies.
    DidSigned(DidSignedAssertion),
    /// Attestation quote. The consumer verifies the quote against vendor roots
    /// and matches `user_data`.
    Attested(AttestationQuoteAssertion),
    /// No further proof — the consumer is relying on the pinned pubkey alone.
    /// Out-of-band digest verification is the only integrity anchor.
    PinnedOnly,
}

/// The producer's claim that it owns the pubkey embedded in chunk 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducerAssertion {
    /// X25519 producer public key (32 bytes), base64url-no-pad.
    /// Pinned by the consumer out-of-band.
    pub producer_pubkey_b64: String,
    pub proof: AssertionProof,
}

/// Top-level sealed bundle. Carries one or more armored chunks plus the
/// metadata needed to verify and reassemble them.
///
/// In the wire format (armor), each chunk is a separate `BEGIN/END` block
/// sharing a `Bundle-Id`. This struct is the in-memory representation produced
/// by the armor parser.
#[derive(Debug, Clone)]
pub struct SealedBundle {
    pub bundle_id: [u8; 16],
    pub digest_algo: String,
    pub chunks: Vec<ArmoredChunk>,
}

/// One armored chunk of a sealed bundle.
#[derive(Debug, Clone)]
pub struct ArmoredChunk {
    pub chunk_index: u16,
    pub total_chunks: u16,
    /// HPKE-sealed payload (the `HpkeSealed` wire struct, CBOR-encoded).
    pub sealed_bytes: Vec<u8>,
}
