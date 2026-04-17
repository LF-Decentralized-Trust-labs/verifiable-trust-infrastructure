//! Bootstrap request: the consumer-side artifact that initiates a sealed transfer.
//!
//! Carries no secrets — only the consumer's ephemeral X25519 public key, a fresh
//! nonce, and an optional human-readable label so the producer knows which
//! request they're sealing for.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

use super::error::SealedTransferError;

/// A request from a consumer to receive a sealed bundle.
///
/// JSON-serialized for offline transport. Contains no secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRequest {
    /// Wire-format version. Currently 1.
    pub version: u8,

    /// Consumer's ephemeral X25519 public key (32 bytes), base64url-no-pad.
    pub client_pubkey: String,

    /// Random 16-byte nonce, base64url-no-pad. Becomes the bundle_id under HPKE.
    pub nonce: String,

    /// Optional human-readable label (operator-visible only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl BootstrapRequest {
    /// Build a new request from raw pubkey + nonce bytes.
    pub fn new(client_pubkey: [u8; 32], nonce: [u8; 16], label: Option<String>) -> Self {
        Self {
            version: 1,
            client_pubkey: BASE64.encode(client_pubkey),
            nonce: BASE64.encode(nonce),
            label,
        }
    }

    /// Decode the embedded client pubkey.
    pub fn decode_client_pubkey(&self) -> Result<[u8; 32], SealedTransferError> {
        let raw = BASE64
            .decode(&self.client_pubkey)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?;
        raw.try_into()
            .map_err(|_| SealedTransferError::Wire("client_pubkey must be 32 bytes".into()))
    }

    /// Decode the embedded nonce.
    pub fn decode_nonce(&self) -> Result<[u8; 16], SealedTransferError> {
        let raw = BASE64
            .decode(&self.nonce)
            .map_err(|e| SealedTransferError::Base64(e.to_string()))?;
        raw.try_into()
            .map_err(|_| SealedTransferError::Wire("nonce must be 16 bytes".into()))
    }
}
