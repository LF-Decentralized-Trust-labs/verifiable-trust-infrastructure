use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

use crate::did_secrets::SecretEntry;

/// A self-contained bundle for provisioning an application context.
///
/// Contains everything an independent application needs to connect to the VTA,
/// authenticate, and self-administer its context. Optionally includes DID
/// material (document, log entry, keys) when a DID was created during
/// provisioning.
///
/// Encodes as JSON, then base64url-no-pad for safe transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextProvisionBundle {
    /// Context identifier.
    pub context_id: String,
    /// Human-readable context name.
    pub context_name: String,
    /// VTA service public URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,
    /// VTA service DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    /// Base64url-encoded admin credential bundle (existing `CredentialBundle` format).
    pub credential: String,
    /// DID of the admin identity created for this context.
    pub admin_did: String,
    /// DID material, present when a DID was created during provisioning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<ProvisionedDid>,
}

/// DID material included when a DID is created during context provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionedDid {
    /// The DID identifier (e.g. `did:webvh:...`).
    pub id: String,
    /// DID document (JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    /// Serialized DID log entry for `did.jsonl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_entry: Option<String>,
    /// Private keys associated with the DID.
    pub secrets: Vec<SecretEntry>,
}

impl ContextProvisionBundle {
    /// Decode a base64url-no-pad encoded provision bundle.
    ///
    /// **Deprecated.** Transport via [`crate::sealed_transfer`]
    /// (`SealedPayloadV1::ContextProvision`) — the plaintext envelope has no
    /// integrity or confidentiality.
    #[deprecated(
        since = "0.4.2",
        note = "use vta_sdk::sealed_transfer (SealedPayloadV1::ContextProvision)"
    )]
    pub fn decode(encoded: &str) -> Result<Self, ContextProvisionBundleError> {
        let json_bytes = BASE64
            .decode(encoded)
            .map_err(|e| ContextProvisionBundleError::Base64(e.to_string()))?;
        serde_json::from_slice(&json_bytes)
            .map_err(|e| ContextProvisionBundleError::Json(e.to_string()))
    }

    /// Encode this bundle as a base64url-no-pad string.
    ///
    /// **Deprecated.** See [`Self::decode`].
    #[deprecated(
        since = "0.4.2",
        note = "use vta_sdk::sealed_transfer (SealedPayloadV1::ContextProvision)"
    )]
    pub fn encode(&self) -> Result<String, ContextProvisionBundleError> {
        let json = serde_json::to_vec(self)
            .map_err(|e| ContextProvisionBundleError::Json(e.to_string()))?;
        Ok(BASE64.encode(&json))
    }
}

/// Errors when decoding or encoding a [`ContextProvisionBundle`].
#[derive(Debug)]
pub enum ContextProvisionBundleError {
    Base64(String),
    Json(String),
}

impl std::fmt::Display for ContextProvisionBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64(e) => write!(f, "base64 decode error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
        }
    }
}

impl std::error::Error for ContextProvisionBundleError {}

#[cfg(test)]
#[allow(deprecated)] // tests exercise the legacy encode/decode path intentionally
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip_without_did() {
        let bundle = ContextProvisionBundle {
            context_id: "my-app".to_string(),
            context_name: "My Application".to_string(),
            vta_url: Some("https://vta.example.com".to_string()),
            vta_did: Some("did:webvh:abc:example.com".to_string()),
            credential: "eyJ0ZXN0IjogdHJ1ZX0".to_string(),
            admin_did: "did:key:z6Mk123".to_string(),
            did: None,
        };
        let encoded = bundle.encode().unwrap();
        let decoded = ContextProvisionBundle::decode(&encoded).unwrap();
        assert_eq!(decoded.context_id, "my-app");
        assert_eq!(decoded.context_name, "My Application");
        assert_eq!(decoded.admin_did, "did:key:z6Mk123");
        assert!(decoded.did.is_none());
    }

    #[test]
    fn test_encode_decode_roundtrip_with_did() {
        let bundle = ContextProvisionBundle {
            context_id: "my-app".to_string(),
            context_name: "My Application".to_string(),
            vta_url: None,
            vta_did: None,
            credential: "eyJ0ZXN0IjogdHJ1ZX0".to_string(),
            admin_did: "did:key:z6Mk123".to_string(),
            did: Some(ProvisionedDid {
                id: "did:webvh:abc:example.com".to_string(),
                did_document: Some(serde_json::json!({"id": "did:webvh:abc:example.com"})),
                log_entry: Some("{\"log\": \"entry\"}".to_string()),
                secrets: vec![SecretEntry {
                    key_id: "did:webvh:abc:example.com#key-0".to_string(),
                    key_type: crate::keys::KeyType::Ed25519,
                    private_key_multibase: "z6Mk...signing".to_string(),
                }],
            }),
        };
        let encoded = bundle.encode().unwrap();
        let decoded = ContextProvisionBundle::decode(&encoded).unwrap();
        assert_eq!(decoded.context_id, "my-app");
        let did = decoded.did.unwrap();
        assert_eq!(did.id, "did:webvh:abc:example.com");
        assert!(did.did_document.is_some());
        assert!(did.log_entry.is_some());
        assert_eq!(did.secrets.len(), 1);
    }

    #[test]
    fn test_decode_invalid_base64() {
        let result = ContextProvisionBundle::decode("!!!not-base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64"));
    }
}
