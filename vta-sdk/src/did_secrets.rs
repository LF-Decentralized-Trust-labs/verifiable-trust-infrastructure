use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

use crate::keys::KeyType;

/// A portable bundle of DID secrets for import/export.
///
/// Encodes as JSON, then base64url-no-pad for safe transport.
///
/// # Example — decoding
///
/// ```
/// use vta_sdk::did_secrets::DidSecretsBundle;
///
/// let bundle = DidSecretsBundle::decode("eyJkaWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJzZWNyZXRzIjpbXX0")
///     .expect("valid bundle");
/// assert_eq!(bundle.did, "did:example:123");
/// ```
///
/// # Example — constructing secrets for DIDComm
///
/// Applications using `affinidi_tdk` can reconstruct `Secret` objects from the
/// entries in this bundle:
///
/// ```ignore
/// use affinidi_tdk::secrets_resolver::secrets::Secret;
///
/// let bundle = DidSecretsBundle::decode(&base64_string)?;
/// for entry in &bundle.secrets {
///     let seed_bytes: [u8; 32] = /* decode entry.private_key_multibase */;
///     match entry.key_type {
///         KeyType::Ed25519 => {
///             let secret = Secret::generate_ed25519(
///                 Some(&entry.key_id), Some(&seed_bytes),
///             );
///             resolver.insert(secret);
///         }
///         KeyType::X25519 => {
///             let secret = Secret::generate_ed25519(None, Some(&seed_bytes))
///                 .to_x25519()?;
///             // Set the key ID after conversion
///             secret.id = entry.key_id.clone();
///             resolver.insert(secret);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidSecretsBundle {
    /// The DID these secrets belong to.
    pub did: String,
    /// Secret entries (one per verification method).
    pub secrets: Vec<SecretEntry>,
}

/// A single secret entry within a [`DidSecretsBundle`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Verification method ID (e.g. `did:webvh:...#key-0`).
    pub key_id: String,
    /// Key type — determines how to reconstruct the secret.
    pub key_type: KeyType,
    /// Multibase-encoded (Base58BTC) private key seed bytes.
    ///
    /// For **Ed25519** keys, these are the 32-byte Ed25519 seed.
    /// For **X25519** keys, these are the 32-byte Ed25519 seed that was
    /// used to derive the X25519 key via scalar conversion.
    pub private_key_multibase: String,
}

impl DidSecretsBundle {
    /// Decode a base64url-no-pad encoded secrets bundle.
    pub fn decode(encoded: &str) -> Result<Self, DidSecretsBundleError> {
        let json_bytes = BASE64
            .decode(encoded)
            .map_err(|e| DidSecretsBundleError::Base64(e.to_string()))?;
        serde_json::from_slice(&json_bytes).map_err(|e| DidSecretsBundleError::Json(e.to_string()))
    }

    /// Encode this bundle as a base64url-no-pad string.
    pub fn encode(&self) -> Result<String, DidSecretsBundleError> {
        let json =
            serde_json::to_vec(self).map_err(|e| DidSecretsBundleError::Json(e.to_string()))?;
        Ok(BASE64.encode(&json))
    }
}

/// Errors when decoding or encoding a [`DidSecretsBundle`].
#[derive(Debug)]
pub enum DidSecretsBundleError {
    Base64(String),
    Json(String),
}

impl std::fmt::Display for DidSecretsBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64(e) => write!(f, "base64 decode error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
        }
    }
}

impl std::error::Error for DidSecretsBundleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let bundle = DidSecretsBundle {
            did: "did:webvh:abc123:example.com".to_string(),
            secrets: vec![
                SecretEntry {
                    key_id: "did:webvh:abc123:example.com#key-0".to_string(),
                    key_type: KeyType::Ed25519,
                    private_key_multibase: "z6Mk...signing".to_string(),
                },
                SecretEntry {
                    key_id: "did:webvh:abc123:example.com#key-1".to_string(),
                    key_type: KeyType::X25519,
                    private_key_multibase: "z6Mk...ka".to_string(),
                },
            ],
        };

        let encoded = bundle.encode().unwrap();
        let decoded = DidSecretsBundle::decode(&encoded).unwrap();

        assert_eq!(decoded.did, bundle.did);
        assert_eq!(decoded.secrets.len(), 2);
        assert_eq!(decoded.secrets[0].key_id, bundle.secrets[0].key_id);
        assert_eq!(decoded.secrets[0].key_type, KeyType::Ed25519);
        assert_eq!(
            decoded.secrets[0].private_key_multibase,
            bundle.secrets[0].private_key_multibase
        );
        assert_eq!(decoded.secrets[1].key_type, KeyType::X25519);
    }

    #[test]
    fn test_decode_invalid_base64() {
        let result = DidSecretsBundle::decode("!!!not-base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64"));
    }

    #[test]
    fn test_decode_invalid_json() {
        let encoded = BASE64.encode(b"not json");
        let result = DidSecretsBundle::decode(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("JSON"));
    }

    #[test]
    fn test_decode_empty_secrets() {
        let bundle = DidSecretsBundle {
            did: "did:example:123".to_string(),
            secrets: vec![],
        };
        let encoded = bundle.encode().unwrap();
        let decoded = DidSecretsBundle::decode(&encoded).unwrap();
        assert_eq!(decoded.did, "did:example:123");
        assert!(decoded.secrets.is_empty());
    }
}
