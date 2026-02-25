use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

/// A portable credential bundle issued by a VTA for client authentication.
///
/// Encodes as JSON, then base64url-no-pad for safe transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialBundle {
    pub did: String,
    #[serde(rename = "privateKeyMultibase")]
    pub private_key_multibase: String,
    #[serde(rename = "vtaDid")]
    pub vta_did: String,
    #[serde(rename = "vtaUrl", default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,
}

impl CredentialBundle {
    /// Decode a base64url-no-pad encoded credential bundle.
    pub fn decode(encoded: &str) -> Result<Self, CredentialBundleError> {
        let json_bytes = BASE64
            .decode(encoded)
            .map_err(|e| CredentialBundleError::Base64(e.to_string()))?;
        serde_json::from_slice(&json_bytes).map_err(|e| CredentialBundleError::Json(e.to_string()))
    }

    /// Encode this bundle as a base64url-no-pad string.
    pub fn encode(&self) -> Result<String, CredentialBundleError> {
        let json =
            serde_json::to_vec(self).map_err(|e| CredentialBundleError::Json(e.to_string()))?;
        Ok(BASE64.encode(&json))
    }
}

/// Errors when decoding or encoding a [`CredentialBundle`].
#[derive(Debug)]
pub enum CredentialBundleError {
    Base64(String),
    Json(String),
}

impl std::fmt::Display for CredentialBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64(e) => write!(f, "base64 decode error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
        }
    }
}

impl std::error::Error for CredentialBundleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_bundle_full() {
        let json = r#"{
            "did": "did:key:z6Mk123",
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA",
            "vtaUrl": "https://vta.example.com"
        }"#;
        let bundle: CredentialBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.did, "did:key:z6Mk123");
        assert_eq!(bundle.private_key_multibase, "z1234567890");
        assert_eq!(bundle.vta_did, "did:key:z6MkVTA");
        assert_eq!(bundle.vta_url.as_deref(), Some("https://vta.example.com"));
    }

    #[test]
    fn test_credential_bundle_without_url() {
        let json = r#"{
            "did": "did:key:z6Mk123",
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA"
        }"#;
        let bundle: CredentialBundle = serde_json::from_str(json).unwrap();
        assert!(bundle.vta_url.is_none());
    }

    #[test]
    fn test_credential_bundle_missing_did_fails() {
        let json = r#"{
            "privateKeyMultibase": "z1234567890",
            "vtaDid": "did:key:z6MkVTA"
        }"#;
        assert!(serde_json::from_str::<CredentialBundle>(json).is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let bundle = CredentialBundle {
            did: "did:key:z6Mk123".to_string(),
            private_key_multibase: "z1234567890".to_string(),
            vta_did: "did:key:z6MkVTA".to_string(),
            vta_url: Some("https://vta.example.com".to_string()),
        };
        let encoded = bundle.encode().unwrap();
        let decoded = CredentialBundle::decode(&encoded).unwrap();
        assert_eq!(decoded.did, bundle.did);
        assert_eq!(decoded.private_key_multibase, bundle.private_key_multibase);
        assert_eq!(decoded.vta_did, bundle.vta_did);
        assert_eq!(decoded.vta_url, bundle.vta_url);
    }

    #[test]
    fn test_encode_decode_without_url() {
        let bundle = CredentialBundle {
            did: "did:key:z6Mk123".to_string(),
            private_key_multibase: "z1234567890".to_string(),
            vta_did: "did:key:z6MkVTA".to_string(),
            vta_url: None,
        };
        let encoded = bundle.encode().unwrap();
        let decoded = CredentialBundle::decode(&encoded).unwrap();
        assert!(decoded.vta_url.is_none());
    }

    #[test]
    fn test_decode_invalid_base64() {
        let result = CredentialBundle::decode("!!!not-base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64"));
    }

    #[test]
    fn test_decode_invalid_json() {
        let encoded = BASE64.encode(b"not json");
        let result = CredentialBundle::decode(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("JSON"));
    }
}
