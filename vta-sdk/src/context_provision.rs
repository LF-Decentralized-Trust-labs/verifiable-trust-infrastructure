use serde::{Deserialize, Serialize};

use crate::credentials::CredentialBundle;
use crate::did_secrets::SecretEntry;

/// A self-contained bundle for provisioning an application context.
///
/// Contains everything an independent application needs to connect to the VTA,
/// authenticate, and self-administer its context. Optionally includes DID
/// material (document, log entry, keys) when a DID was created during
/// provisioning.
///
/// Post-Phase-5 the canonical transport is [`crate::sealed_transfer`]
/// (`SealedPayloadV1::ContextProvision`) — HPKE-sealed, armored, with a
/// producer assertion anchoring trust. This struct is now only what rides
/// inside that envelope.
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
    /// Admin credential bundle for the provisioned context.
    pub credential: CredentialBundle,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_credential() -> CredentialBundle {
        CredentialBundle::new("did:key:z6Mk123", "z1234567890", "did:key:z6MkVTA")
    }

    #[test]
    fn test_serde_json_roundtrip_without_did() {
        let bundle = ContextProvisionBundle {
            context_id: "my-app".to_string(),
            context_name: "My Application".to_string(),
            vta_url: Some("https://vta.example.com".to_string()),
            vta_did: Some("did:webvh:abc:example.com".to_string()),
            credential: sample_credential(),
            admin_did: "did:key:z6Mk123".to_string(),
            did: None,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: ContextProvisionBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.context_id, "my-app");
        assert_eq!(decoded.context_name, "My Application");
        assert_eq!(decoded.admin_did, "did:key:z6Mk123");
        assert_eq!(decoded.credential.did, "did:key:z6Mk123");
        assert!(decoded.did.is_none());
    }

    #[test]
    fn test_serde_json_roundtrip_with_did() {
        let bundle = ContextProvisionBundle {
            context_id: "my-app".to_string(),
            context_name: "My Application".to_string(),
            vta_url: None,
            vta_did: None,
            credential: sample_credential(),
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
        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: ContextProvisionBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.context_id, "my-app");
        let did = decoded.did.unwrap();
        assert_eq!(did.id, "did:webvh:abc:example.com");
        assert!(did.did_document.is_some());
        assert!(did.log_entry.is_some());
        assert_eq!(did.secrets.len(), 1);
    }
}
