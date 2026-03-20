//! Integration tests for the VTA authentication flow.
//!
//! These tests verify the core authentication components in isolation.
//! Full end-to-end auth testing requires a running VTA instance with
//! configured DID resolver and seed store.

#[cfg(test)]
mod tests {
    use vta_sdk::protocols::auth::{ChallengeRequest, ChallengeResponse};

    #[test]
    fn challenge_request_serialization() {
        let req = ChallengeRequest {
            did: "did:key:z6MkTest123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ChallengeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.did, req.did);
    }

    #[test]
    fn challenge_response_has_required_fields() {
        let json = r#"{"sessionId":"abc-123","data":{"challenge":"deadbeef","teeAttestation":null}}"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id, "abc-123");
        assert_eq!(resp.data.challenge, "deadbeef");
    }

    #[test]
    fn did_base_extraction() {
        // The auth flow strips DID fragments before comparison
        let did_with_fragment = "did:key:z6MkTest123#key-0";
        let base = did_with_fragment.split('#').next().unwrap_or(did_with_fragment);
        assert_eq!(base, "did:key:z6MkTest123");

        let did_without_fragment = "did:key:z6MkTest123";
        let base = did_without_fragment.split('#').next().unwrap_or(did_without_fragment);
        assert_eq!(base, "did:key:z6MkTest123");
    }
}
