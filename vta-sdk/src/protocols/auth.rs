use serde::{Deserialize, Serialize};

/// Client sends to `POST /auth/challenge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

/// Server responds from `POST /auth/challenge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub session_id: String,
    pub data: ChallengeData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    pub challenge: String,
}

/// Server responds from `POST /auth/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateResponse {
    #[serde(default)]
    pub session_id: Option<String>,
    pub data: AuthenticateData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateData {
    pub access_token: String,
    pub access_expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_expires_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_response_camel_case() {
        let json = r#"{
            "sessionId": "sess-abc",
            "data": { "challenge": "nonce123" }
        }"#;
        let resp: ChallengeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id, "sess-abc");
        assert_eq!(resp.data.challenge, "nonce123");
    }

    #[test]
    fn test_authenticate_response_camel_case() {
        let json = r#"{
            "data": {
                "accessToken": "jwt.token.here",
                "accessExpiresAt": 1700001000
            }
        }"#;
        let resp: AuthenticateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.access_token, "jwt.token.here");
        assert_eq!(resp.data.access_expires_at, 1700001000);
        assert!(resp.session_id.is_none());
        assert!(resp.data.refresh_token.is_none());
        assert!(resp.data.refresh_expires_at.is_none());
    }

    #[test]
    fn test_authenticate_response_full() {
        let json = r#"{
            "sessionId": "sess-123",
            "data": {
                "accessToken": "jwt.token.here",
                "accessExpiresAt": 1700001000,
                "refreshToken": "refresh-abc",
                "refreshExpiresAt": 1700002000
            }
        }"#;
        let resp: AuthenticateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id.as_deref(), Some("sess-123"));
        assert_eq!(resp.data.access_token, "jwt.token.here");
        assert_eq!(resp.data.access_expires_at, 1700001000);
        assert_eq!(resp.data.refresh_token.as_deref(), Some("refresh-abc"));
        assert_eq!(resp.data.refresh_expires_at, Some(1700002000));
    }

    #[test]
    fn test_challenge_request_serialize() {
        let req = ChallengeRequest {
            did: "did:key:z6Mk123".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["did"], "did:key:z6Mk123");
    }

    #[test]
    fn test_authenticate_response_serialize_skips_none() {
        let resp = AuthenticateResponse {
            session_id: Some("sess-1".to_string()),
            data: AuthenticateData {
                access_token: "tok".to_string(),
                access_expires_at: 100,
                refresh_token: None,
                refresh_expires_at: None,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["data"].get("refreshToken").is_none());
        assert!(json["data"].get("refreshExpiresAt").is_none());
    }
}
