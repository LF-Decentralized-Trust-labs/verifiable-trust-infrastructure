use crate::error::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// JWT claims for VTA/VTC access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub sub: String,
    pub session_id: String,
    pub role: String,
    #[serde(default)]
    pub contexts: Vec<String>,
    pub exp: u64,
    /// Indicates the service is running inside a Trusted Execution Environment.
    /// Only present (and `true`) when TEE is active; omitted when false to
    /// reduce token size.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tee_attested: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// Holds the JWT encoding and decoding keys derived from an Ed25519 seed.
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    /// Audience string used for encoding and validation (e.g., "VTA" or "VTC").
    audience: String,
}

impl JwtKeys {
    /// Create JWT keys from raw 32-byte Ed25519 private key bytes.
    ///
    /// `audience` is the expected JWT audience claim (e.g., "VTA" or "VTC").
    ///
    /// Computes the public key and wraps both in DER format as required
    /// by `jsonwebtoken`'s `from_ed_der()` methods.
    pub fn from_ed25519_bytes(private_bytes: &[u8; 32], audience: &str) -> Result<Self, AppError> {
        // Compute the Ed25519 public key from the private key seed
        let signing_key = ed25519_dalek::SigningKey::from_bytes(private_bytes);
        let public_bytes = signing_key.verifying_key().to_bytes();

        // Build PKCS8 v1 DER for the private key (used by EncodingKey)
        //
        // SEQUENCE {                                  -- 0x30, 0x2e (46 bytes)
        //   INTEGER 0                                 -- 0x02, 0x01, 0x00
        //   SEQUENCE { OID 1.3.101.112 }              -- 0x30, 0x05, ...
        //   OCTET STRING { OCTET STRING <32 bytes> }  -- 0x04, 0x22, 0x04, 0x20, ...
        // }
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&[
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER 0 (version v1)
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier (Ed25519)
            0x04, 0x22, 0x04, 0x20, // OCTET STRING { OCTET STRING, 32 bytes }
        ]);
        pkcs8.extend_from_slice(private_bytes);

        let encoding = EncodingKey::from_ed_der(&pkcs8);
        // rust_crypto backend expects raw 32-byte public key, not SPKI DER
        let decoding = DecodingKey::from_ed_der(&public_bytes);

        Ok(Self {
            encoding,
            decoding,
            audience: audience.to_string(),
        })
    }

    /// Encode claims into a signed JWT access token.
    pub fn encode(&self, claims: &Claims) -> Result<String, AppError> {
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| AppError::Internal(format!("JWT encode failed: {e}")))
    }

    /// Decode and validate a JWT access token, returning the claims.
    pub fn decode(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id", "role"]);

        jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                debug!(error = %e, "JWT decode failed");
                AppError::Unauthorized(format!("invalid token: {e}"))
            })
    }

    /// Create claims for a new access token.
    pub fn new_claims(
        &self,
        sub: String,
        session_id: String,
        role: String,
        contexts: Vec<String>,
        expiry_secs: u64,
        tee_attested: bool,
    ) -> Claims {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + expiry_secs;

        Claims {
            aud: self.audience.clone(),
            sub,
            session_id,
            role,
            contexts,
            exp,
            tee_attested,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn test_keys() -> JwtKeys {
        JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTA").unwrap()
    }

    #[test]
    fn test_jwt_roundtrip() {
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-1".into(),
            "admin".into(),
            vec!["vta".into()],
            900,
            false,
        );
        let token = keys.encode(&claims).unwrap();
        let decoded = keys.decode(&token).unwrap();
        assert_eq!(decoded.sub, "did:key:z6Mk");
        assert_eq!(decoded.role, "admin");
        assert!(!decoded.tee_attested);
    }

    #[test]
    fn test_jwt_tee_attested_true() {
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-2".into(),
            "admin".into(),
            vec![],
            900,
            true,
        );
        let token = keys.encode(&claims).unwrap();

        // Verify the raw JSON contains tee_attested
        let parts: Vec<&str> = token.split('.').collect();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(json["tee_attested"], true);

        let decoded = keys.decode(&token).unwrap();
        assert!(decoded.tee_attested);
    }

    #[test]
    fn test_jwt_tee_attested_false_omitted() {
        let keys = test_keys();
        let claims = keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-3".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let token = keys.encode(&claims).unwrap();

        // Verify tee_attested is NOT in the JSON (skip_serializing_if)
        let parts: Vec<&str> = token.split('.').collect();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(json.get("tee_attested").is_none());
    }

    #[test]
    fn test_jwt_audience_parameterized() {
        let vta_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTA").unwrap();
        let vtc_keys = JwtKeys::from_ed25519_bytes(&[0x42u8; 32], "VTC").unwrap();

        // VTA token should decode with VTA keys
        let claims = vta_keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-1".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let token = vta_keys.encode(&claims).unwrap();
        assert!(vta_keys.decode(&token).is_ok());
        // VTA token should NOT decode with VTC audience
        assert!(vtc_keys.decode(&token).is_err());

        // VTC token should decode with VTC keys
        let claims = vtc_keys.new_claims(
            "did:key:z6Mk".into(),
            "sess-2".into(),
            "admin".into(),
            vec![],
            900,
            false,
        );
        let token = vtc_keys.encode(&claims).unwrap();
        assert!(vtc_keys.decode(&token).is_ok());
        assert!(vta_keys.decode(&token).is_err());
    }
}
