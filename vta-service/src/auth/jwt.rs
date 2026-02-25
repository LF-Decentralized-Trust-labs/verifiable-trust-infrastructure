use crate::error::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// JWT claims for VTA access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub sub: String,
    pub session_id: String,
    pub role: String,
    #[serde(default)]
    pub contexts: Vec<String>,
    pub exp: u64,
}

/// Holds the JWT encoding and decoding keys derived from an Ed25519 seed.
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKeys {
    /// Create JWT keys from raw 32-byte Ed25519 private key bytes.
    ///
    /// Computes the public key and wraps both in DER format as required
    /// by `jsonwebtoken`'s `from_ed_der()` methods.
    pub fn from_ed25519_bytes(private_bytes: &[u8; 32]) -> Result<Self, AppError> {
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

        Ok(Self { encoding, decoding })
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
        validation.set_audience(&["VTA"]);
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
        sub: String,
        session_id: String,
        role: String,
        contexts: Vec<String>,
        expiry_secs: u64,
    ) -> Claims {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + expiry_secs;

        Claims {
            aud: "VTA".to_string(),
            sub,
            session_id,
            role,
            contexts,
            exp,
        }
    }
}
