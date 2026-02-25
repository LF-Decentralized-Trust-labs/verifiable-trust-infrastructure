/// Encode an Ed25519 public key as a multibase Base58BTC string with multicodec prefix `0xed01`.
pub fn ed25519_multibase_pubkey(public_key_bytes: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&[0xed, 0x01]);
    buf.extend_from_slice(public_key_bytes);
    multibase::encode(multibase::Base::Base58Btc, &buf)
}

/// Ed25519 private key multicodec prefix (`0x8026`).
const ED25519_PRIV_CODEC: [u8; 2] = [0x80, 0x26];

/// Decode a multibase-encoded private key seed to 32 bytes.
///
/// Accepts both raw 32-byte encodings and 34-byte encodings that include
/// the `0x8026` ed25519-priv multicodec prefix (as produced by
/// `Secret::get_private_keymultibase()`).
pub fn decode_private_key_multibase(mb: &str) -> Result<[u8; 32], DidKeyError> {
    let (_, raw) = multibase::decode(mb).map_err(|e| DidKeyError::Multibase(e.to_string()))?;
    let seed_bytes = if raw.len() == 34 && raw[..2] == ED25519_PRIV_CODEC {
        &raw[2..]
    } else {
        &raw[..]
    };
    seed_bytes
        .try_into()
        .map_err(|_| DidKeyError::InvalidSeedLength)
}

/// Ed25519 signing + X25519 key-agreement secrets for a `did:key`.
#[cfg(feature = "didcomm")]
pub struct DidKeySecrets {
    pub signing: affinidi_tdk::secrets_resolver::secrets::Secret,
    pub key_agreement: affinidi_tdk::secrets_resolver::secrets::Secret,
}

/// Construct Ed25519 signing + X25519 key-agreement secrets for a `did:key`.
///
/// The `did` must start with `did:key:`. The `seed` is the 32-byte Ed25519
/// private key seed.
#[cfg(feature = "didcomm")]
pub fn secrets_from_did_key(did: &str, seed: &[u8; 32]) -> Result<DidKeySecrets, DidKeyError> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let ed_pub_mb = did
        .strip_prefix("did:key:")
        .ok_or(DidKeyError::InvalidDidKey)?;

    // Ed25519 signing secret
    let mut signing = Secret::generate_ed25519(None, Some(seed));
    signing.id = format!("{did}#{ed_pub_mb}");

    // X25519 key-agreement secret (derived from Ed25519)
    let mut key_agreement = signing
        .to_x25519()
        .map_err(|e| DidKeyError::X25519Conversion(e.to_string()))?;
    let x_pub_mb = key_agreement
        .get_public_keymultibase()
        .map_err(|e| DidKeyError::X25519Conversion(e.to_string()))?;
    key_agreement.id = format!("{did}#{x_pub_mb}");

    Ok(DidKeySecrets {
        signing,
        key_agreement,
    })
}

#[derive(Debug)]
pub enum DidKeyError {
    Multibase(String),
    InvalidSeedLength,
    InvalidDidKey,
    #[cfg(feature = "didcomm")]
    X25519Conversion(String),
}

impl std::fmt::Display for DidKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Multibase(e) => write!(f, "invalid private key multibase: {e}"),
            Self::InvalidSeedLength => write!(f, "private key seed must be 32 bytes"),
            Self::InvalidDidKey => write!(f, "invalid did:key format"),
            #[cfg(feature = "didcomm")]
            Self::X25519Conversion(e) => write!(f, "X25519 conversion failed: {e}"),
        }
    }
}

impl std::error::Error for DidKeyError {}

/// Convert a [`GetKeySecretResponse`](crate::client::GetKeySecretResponse) into
/// an `affinidi_tdk` [`Secret`].
///
/// The response's `private_key_multibase` is a multicodec-prefixed multibase
/// string (e.g. ed25519-priv `0x8026`). `Secret::from_multibase` handles the
/// decoding for all supported key types.
#[cfg(feature = "client")]
pub fn secret_from_key_response(
    resp: &crate::client::GetKeySecretResponse,
) -> Result<affinidi_tdk::secrets_resolver::secrets::Secret, DidKeyError> {
    affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &resp.private_key_multibase,
        None,
    )
    .map_err(|e| DidKeyError::Multibase(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_multibase_pubkey_format() {
        let key = [0u8; 32];
        let result = ed25519_multibase_pubkey(&key);
        // Should start with 'z' (Base58BTC) and decode to [0xed, 0x01] + key
        assert!(result.starts_with('z'));

        let (_, decoded) = multibase::decode(&result).unwrap();
        assert_eq!(decoded.len(), 34);
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], &key);
    }

    #[test]
    fn test_decode_private_key_multibase_roundtrip() {
        let seed = [42u8; 32];
        let encoded = multibase::encode(multibase::Base::Base58Btc, seed);
        let decoded = decode_private_key_multibase(&encoded).unwrap();
        assert_eq!(decoded, seed);
    }

    #[test]
    fn test_decode_private_key_multibase_with_codec_prefix() {
        let seed = [42u8; 32];
        let mut prefixed = Vec::with_capacity(34);
        prefixed.extend_from_slice(&ED25519_PRIV_CODEC);
        prefixed.extend_from_slice(&seed);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &prefixed);
        let decoded = decode_private_key_multibase(&encoded).unwrap();
        assert_eq!(decoded, seed);
    }

    #[test]
    fn test_decode_private_key_multibase_invalid() {
        let result = decode_private_key_multibase("!!!bad!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_private_key_multibase_wrong_length() {
        let encoded = multibase::encode(multibase::Base::Base58Btc, [1u8; 16]);
        let result = decode_private_key_multibase(&encoded);
        assert!(matches!(result, Err(DidKeyError::InvalidSeedLength)));
    }
}
