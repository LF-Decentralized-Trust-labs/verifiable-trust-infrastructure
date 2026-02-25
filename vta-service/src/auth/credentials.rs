use ed25519_dalek::SigningKey;
use multibase::Base;
use rand::Rng;
use tracing::debug;

use vta_sdk::did_key::ed25519_multibase_pubkey;

/// Generate a new `did:key` identity from a random Ed25519 keypair.
///
/// Returns `(did, private_key_multibase)` where:
/// - `did` is `did:key:z6Mk...`
/// - `private_key_multibase` is the seed encoded as multibase Base58BTC (`z...`)
pub fn generate_did_key() -> (String, String) {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);

    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let private_key_multibase = multibase::encode(Base::Base58Btc, seed);

    debug!(did = %did, "did:key identity generated");

    (did, private_key_multibase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_did_key_format() {
        let (did, priv_mb) = generate_did_key();
        assert!(
            did.starts_with("did:key:z6Mk"),
            "DID should start with did:key:z6Mk, got: {did}"
        );
        assert!(
            priv_mb.starts_with('z'),
            "private key multibase should start with 'z'"
        );

        // Decode private key to verify it's 32 bytes
        let (_, seed_bytes) = multibase::decode(&priv_mb).unwrap();
        assert_eq!(seed_bytes.len(), 32);
    }

    #[test]
    fn test_generate_did_key_unique() {
        let (did1, _) = generate_did_key();
        let (did2, _) = generate_did_key();
        assert_ne!(did1, did2);
    }

    #[test]
    fn test_generate_did_key_roundtrip() {
        let (did, priv_mb) = generate_did_key();

        // Re-derive the DID from the private key
        let (_, seed_bytes) = multibase::decode(&priv_mb).unwrap();
        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();

        let mut multicodec = Vec::with_capacity(34);
        multicodec.extend_from_slice(&[0xed, 0x01]);
        multicodec.extend_from_slice(&public_key);

        let multibase_pubkey = multibase::encode(Base::Base58Btc, &multicodec);
        let reconstructed_did = format!("did:key:{multibase_pubkey}");
        assert_eq!(did, reconstructed_did);
    }
}
