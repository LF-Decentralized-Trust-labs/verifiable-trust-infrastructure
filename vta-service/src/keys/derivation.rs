use crate::error::AppError;
use crate::keys::seed_store::SeedStore;
use affinidi_tdk::{
    affinidi_crypto::ed25519::ed25519_private_to_x25519, secrets_resolver::secrets::Secret,
};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use rand::Rng;
use tracing::{debug, info};

/// Wrapper holding a derived P-256 secret key.
pub struct P256Secret {
    pub secret_key: p256::SecretKey,
}

pub trait Bip32Extension {
    /// Derive an Ed25519 key pair from a seed and BIP32 derivation path.
    ///
    /// Returns `Secret`.
    fn derive_ed25519(&self, path: &str) -> Result<Secret, AppError>;
    /// Derive an X25519 key pair from a seed and BIP32 derivation path.
    ///
    /// Returns `Secret`.
    fn derive_x25519(&self, path: &str) -> Result<Secret, AppError>;
    /// Derive a P-256 key pair from a seed and BIP32 derivation path.
    ///
    /// Uses HMAC-SHA512 domain separation to produce P-256 key material
    /// independent from the Ed25519 key at the same path. This avoids
    /// cross-curve key reuse, Ed25519 clamping artifacts, and group-order bias.
    fn derive_p256(&self, path: &str) -> Result<P256Secret, AppError>;
}

impl Bip32Extension for ExtendedSigningKey {
    fn derive_ed25519(&self, path: &str) -> Result<Secret, AppError> {
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| AppError::KeyDerivation(format!("invalid derivation path: {e}")))?;

        let derived = self
            .derive(&derivation_path)
            .map_err(|e| AppError::KeyDerivation(format!("derivation failed: {e}")))?;

        Ok(Secret::generate_ed25519(
            None,
            Some(derived.signing_key.as_bytes()),
        ))
    }

    fn derive_x25519(&self, path: &str) -> Result<Secret, AppError> {
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| AppError::KeyDerivation(format!("invalid derivation path: {e}")))?;

        let derived = self
            .derive(&derivation_path)
            .map_err(|e| AppError::KeyDerivation(format!("derivation failed: {e}")))?;

        let x25519_seed = ed25519_private_to_x25519(derived.signing_key.as_bytes());
        Ok(Secret::generate_x25519(None, Some(&x25519_seed))?)
    }

    fn derive_p256(&self, path: &str) -> Result<P256Secret, AppError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| AppError::KeyDerivation(format!("invalid derivation path: {e}")))?;

        let derived = self
            .derive(&derivation_path)
            .map_err(|e| AppError::KeyDerivation(format!("derivation failed: {e}")))?;

        // Domain-separated derivation via HMAC-SHA512.
        // Prevents cross-curve key reuse: the same BIP-32 path produces
        // independent key material for Ed25519 and P-256.
        let mut mac = Hmac::<Sha512>::new_from_slice(b"p256-key-derivation")
            .expect("HMAC accepts any key length");
        mac.update(derived.signing_key.as_bytes());
        mac.update(&derived.chain_code);
        let hmac_output = mac.finalize().into_bytes();

        // First 32 bytes → P-256 scalar. from_bytes() reduces mod n automatically.
        let secret_key = p256::SecretKey::from_bytes(
            p256::FieldBytes::from_slice(&hmac_output[..32]),
        )
        .map_err(|e| AppError::KeyDerivation(format!("P-256 key creation failed: {e}")))?;

        Ok(P256Secret { secret_key })
    }
}

/// Load an existing master seed from the store, or generate/derive a new one.
///
/// - If `mnemonic` is provided, validates it as a BIP-39 phrase and derives a
///   64-byte seed via PBKDF2 (with an empty passphrase), then stores it.
/// - If no mnemonic and a seed already exists, returns the existing seed.
/// - If no mnemonic and no seed exists, generates 32 random bytes and stores them.
#[allow(dead_code)]
pub async fn load_or_generate_seed(
    seed_store: &dyn SeedStore,
    mnemonic: Option<&str>,
) -> Result<ExtendedSigningKey, AppError> {
    if let Some(phrase) = mnemonic {
        let m = bip39::Mnemonic::parse(phrase)
            .map_err(|e| AppError::KeyDerivation(format!("invalid BIP-39 mnemonic: {e}")))?;
        let seed = m.to_seed("");
        seed_store.set(&seed).await?;
        info!("master seed derived from mnemonic and stored");
        return ExtendedSigningKey::from_seed(&seed).map_err(|e| {
            AppError::KeyDerivation(format!(
                "Couldn't create bip32 root signing key! Reason: {e}"
            ))
        });
    }

    if let Some(existing) = seed_store.get().await? {
        debug!("master seed loaded from store");
        return ExtendedSigningKey::from_seed(&existing).map_err(|e| {
            AppError::KeyDerivation(format!(
                "Couldn't create bip32 root signing key! Reason: {e}"
            ))
        });
    }

    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    seed_store.set(&seed).await?;
    info!("new random master seed generated and stored");
    ExtendedSigningKey::from_seed(&seed).map_err(|e| {
        AppError::KeyDerivation(format!(
            "Couldn't create bip32 root signing key! Reason: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    fn get_bip32() -> ExtendedSigningKey {
        ExtendedSigningKey::from_seed(&[
            7, 26, 142, 230, 65, 85, 188, 182, 29, 129, 52, 229, 217, 159, 243, 182, 73, 89, 196,
            246, 58, 28, 100, 144, 187, 21, 157, 39, 4, 188, 154, 180,
        ])
        .unwrap()
    }

    #[test]
    fn test_derive_ed25519_deterministic() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let secret = bip32.derive_ed25519(path).unwrap();

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z3u2RHYaCxd1wzvJB6wQEcnrLth65xcNHcGDDSdfwDjmkoG3".to_string()
        );
        assert_eq!(
            secret.get_public_keymultibase().unwrap(),
            "z6MkestKNR7EyyB8yojbPcRoG8rF6iX4uXYkyVbDBsM9Fj5i".to_string()
        );
    }

    #[test]
    fn test_derive_ed25519_different_paths() {
        let bip32 = get_bip32();

        let secret1 = bip32.derive_ed25519("m/44'/0'/0'").unwrap();
        let secret2 = bip32.derive_ed25519("m/44'/0'/1'").unwrap();

        assert_eq!(
            secret1.get_private_keymultibase().unwrap(),
            "z3u2RHYaCxd1wzvJB6wQEcnrLth65xcNHcGDDSdfwDjmkoG3".to_string()
        );
        assert_eq!(
            secret1.get_public_keymultibase().unwrap(),
            "z6MkestKNR7EyyB8yojbPcRoG8rF6iX4uXYkyVbDBsM9Fj5i".to_string()
        );
        assert_eq!(
            secret2.get_private_keymultibase().unwrap(),
            "z3u2iLUGo3YPXjUFE6LR2z1f84ufRDe4PEeQpvA9dPU8HZ1G".to_string()
        );
        assert_eq!(
            secret2.get_public_keymultibase().unwrap(),
            "z6Mkw5tnbEgzv7zc4SJmSACo6FbfKLHveK4dCHjar8h2voDE".to_string()
        );
    }

    #[test]
    fn test_derive_x25519_deterministic() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let secret = bip32.derive_x25519(path).unwrap();

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z3wenSajog3TCG3QxA8yVvEniVxp2QU9mE3fYgDYQj8j6MHo".to_string()
        );
        assert_eq!(
            secret.get_public_keymultibase().unwrap(),
            "z6LStYM3H4UG8qn79pQwGmSRd81VMETBPjH49uf5SeqJBB7G".to_string()
        );
    }

    #[test]
    fn test_derive_x25519_differs_from_ed25519() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let ed_secret = bip32.derive_ed25519(path).unwrap();
        let x_secret = bip32.derive_x25519(path).unwrap();

        assert_ne!(
            ed_secret.get_public_keymultibase().unwrap(),
            x_secret.get_private_keymultibase().unwrap()
        );
    }

    #[test]
    fn test_invalid_path() {
        let bip32 = get_bip32();
        let result = bip32.derive_ed25519("not/a/valid/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_bip39_seed_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m1 = bip39::Mnemonic::parse(phrase).unwrap();
        let m2 = bip39::Mnemonic::parse(phrase).unwrap();
        assert_eq!(m1.to_seed(""), m2.to_seed(""));
        // BIP-39 produces a 64-byte seed
        assert_eq!(m1.to_seed("").len(), 64);
    }

    #[test]
    fn test_bip39_invalid_mnemonic() {
        let result = bip39::Mnemonic::parse("not a valid mnemonic");
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_p256_deterministic() {
        let bip32 = get_bip32();
        let path = "m/44'/0'/0'";

        let p256_1 = bip32.derive_p256(path).unwrap();
        let p256_2 = bip32.derive_p256(path).unwrap();

        // Same seed + path must produce the same key
        assert_eq!(
            p256_1.secret_key.to_bytes(),
            p256_2.secret_key.to_bytes()
        );

        // Public key must be derivable
        let pk = p256_1.secret_key.public_key();
        let encoded = pk.to_encoded_point(true);
        assert_eq!(encoded.len(), 33, "compressed P-256 pubkey should be 33 bytes");
    }

    #[test]
    fn test_derive_p256_different_paths() {
        let bip32 = get_bip32();

        let p256_1 = bip32.derive_p256("m/44'/0'/0'").unwrap();
        let p256_2 = bip32.derive_p256("m/44'/0'/1'").unwrap();

        assert_ne!(
            p256_1.secret_key.to_bytes(),
            p256_2.secret_key.to_bytes(),
            "different paths must produce different keys"
        );
    }

    #[test]
    fn test_derive_p256_sign_verify() {
        let bip32 = get_bip32();
        let p256_secret = bip32.derive_p256("m/44'/0'/0'").unwrap();

        let signing_key = p256::ecdsa::SigningKey::from(&p256_secret.secret_key);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);

        use p256::ecdsa::signature::{Signer, Verifier};
        let message = b"hello VTA signing oracle";
        let sig: p256::ecdsa::Signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_derive_p256_invalid_path() {
        let bip32 = get_bip32();
        let result = bip32.derive_p256("not/a/valid/path");
        assert!(result.is_err());
    }
}
