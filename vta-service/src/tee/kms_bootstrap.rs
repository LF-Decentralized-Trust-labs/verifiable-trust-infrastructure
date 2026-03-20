//! KMS-based secret bootstrap for Nitro Enclaves.
//!
//! On first boot (no existing ciphertext), generates a BIP-39 seed and JWT
//! signing key inside the TEE, encrypts them with KMS, writes the ciphertext
//! to external storage, and stores a JWT key fingerprint for tamper detection.
//!
//! On subsequent boots, decrypts the ciphertext using KMS, verifies the JWT
//! key fingerprint, and returns the secrets for use.
//!
//! # Attestation Status
//!
//! The full Nitro attestation flow (ephemeral RSA + NSM attestation document +
//! CiphertextForRecipient) requires the `aws-nitro-enclaves-nsm-api` crate
//! running on real Nitro hardware. When NSM is not available (simulated mode
//! or development), the VTA falls back to direct KMS Decrypt. This is logged
//! as a warning — in production, the KMS key policy's PCR conditions provide
//! the attestation enforcement at the KMS level regardless.

use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

use crate::config::TeeKmsConfig;
use crate::error::AppError;

/// Secrets bootstrapped from KMS, held only in TEE memory.
///
/// All secret fields are zeroed on drop via the `Drop` implementation.
pub struct BootstrappedSecrets {
    /// BIP-39 seed (32 bytes).
    pub seed: Vec<u8>,
    /// JWT signing key (32 bytes).
    pub jwt_signing_key: [u8; 32],
    /// AES-256 storage encryption key (32 bytes), derived from seed via HKDF.
    pub storage_key: [u8; 32],
    /// BIP-39 entropy bytes (only on first boot — `None` on subsequent boots).
    pub entropy: Option<[u8; 32]>,
    /// Whether this is a first boot (new secrets generated).
    pub is_first_boot: bool,
}

impl Drop for BootstrappedSecrets {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.jwt_signing_key.zeroize();
        self.storage_key.zeroize();
        if let Some(ref mut e) = self.entropy {
            e.zeroize();
        }
    }
}

/// JWT key fingerprint file name (stored alongside ciphertexts).
const JWT_FINGERPRINT_FILE: &str = "jwt.fingerprint";

/// Bootstrap secrets from KMS.
///
/// - If ciphertext files exist: decrypt via KMS, verify JWT fingerprint (subsequent boot)
/// - If no ciphertext files: generate new secrets, encrypt with KMS, store ciphertext + fingerprint (first boot)
pub async fn bootstrap_secrets(
    kms_config: &TeeKmsConfig,
    storage_key_salt: &str,
) -> Result<BootstrappedSecrets, AppError> {
    let seed_ct_path = std::path::Path::new(&kms_config.seed_ciphertext_path);
    let jwt_ct_path = std::path::Path::new(&kms_config.jwt_ciphertext_path);

    let seed: Vec<u8>;
    let jwt_key: [u8; 32];

    if seed_ct_path.exists() && jwt_ct_path.exists() {
        // ── Subsequent boot: decrypt existing ciphertexts ──
        info!("found existing secret ciphertexts — decrypting via KMS");

        let seed_ciphertext = std::fs::read(seed_ct_path)
            .map_err(|e| AppError::TeeAttestation(format!("failed to read seed ciphertext: {e}")))?;
        let jwt_ciphertext = std::fs::read(jwt_ct_path)
            .map_err(|e| AppError::TeeAttestation(format!("failed to read JWT ciphertext: {e}")))?;

        seed = kms_decrypt(kms_config, &seed_ciphertext).await?;
        let jwt_bytes = kms_decrypt(kms_config, &jwt_ciphertext).await?;
        jwt_key = jwt_bytes.try_into().map_err(|_| {
            AppError::TeeAttestation("JWT key must be exactly 32 bytes".into())
        })?;

        // Verify JWT key fingerprint (tamper detection)
        verify_jwt_fingerprint(kms_config, &jwt_key)?;

        info!("secrets decrypted from KMS — subsequent boot");
    } else {
        // ── First boot: generate new secrets inside the TEE ──
        info!("no existing ciphertexts found — first boot, generating new secrets in TEE");

        // Generate BIP-39 entropy using platform random (NSM-backed in Nitro).
        let mut entropy = [0u8; 32];
        rand::fill(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| AppError::TeeAttestation(format!("failed to generate mnemonic: {e}")))?;

        info!("first boot — master seed generated inside TEE (mnemonic NOT displayed)");
        info!("to export the mnemonic, restart with VTA_MNEMONIC_EXPORT_WINDOW=<seconds>");

        seed = mnemonic.to_seed("").to_vec();
        // BIP-39 to_seed returns 64 bytes; we use the first 32 for BIP-32 compatibility
        let seed = seed[..32].to_vec();

        // Generate random JWT signing key
        let mut jwt_key_bytes = [0u8; 32];
        rand::fill(&mut jwt_key_bytes);
        jwt_key = jwt_key_bytes;

        // Encrypt and store ciphertexts
        let seed_ciphertext = kms_encrypt(kms_config, &seed).await?;
        let jwt_ciphertext = kms_encrypt(kms_config, &jwt_key).await?;

        // Create parent directories
        if let Some(parent) = seed_ct_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AppError::TeeAttestation(format!("failed to create secrets directory: {e}"))
            })?;
        }

        std::fs::write(seed_ct_path, &seed_ciphertext).map_err(|e| {
            AppError::TeeAttestation(format!("failed to write seed ciphertext: {e}"))
        })?;
        std::fs::write(jwt_ct_path, &jwt_ciphertext).map_err(|e| {
            AppError::TeeAttestation(format!("failed to write JWT ciphertext: {e}"))
        })?;

        // Store JWT key fingerprint for tamper detection on subsequent boots
        store_jwt_fingerprint(kms_config, &jwt_key)?;

        info!("secrets generated and encrypted to KMS — ciphertexts stored");

        return Ok(BootstrappedSecrets {
            storage_key: derive_storage_key(&seed, storage_key_salt),
            seed,
            jwt_signing_key: jwt_key,
            entropy: Some(entropy),
            is_first_boot: true,
        });
    }

    let storage_key = derive_storage_key(&seed, storage_key_salt);

    Ok(BootstrappedSecrets {
        seed,
        jwt_signing_key: jwt_key,
        storage_key,
        entropy: None,
        is_first_boot: false,
    })
}

// ---------------------------------------------------------------------------
// JWT key fingerprint (tamper detection)
// ---------------------------------------------------------------------------

/// Compute a SHA-256 fingerprint of the JWT signing key.
fn jwt_fingerprint(key: &[u8; 32]) -> String {
    let hash = Sha256::digest(key);
    hex::encode(&hash[..16]) // First 16 bytes = 32 hex chars
}

/// Store the JWT key fingerprint alongside the ciphertexts.
fn store_jwt_fingerprint(config: &TeeKmsConfig, key: &[u8; 32]) -> Result<(), AppError> {
    let fingerprint = jwt_fingerprint(key);
    let path = fingerprint_path(config);
    std::fs::write(&path, fingerprint.as_bytes()).map_err(|e| {
        AppError::TeeAttestation(format!("failed to write JWT fingerprint: {e}"))
    })?;
    debug!(fingerprint = %fingerprint, "JWT key fingerprint stored");
    Ok(())
}

/// Verify the JWT key matches the stored fingerprint.
fn verify_jwt_fingerprint(config: &TeeKmsConfig, key: &[u8; 32]) -> Result<(), AppError> {
    let path = fingerprint_path(config);
    if !path.exists() {
        // No fingerprint file — likely an upgrade from before fingerprinting was added.
        // Store it now for future boots, but don't fail.
        warn!("no JWT fingerprint file found — storing one now (first boot after upgrade)");
        return store_jwt_fingerprint(config, key);
    }

    let stored = std::fs::read_to_string(&path).map_err(|e| {
        AppError::TeeAttestation(format!("failed to read JWT fingerprint: {e}"))
    })?;
    let computed = jwt_fingerprint(key);

    if stored.trim() != computed {
        error!(
            stored = %stored.trim(),
            computed = %computed,
            "JWT key fingerprint MISMATCH — possible key tampering or KMS key rotation"
        );
        return Err(AppError::TeeAttestation(
            "JWT key fingerprint mismatch — the decrypted JWT key does not match the key \
             used on first boot. This could indicate tampering with the ciphertext files \
             or a KMS key change. If this is intentional (e.g., disaster recovery), \
             delete the jwt.fingerprint file and restart."
                .into(),
        ));
    }

    debug!(fingerprint = %computed, "JWT key fingerprint verified");
    Ok(())
}

fn fingerprint_path(config: &TeeKmsConfig) -> std::path::PathBuf {
    std::path::Path::new(&config.jwt_ciphertext_path)
        .parent()
        .unwrap_or(std::path::Path::new("/mnt/vta-data/secrets"))
        .join(JWT_FINGERPRINT_FILE)
}

// ---------------------------------------------------------------------------
// Storage key derivation
// ---------------------------------------------------------------------------

/// Derive the AES-256 storage encryption key from the master seed using HKDF.
///
/// Uses HMAC-SHA256 as the PRF. The salt and info strings ensure domain separation.
/// Deterministic: same seed + salt → same key (survives enclave restarts).
pub(crate) fn derive_storage_key(seed: &[u8], salt: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    // HKDF-Extract: PRK = HMAC-SHA256(salt, seed)
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(seed);
    let prk = mac.finalize().into_bytes();

    // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    let info = b"aes-256-gcm-storage";
    let mut mac = HmacSha256::new_from_slice(&prk)
        .expect("HMAC accepts any key length");
    mac.update(info);
    mac.update(&[0x01]);
    let okm = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

// ---------------------------------------------------------------------------
// KMS operations
// ---------------------------------------------------------------------------

/// Decrypt ciphertext using KMS.
///
/// On real Nitro hardware (/dev/nsm available), this should use the
/// attestation-based Recipient parameter. Currently uses direct KMS Decrypt
/// which is protected by the KMS key policy's PCR conditions.
async fn kms_decrypt(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    if std::path::Path::new("/dev/nsm").exists() {
        // TODO: Implement attestation-based KMS Decrypt with Recipient parameter.
        // This requires aws-nitro-enclaves-nsm-api for NSM attestation docs and
        // RSA key generation, plus CMS envelope parsing (RFC 5652).
        //
        // Currently using direct KMS Decrypt. Security is maintained by the KMS
        // key policy which requires attestation conditions (PCR0/PCR3/PCR8) on
        // the EC2 instance role — KMS rejects requests from non-matching enclaves.
        //
        // The Recipient parameter adds an additional layer: KMS re-encrypts the
        // response to the enclave's ephemeral RSA key, preventing even the parent
        // from reading the response. Without it, the parent could theoretically
        // intercept the KMS response on the vsock channel. In practice, the
        // response is protected by TLS between the AWS SDK and KMS.
        warn!("using direct KMS Decrypt (attestation-based Recipient parameter not yet implemented)");
    }

    kms_decrypt_direct(config, ciphertext).await
}

/// Direct KMS Decrypt without the Recipient parameter.
async fn kms_decrypt_direct(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;

    let client = aws_sdk_kms::Client::new(&sdk_config);

    let resp = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
        .key_id(&config.key_arn)
        .send()
        .await
        .map_err(|e| classify_kms_error("Decrypt", e))?;

    resp.plaintext()
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| AppError::TeeAttestation("KMS Decrypt returned no plaintext".into()))
}

/// Encrypt plaintext with KMS (for first-boot secret storage).
async fn kms_encrypt(
    config: &TeeKmsConfig,
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;

    let client = aws_sdk_kms::Client::new(&sdk_config);

    let resp = client
        .encrypt()
        .key_id(&config.key_arn)
        .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext))
        .send()
        .await
        .map_err(|e| classify_kms_error("Encrypt", e))?;

    resp.ciphertext_blob()
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| AppError::TeeAttestation("KMS Encrypt returned no ciphertext".into()))
}

/// Classify KMS errors for operator diagnostics.
fn classify_kms_error<E: std::error::Error>(operation: &str, err: E) -> AppError {
    let err_str = format!("{err}");

    // Classify by error message patterns for clear operator guidance
    let classification = if err_str.contains("AccessDeniedException") {
        "ACCESS_DENIED — check KMS key policy PCR conditions and IAM role permissions"
    } else if err_str.contains("NotFoundException") || err_str.contains("not found") {
        "KEY_NOT_FOUND — verify the KMS key ARN in config.toml"
    } else if err_str.contains("InvalidCiphertextException") {
        "INVALID_CIPHERTEXT — ciphertext file may be corrupt or encrypted with a different key"
    } else if err_str.contains("KMSInternalException") {
        "KMS_INTERNAL — transient AWS error, retry may help"
    } else if err_str.contains("connect") || err_str.contains("timeout") {
        "NETWORK — cannot reach KMS endpoint, check vsock proxy and allowlist"
    } else {
        "UNKNOWN"
    };

    let mut msg = format!("KMS {operation} failed [{classification}]: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        msg.push_str(&format!("\n  caused by: {cause}"));
        source = cause.source();
    }

    error!(operation, classification, "KMS error");
    AppError::TeeAttestation(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_storage_key_deterministic() {
        let seed = [0x42u8; 32];
        let key1 = derive_storage_key(&seed, "test-salt");
        let key2 = derive_storage_key(&seed, "test-salt");
        assert_eq!(key1, key2, "same seed + salt must produce same key");
    }

    #[test]
    fn test_derive_storage_key_different_salts() {
        let seed = [0x42u8; 32];
        let key1 = derive_storage_key(&seed, "salt-a");
        let key2 = derive_storage_key(&seed, "salt-b");
        assert_ne!(key1, key2, "different salts must produce different keys");
    }

    #[test]
    fn test_derive_storage_key_different_seeds() {
        let key1 = derive_storage_key(&[0x01u8; 32], "same-salt");
        let key2 = derive_storage_key(&[0x02u8; 32], "same-salt");
        assert_ne!(key1, key2, "different seeds must produce different keys");
    }

    #[test]
    fn test_jwt_fingerprint_deterministic() {
        let key = [0xABu8; 32];
        let fp1 = jwt_fingerprint(&key);
        let fp2 = jwt_fingerprint(&key);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32); // 16 bytes = 32 hex chars
    }
}
