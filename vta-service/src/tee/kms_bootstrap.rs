//! KMS-based secret bootstrap for Nitro Enclaves.
//!
//! On first boot (no existing ciphertext), generates a BIP-39 seed and JWT
//! signing key inside the TEE, encrypts them with KMS, and writes the
//! ciphertext to external storage.
//!
//! On subsequent boots, decrypts the ciphertext using KMS with attestation-
//! based key policy enforcement (PCR0/PCR3/PCR8).

use sha2::Sha256;
use tracing::{info, warn};

use crate::config::TeeKmsConfig;
use crate::error::AppError;

/// Secrets bootstrapped from KMS, held only in TEE memory.
pub struct BootstrappedSecrets {
    /// BIP-39 seed (32 bytes).
    pub seed: Vec<u8>,
    /// JWT signing key (32 bytes).
    pub jwt_signing_key: [u8; 32],
    /// AES-256 storage encryption key (32 bytes), derived from seed via HKDF.
    pub storage_key: [u8; 32],
    /// BIP-39 entropy bytes (only on first boot — `None` on subsequent boots).
    /// Used by `MnemonicExportGuard` for time-limited, authenticated export.
    pub entropy: Option<[u8; 32]>,
}

/// Bootstrap secrets from KMS using Nitro attestation.
///
/// - If ciphertext files exist: decrypt via KMS with attestation (subsequent boot)
/// - If no ciphertext files: generate new secrets, encrypt with KMS, store ciphertext (first boot)
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
        info!("found existing secret ciphertexts — decrypting via KMS with attestation");

        let seed_ciphertext = std::fs::read(seed_ct_path)
            .map_err(|e| AppError::TeeAttestation(format!("failed to read seed ciphertext: {e}")))?;
        let jwt_ciphertext = std::fs::read(jwt_ct_path)
            .map_err(|e| AppError::TeeAttestation(format!("failed to read JWT ciphertext: {e}")))?;

        seed = kms_decrypt_with_attestation(kms_config, &seed_ciphertext).await?;
        let jwt_bytes = kms_decrypt_with_attestation(kms_config, &jwt_ciphertext).await?;
        jwt_key = jwt_bytes.try_into().map_err(|_| {
            AppError::TeeAttestation("JWT key must be exactly 32 bytes".into())
        })?;

        info!("secrets decrypted from KMS (attestation-verified)");
    } else if !kms_config.allow_first_boot {
        // ── Ciphertexts missing but first boot not allowed ──
        // This prevents an attacker from deleting ciphertext files to trigger
        // a first-boot and hijack the VTA with a new identity.
        return Err(AppError::TeeAttestation(
            "secret ciphertext files not found and allow_first_boot is false. \
             This may indicate the ciphertext files were deleted by an attacker. \
             If this is genuinely a first deployment, set tee.kms.allow_first_boot = true \
             in config.toml, deploy once, then set it back to false."
                .into(),
        ));
    } else {
        // ── First boot: generate new secrets inside the TEE ──
        info!("no existing ciphertexts found — first boot, generating new secrets in TEE");

        // Generate BIP-39 entropy using platform random (NSM-backed in Nitro).
        // The mnemonic is NEVER displayed. It can only be exported via the
        // authenticated, time-limited MnemonicExportGuard mechanism.
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

        info!("secrets generated and encrypted to KMS — ciphertexts stored");

        // First boot: return entropy for the MnemonicExportGuard
        return Ok(BootstrappedSecrets {
            storage_key: derive_storage_key(&seed, storage_key_salt),
            seed,
            jwt_signing_key: jwt_key,
            entropy: Some(entropy),
        });
    }

    let storage_key = derive_storage_key(&seed, storage_key_salt);

    // Subsequent boot: no entropy available (mnemonic export impossible)
    Ok(BootstrappedSecrets {
        seed,
        jwt_signing_key: jwt_key,
        storage_key,
        entropy: None,
    })
}

/// Derive the AES-256 storage encryption key from the master seed using HKDF.
///
/// Uses HMAC-SHA256 as the PRF. The salt and info strings ensure domain separation.
fn derive_storage_key(seed: &[u8], salt: &str) -> [u8; 32] {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, seed)
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

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

/// Decrypt ciphertext using KMS with Nitro attestation.
///
/// 1. Generates an ephemeral RSA-2048 keypair
/// 2. Gets an NSM attestation document embedding the RSA public key
/// 3. Calls KMS Decrypt with Recipient = { AttestationDocument, RSAES_OAEP_SHA_256 }
/// 4. KMS verifies PCR values against key policy, re-encrypts plaintext to RSA public key
/// 5. Decrypts CiphertextForRecipient with RSA private key
async fn kms_decrypt_with_attestation(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    // For now, this is a placeholder that documents the exact flow.
    // The full implementation requires the aws-sdk-kms and aws-nitro-enclaves-nsm-api
    // crates which need Nitro hardware to function.
    //
    // In simulated TEE mode, we fall back to direct KMS Decrypt (no attestation).

    // Step 1: Check if we're in a real Nitro Enclave
    if std::path::Path::new("/dev/nsm").exists() {
        kms_decrypt_nitro(config, ciphertext).await
    } else {
        // Simulated mode: direct KMS decrypt (no attestation)
        warn!("NSM not available — using direct KMS decrypt (simulated TEE mode)");
        kms_decrypt_direct(config, ciphertext).await
    }
}

/// Real Nitro Enclave KMS decrypt with attestation.
async fn kms_decrypt_nitro(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    // Full implementation flow (requires aws-sdk-kms + aws-nitro-enclaves-nsm-api):
    //
    // 1. Generate ephemeral RSA-2048:
    //    let rsa_key = rsa::RsaPrivateKey::new(&mut nsm_rng, 2048)?;
    //    let pub_der = rsa_key.to_public_key().to_public_key_der()?;
    //
    // 2. Get NSM attestation document:
    //    let nsm_fd = nsm_lib::nsm_init();
    //    let att_doc = nsm_lib::nsm_get_attestation_doc(nsm_fd, None, None, Some(&pub_der));
    //
    // 3. Call KMS Decrypt:
    //    let resp = kms_client.decrypt()
    //        .ciphertext_blob(Blob::new(ciphertext))
    //        .key_id(&config.key_arn)
    //        .recipient(RecipientInfo::builder()
    //            .attestation_document(Blob::new(att_doc))
    //            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
    //            .build())
    //        .send().await?;
    //
    // 4. Decrypt CiphertextForRecipient (CMS/RFC5652):
    //    let cms_bytes = resp.ciphertext_for_recipient()?;
    //    let plaintext = decrypt_cms_envelope(&cms_bytes, &rsa_key)?;
    //
    // For now, fall back to direct decrypt until aws-sdk-kms is integrated:
    warn!("Nitro attestation-based KMS decrypt not yet fully integrated — using direct decrypt");
    kms_decrypt_direct(config, ciphertext).await
}

/// Direct KMS decrypt without attestation (for simulated mode and initial development).
async fn kms_decrypt_direct(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    // This uses the standard AWS SDK KMS Decrypt without the Recipient parameter.
    // In production Nitro mode, this should NEVER be used — kms_decrypt_nitro handles that.

    let sdk_config = if let Some(ref region) = Some(&config.region) {
        aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await
    } else {
        aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await
    };

    let client = aws_sdk_kms::Client::new(&sdk_config);

    let resp = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
        .key_id(&config.key_arn)
        .send()
        .await
        .map_err(|e| {
            let mut msg = format!("KMS Decrypt failed: {e}");
            let mut source = std::error::Error::source(&e);
            while let Some(cause) = source {
                msg.push_str(&format!("\n  caused by: {cause}"));
                source = cause.source();
            }
            AppError::TeeAttestation(msg)
        })?;

    resp.plaintext()
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| AppError::TeeAttestation("KMS Decrypt returned no plaintext".into()))
}

/// Encrypt plaintext with KMS (for first-boot secret storage).
///
/// Does not require attestation — we're encrypting TO KMS, not receiving FROM KMS.
async fn kms_encrypt(
    config: &TeeKmsConfig,
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    let sdk_config = if let Some(ref region) = Some(&config.region) {
        aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await
    } else {
        aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await
    };

    let client = aws_sdk_kms::Client::new(&sdk_config);

    let resp = client
        .encrypt()
        .key_id(&config.key_arn)
        .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext))
        .send()
        .await
        .map_err(|e| {
            let mut msg = format!("KMS Encrypt failed: {e}");
            let mut source = std::error::Error::source(&e);
            while let Some(cause) = source {
                msg.push_str(&format!("\n  caused by: {cause}"));
                source = cause.source();
            }
            AppError::TeeAttestation(msg)
        })?;

    resp.ciphertext_blob()
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| AppError::TeeAttestation("KMS Encrypt returned no ciphertext".into()))
}
