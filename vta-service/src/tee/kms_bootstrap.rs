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
use crate::error::{AppError, tee_attestation_error};

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


/// Bootstrap secrets from KMS.
///
/// - If ciphertext files exist: decrypt via KMS, verify JWT fingerprint (subsequent boot)
/// - If no ciphertext files: generate new secrets, encrypt with KMS, store ciphertext + fingerprint (first boot)
/// Well-known keys in the bootstrap keyspace (no encryption — data is KMS-encrypted).
const BOOTSTRAP_SEED_CT_KEY: &str = "bootstrap:seed_ciphertext";
const BOOTSTRAP_JWT_CT_KEY: &str = "bootstrap:jwt_ciphertext";
const BOOTSTRAP_JWT_FINGERPRINT_KEY: &str = "bootstrap:jwt_fingerprint";

pub async fn bootstrap_secrets(
    kms_config: &TeeKmsConfig,
    storage_key_salt: &str,
    store: &crate::store::Store,
) -> Result<BootstrappedSecrets, AppError> {
    // Bootstrap keyspace — no encryption (ciphertexts are already KMS-encrypted)
    let bs_ks = store.keyspace("bootstrap")?;

    let seed: Vec<u8>;
    let jwt_key: [u8; 32];

    let seed_ct = bs_ks.get_raw(BOOTSTRAP_SEED_CT_KEY).await?;
    let jwt_ct = bs_ks.get_raw(BOOTSTRAP_JWT_CT_KEY).await?;

    if let (Some(seed_ciphertext), Some(jwt_ciphertext)) = (seed_ct, jwt_ct) {
        // ── Subsequent boot: decrypt existing ciphertexts ──
        info!("found existing secret ciphertexts in store — decrypting via KMS");

        seed = kms_decrypt(kms_config, &seed_ciphertext).await?;
        let jwt_bytes = kms_decrypt(kms_config, &jwt_ciphertext).await?;
        jwt_key = jwt_bytes.try_into().map_err(|_| {
            tee_attestation_error("JWT key must be exactly 32 bytes")
        })?;

        // Verify JWT key fingerprint (tamper detection)
        verify_jwt_fingerprint(&bs_ks, &jwt_key).await?;

        info!("secrets decrypted from KMS — subsequent boot");
    } else {
        // ── First boot: generate new secrets inside the TEE ──
        info!("no existing ciphertexts found — first boot, generating new secrets in TEE");

        let mut entropy = [0u8; 32];
        rand::fill(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| tee_attestation_error(format!("failed to generate mnemonic: {e}")))?;

        info!("first boot — master seed generated inside TEE (mnemonic NOT displayed)");
        info!("to export the mnemonic, restart with VTA_MNEMONIC_EXPORT_WINDOW=<seconds>");

        seed = mnemonic.to_seed("").to_vec();
        let seed = seed[..32].to_vec();

        let mut jwt_key_bytes = [0u8; 32];
        rand::fill(&mut jwt_key_bytes);
        jwt_key = jwt_key_bytes;

        // Encrypt with KMS and store ciphertexts in the bootstrap keyspace
        let seed_ciphertext = kms_encrypt(kms_config, &seed).await?;
        let jwt_ciphertext = kms_encrypt(kms_config, &jwt_key).await?;

        bs_ks.insert_raw(BOOTSTRAP_SEED_CT_KEY, seed_ciphertext).await?;
        bs_ks.insert_raw(BOOTSTRAP_JWT_CT_KEY, jwt_ciphertext).await?;
        store_jwt_fingerprint(&bs_ks, &jwt_key).await?;

        // Flush to ensure ciphertexts survive if the enclave crashes during startup
        store.persist().await?;

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

// ---------------------------------------------------------------------------
// JWT key fingerprint (tamper detection)
// ---------------------------------------------------------------------------

/// Store the JWT key fingerprint in the bootstrap keyspace.
async fn store_jwt_fingerprint(
    bs_ks: &crate::store::KeyspaceHandle,
    key: &[u8; 32],
) -> Result<(), AppError> {
    let fingerprint = jwt_fingerprint(key);
    bs_ks.insert_raw(BOOTSTRAP_JWT_FINGERPRINT_KEY, fingerprint.as_bytes().to_vec()).await?;
    debug!(fingerprint = %fingerprint, "JWT key fingerprint stored");
    Ok(())
}

/// Verify the JWT key matches the stored fingerprint.
async fn verify_jwt_fingerprint(
    bs_ks: &crate::store::KeyspaceHandle,
    key: &[u8; 32],
) -> Result<(), AppError> {
    let stored_bytes = match bs_ks.get_raw(BOOTSTRAP_JWT_FINGERPRINT_KEY).await? {
        Some(bytes) => bytes,
        None => {
            warn!("no JWT fingerprint found — storing one now (first boot after upgrade)");
            return store_jwt_fingerprint(bs_ks, key).await;
        }
    };

    let stored = String::from_utf8_lossy(&stored_bytes);
    let computed = jwt_fingerprint(key);

    if stored.trim() != computed {
        error!(
            stored = %stored.trim(),
            computed = %computed,
            "JWT key fingerprint MISMATCH — possible key tampering or KMS key rotation"
        );
        return Err(tee_attestation_error(
            "JWT key fingerprint mismatch — the decrypted JWT key does not match the key \
             used on first boot. This could indicate tampering with the ciphertext \
             or a KMS key change. If this is intentional (e.g., disaster recovery), \
             clear the bootstrap keyspace and restart.",
        ));
    }

    debug!(fingerprint = %computed, "JWT key fingerprint verified");
    Ok(())
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
/// On real Nitro hardware (`/dev/nsm` available), uses attestation-based
/// KMS Decrypt with the `Recipient` parameter: KMS re-encrypts the
/// plaintext to an ephemeral RSA key bound to the enclave's NSM attestation
/// document, preventing even the parent EC2 instance from reading the
/// response on the vsock channel.
///
/// Falls back to direct KMS Decrypt if attestation fails (with a warning).
async fn kms_decrypt(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    if std::path::Path::new("/dev/nsm").exists() {
        match kms_decrypt_attested(config, ciphertext).await {
            Ok(plaintext) => {
                info!("KMS Decrypt succeeded with Nitro attestation (Recipient parameter)");
                return Ok(plaintext);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "attestation-based KMS Decrypt failed — falling back to direct Decrypt"
                );
            }
        }
    }

    kms_decrypt_direct(config, ciphertext).await
}

/// KMS Decrypt with Nitro attestation via the Recipient parameter.
///
/// Flow:
/// 1. Generate ephemeral RSA-2048 keypair
/// 2. Get NSM attestation document binding the RSA public key
/// 3. Call KMS Decrypt with Recipient (attestation doc + key algorithm)
/// 4. KMS returns CiphertextForRecipient (CMS EnvelopedData, RFC 5652)
/// 5. Unwrap CMS envelope: RSA-OAEP-SHA256 decrypt the CEK, AES-GCM decrypt the content
async fn kms_decrypt_attested(
    config: &TeeKmsConfig,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    use rsa::pkcs8::EncodePublicKey;

    // 1. Generate ephemeral RSA-2048 keypair
    //    rsa 0.9 re-exports rand_core 0.6; use its OsRng for compatibility
    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|e| {
        tee_attestation_error(format!("RSA key generation failed: {e}"))
    })?;

    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| {
            tee_attestation_error(format!("RSA public key DER encoding failed: {e}"))
        })?;

    debug!(
        pubkey_der_len = public_key_der.as_ref().len(),
        "generated ephemeral RSA-2048 keypair for KMS Recipient"
    );

    // 2. Get NSM attestation document with the RSA public key embedded
    let attestation_doc =
        super::nitro::request_nsm_attestation_for_kms(public_key_der.as_ref())?;

    debug!(
        attestation_doc_len = attestation_doc.len(),
        "obtained NSM attestation document with embedded public key"
    );

    // 3. Call KMS Decrypt with Recipient parameter
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;

    let client = aws_sdk_kms::Client::new(&sdk_config);

    let recipient = aws_sdk_kms::types::RecipientInfo::builder()
        .attestation_document(aws_sdk_kms::primitives::Blob::new(attestation_doc))
        .key_encryption_algorithm(
            aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256,
        )
        .build();

    let resp = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
        .key_id(&config.key_arn)
        .recipient(recipient)
        .send()
        .await
        .map_err(|e| classify_kms_error("Decrypt(attested)", e))?;

    // 4. Extract CiphertextForRecipient (CMS envelope)
    //    When Recipient is provided, KMS returns CiphertextForRecipient instead of Plaintext
    let cms_bytes = resp
        .ciphertext_for_recipient()
        .ok_or_else(|| {
            tee_attestation_error(
                "KMS response missing CiphertextForRecipient — \
                 the KMS key may not support attestation-based decryption",
            )
        })?;

    debug!(
        cms_len = cms_bytes.as_ref().len(),
        "received CMS envelope from KMS"
    );

    // 5. Unwrap the CMS EnvelopedData to recover the plaintext
    decrypt_cms_envelope(cms_bytes.as_ref(), &private_key)
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
        .ok_or_else(|| tee_attestation_error("KMS Decrypt returned no plaintext"))
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
        .ok_or_else(|| tee_attestation_error("KMS Encrypt returned no ciphertext"))
}

// ---------------------------------------------------------------------------
// CMS EnvelopedData decryption (RFC 5652)
// ---------------------------------------------------------------------------

/// Decrypt a CMS EnvelopedData envelope returned by KMS CiphertextForRecipient.
///
/// KMS produces a CMS EnvelopedData (RFC 5652) with:
/// - One `KeyTransRecipientInfo` containing the CEK encrypted with RSA-OAEP-SHA256
/// - `EncryptedContentInfo` with AES-256-GCM encrypted plaintext
///
/// We parse the DER structure manually (the format from KMS is fixed), unwrap the
/// CEK with the ephemeral RSA private key, then decrypt the content with AES-256-GCM.
fn decrypt_cms_envelope(
    cms_bytes: &[u8],
    private_key: &rsa::RsaPrivateKey,
) -> Result<Vec<u8>, AppError> {
    // Parse the CMS EnvelopedData to extract the three fields we need
    let fields = cms_der::parse_enveloped_data(cms_bytes)?;

    // RSA-OAEP-SHA256 decrypt the content-encryption key (CEK)
    use rsa::Oaep;
    let cek = private_key
        .decrypt(Oaep::new::<sha2::Sha256>(), &fields.encrypted_key)
        .map_err(|e| {
            tee_attestation_error(format!("RSA-OAEP decryption of CEK failed: {e}"))
        })?;

    debug!(cek_len = cek.len(), "decrypted content-encryption key from CMS envelope");

    // AES-GCM decrypt the content
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;

    if cek.len() != 32 {
        return Err(tee_attestation_error(format!(
            "unexpected CEK length: {} (expected 32 for AES-256)",
            cek.len()
        )));
    }

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));
    let nonce = GenericArray::from_slice(&fields.nonce);
    let plaintext = cipher
        .decrypt(nonce, fields.ciphertext.as_ref())
        .map_err(|e| {
            tee_attestation_error(format!("AES-GCM decryption of CMS content failed: {e}"))
        })?;

    debug!(plaintext_len = plaintext.len(), "CMS envelope decrypted successfully");
    Ok(plaintext)
}

/// Minimal DER parser for the CMS EnvelopedData structure from KMS.
///
/// Parses just enough ASN.1 to extract the encrypted CEK, AES-GCM nonce,
/// and ciphertext. No external DER/ASN.1 crate needed — the structure
/// from KMS is predictable and constrained.
mod cms_der {
    use crate::error::{AppError, tee_attestation_error};

    /// Parsed fields from a CMS EnvelopedData needed for decryption.
    pub(super) struct CmsFields {
        pub encrypted_key: Vec<u8>,
        pub nonce: Vec<u8>,
        pub ciphertext: Vec<u8>,
    }

    /// Parse a CMS ContentInfo → EnvelopedData and extract the three fields needed
    /// for decryption.
    ///
    /// ASN.1 structure (simplified):
    /// ```text
    /// ContentInfo ::= SEQUENCE {
    ///   contentType  OID (envelopedData)
    ///   content      [0] EXPLICIT EnvelopedData
    /// }
    /// EnvelopedData ::= SEQUENCE {
    ///   version          INTEGER
    ///   recipientInfos   SET { KeyTransRecipientInfo SEQUENCE {
    ///     version          INTEGER
    ///     rid              RecipientIdentifier
    ///     keyEncAlg        AlgorithmIdentifier
    ///     encryptedKey     OCTET STRING
    ///   }}
    ///   encryptedContentInfo SEQUENCE {
    ///     contentType      OID
    ///     contentEncAlg    SEQUENCE { OID, SEQUENCE { nonce OCTET STRING, ... } }
    ///     encryptedContent [0] IMPLICIT OCTET STRING
    ///   }
    /// }
    /// ```
    pub(super) fn parse_enveloped_data(data: &[u8]) -> Result<CmsFields, AppError> {
        let mut pos = 0;

        // ContentInfo SEQUENCE
        let (_, ci_body) = read_tlv(data, &mut pos, "ContentInfo")?;

        let mut ci_pos = 0;
        // contentType OID — skip
        let _ = read_tlv(&ci_body, &mut ci_pos, "contentType OID")?;
        // content [0] EXPLICIT
        let (_, ctx0_body) = read_tlv(&ci_body, &mut ci_pos, "[0] content")?;

        // EnvelopedData SEQUENCE
        let mut env_pos = 0;
        let (_, env_body) = read_tlv(&ctx0_body, &mut env_pos, "EnvelopedData")?;

        let mut ed_pos = 0;
        // version INTEGER — skip
        let _ = read_tlv(&env_body, &mut ed_pos, "EnvelopedData version")?;
        // recipientInfos SET
        let (_, ri_set) = read_tlv(&env_body, &mut ed_pos, "recipientInfos SET")?;
        // encryptedContentInfo SEQUENCE
        let (_, eci_body) = read_tlv(&env_body, &mut ed_pos, "encryptedContentInfo")?;

        // Parse KeyTransRecipientInfo (first element in SET)
        let encrypted_key = parse_key_trans_ri(&ri_set)?;

        // Parse EncryptedContentInfo
        let (nonce, ciphertext) = parse_encrypted_content_info(&eci_body)?;

        Ok(CmsFields {
            encrypted_key,
            nonce,
            ciphertext,
        })
    }

    fn parse_key_trans_ri(set_data: &[u8]) -> Result<Vec<u8>, AppError> {
        let mut pos = 0;
        // KeyTransRecipientInfo SEQUENCE
        let (_, ktri_body) = read_tlv(set_data, &mut pos, "KeyTransRI")?;

        let mut kp = 0;
        // version INTEGER — skip
        let _ = read_tlv(&ktri_body, &mut kp, "KeyTransRI version")?;
        // rid (RecipientIdentifier) — skip
        let _ = read_tlv(&ktri_body, &mut kp, "KeyTransRI rid")?;
        // keyEncryptionAlgorithm — skip
        let _ = read_tlv(&ktri_body, &mut kp, "KeyTransRI keyEncAlg")?;
        // encryptedKey OCTET STRING
        let (_, ek_value) = read_tlv(&ktri_body, &mut kp, "encryptedKey")?;

        Ok(ek_value.to_vec())
    }

    fn parse_encrypted_content_info(
        eci_data: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        let mut pos = 0;
        // contentType OID — skip
        let _ = read_tlv(eci_data, &mut pos, "ECI contentType")?;
        // contentEncryptionAlgorithm SEQUENCE
        let (_, alg_body) = read_tlv(eci_data, &mut pos, "ECI algorithm")?;
        // encryptedContent [0] IMPLICIT OCTET STRING
        let (_, ct_value) = read_tlv(eci_data, &mut pos, "encryptedContent")?;

        // Parse algorithm to get the GCM nonce
        let nonce = parse_aes_gcm_params(&alg_body)?;

        Ok((nonce, ct_value.to_vec()))
    }

    fn parse_aes_gcm_params(alg_data: &[u8]) -> Result<Vec<u8>, AppError> {
        let mut pos = 0;
        // algorithm OID — skip
        let _ = read_tlv(alg_data, &mut pos, "algorithm OID")?;
        // parameters: GCMParameters SEQUENCE
        let (_, params_body) = read_tlv(alg_data, &mut pos, "GCM parameters")?;

        let mut pp = 0;
        // nonce OCTET STRING
        let (_, nonce_value) = read_tlv(&params_body, &mut pp, "GCM nonce")?;

        Ok(nonce_value.to_vec())
    }

    /// Read a DER TLV (tag-length-value) at the given position.
    ///
    /// Returns (tag_byte, value_bytes) and advances `pos` past the TLV.
    /// The value_bytes is the content after the tag+length header.
    fn read_tlv<'a>(
        data: &'a [u8],
        pos: &mut usize,
        context: &str,
    ) -> Result<(u8, &'a [u8]), AppError> {
        if *pos >= data.len() {
            return Err(tee_attestation_error(format!(
                "CMS: unexpected end of data reading {context}"
            )));
        }

        let tag = data[*pos];
        *pos += 1;

        // Read length
        if *pos >= data.len() {
            return Err(tee_attestation_error(format!(
                "CMS: truncated length for {context}"
            )));
        }

        let first_len = data[*pos];
        *pos += 1;

        let len: usize = if first_len < 0x80 {
            // Short form: length in single byte
            first_len as usize
        } else if first_len == 0x80 {
            return Err(tee_attestation_error(format!(
                "CMS: indefinite length not supported for {context}"
            )));
        } else {
            // Long form: first_len & 0x7F = number of length bytes
            let num_bytes = (first_len & 0x7F) as usize;
            if *pos + num_bytes > data.len() {
                return Err(tee_attestation_error(format!(
                    "CMS: truncated length bytes for {context}"
                )));
            }
            let mut len: usize = 0;
            for i in 0..num_bytes {
                len = (len << 8) | (data[*pos + i] as usize);
            }
            *pos += num_bytes;
            len
        };

        if *pos + len > data.len() {
            return Err(tee_attestation_error(format!(
                "CMS: value overflows buffer for {context} (need {len} bytes at offset {pos}, have {})",
                data.len()
            )));
        }

        let value = &data[*pos..*pos + len];
        *pos += len;

        Ok((tag, value))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_read_tlv_short_form() {
            // OCTET STRING, length 3, value [0x01, 0x02, 0x03]
            let data = [0x04, 0x03, 0x01, 0x02, 0x03];
            let mut pos = 0;
            let (tag, value) = read_tlv(&data, &mut pos, "test").unwrap();
            assert_eq!(tag, 0x04);
            assert_eq!(value, &[0x01, 0x02, 0x03]);
            assert_eq!(pos, 5);
        }

        #[test]
        fn test_read_tlv_long_form() {
            // OCTET STRING, length 128 (0x81 0x80), then 128 bytes of 0xAA
            let mut data = vec![0x04, 0x81, 0x80];
            data.extend_from_slice(&[0xAA; 128]);
            let mut pos = 0;
            let (tag, value) = read_tlv(&data, &mut pos, "test").unwrap();
            assert_eq!(tag, 0x04);
            assert_eq!(value.len(), 128);
            assert_eq!(pos, 131);
        }

        #[test]
        fn test_read_tlv_truncated() {
            let data = [0x04, 0x05, 0x01]; // claims 5 bytes but only 1
            let mut pos = 0;
            assert!(read_tlv(&data, &mut pos, "test").is_err());
        }
    }
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
    tee_attestation_error(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic CMS EnvelopedData that mimics what KMS returns
    /// with CiphertextForRecipient. This allows us to test the full
    /// decrypt_cms_envelope round-trip without needing real KMS or NSM.
    #[test]
    fn test_cms_envelope_roundtrip() {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use aes_gcm::aead::generic_array::GenericArray;
        use rsa::{RsaPrivateKey, Oaep};
        use rsa::pkcs8::EncodePublicKey;

        // Generate RSA keypair (the "ephemeral" key the enclave would create)
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        // The plaintext KMS would return (e.g., a 32-byte seed)
        let original_plaintext = b"this is a secret seed value!!!!!"; // 32 bytes

        // Generate random AES-256 CEK and GCM nonce
        let mut cek = [0u8; 32];
        rand::fill(&mut cek);
        let mut nonce_bytes = [0u8; 12];
        rand::fill(&mut nonce_bytes);

        // AES-GCM encrypt the plaintext
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let aes_ciphertext = cipher.encrypt(nonce, original_plaintext.as_ref()).unwrap();

        // RSA-OAEP-SHA256 encrypt the CEK
        let encrypted_cek = private_key
            .to_public_key()
            .encrypt(&mut rng, Oaep::new::<sha2::Sha256>(), &cek)
            .unwrap();

        // Build the CMS EnvelopedData DER structure
        let cms_bytes = build_test_cms_envelope(&encrypted_cek, &nonce_bytes, &aes_ciphertext);

        // Now decrypt it using our implementation
        let recovered = decrypt_cms_envelope(&cms_bytes, &private_key).unwrap();

        assert_eq!(recovered, original_plaintext);
    }

    /// Construct a minimal CMS ContentInfo/EnvelopedData DER structure.
    fn build_test_cms_envelope(
        encrypted_cek: &[u8],
        nonce: &[u8],
        aes_ciphertext: &[u8],
    ) -> Vec<u8> {
        // OID for envelopedData: 1.2.840.113549.1.7.3
        let enveloped_data_oid = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
        ];

        // OID for data: 1.2.840.113549.1.7.1
        let data_oid = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];

        // OID for AES-256-GCM: 2.16.840.1.101.3.4.1.46
        let aes_256_gcm_oid = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E,
        ];

        // OID for RSAES-OAEP: 1.2.840.113549.1.1.7
        let rsaes_oaep_oid = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07,
        ];

        // GCMParameters SEQUENCE { nonce OCTET STRING }
        let nonce_tlv = der_octet_string(nonce);
        let gcm_params = der_sequence(&nonce_tlv);

        // AlgorithmIdentifier SEQUENCE { OID, GCMParameters }
        let mut alg_id_content = Vec::new();
        alg_id_content.extend_from_slice(aes_256_gcm_oid);
        alg_id_content.extend_from_slice(&gcm_params);
        let alg_id = der_sequence(&alg_id_content);

        // encryptedContent [0] IMPLICIT OCTET STRING
        let encrypted_content = der_context_implicit(0, aes_ciphertext);

        // EncryptedContentInfo SEQUENCE
        let mut eci_content = Vec::new();
        eci_content.extend_from_slice(data_oid);
        eci_content.extend_from_slice(&alg_id);
        eci_content.extend_from_slice(&encrypted_content);
        let eci = der_sequence(&eci_content);

        // Fake RecipientIdentifier (IssuerAndSerialNumber — minimal)
        let fake_rid = der_sequence(&[0x30, 0x00, 0x02, 0x01, 0x01]); // SEQUENCE{SEQUENCE{}, INTEGER 1}

        // KeyEncryptionAlgorithm (RSAES-OAEP — simplified, just OID)
        let key_enc_alg = der_sequence(rsaes_oaep_oid);

        // KeyTransRecipientInfo SEQUENCE
        let mut ktri_content = Vec::new();
        ktri_content.extend_from_slice(&[0x02, 0x01, 0x00]); // version INTEGER 0
        ktri_content.extend_from_slice(&fake_rid);
        ktri_content.extend_from_slice(&key_enc_alg);
        ktri_content.extend_from_slice(&der_octet_string(encrypted_cek));
        let ktri = der_sequence(&ktri_content);

        // RecipientInfos SET
        let ri_set = der_set(&ktri);

        // EnvelopedData SEQUENCE
        let mut env_content = Vec::new();
        env_content.extend_from_slice(&[0x02, 0x01, 0x00]); // version INTEGER 0
        env_content.extend_from_slice(&ri_set);
        env_content.extend_from_slice(&eci);
        let enveloped_data = der_sequence(&env_content);

        // [0] EXPLICIT EnvelopedData
        let ctx0 = der_context_explicit(0, &enveloped_data);

        // ContentInfo SEQUENCE
        let mut ci_content = Vec::new();
        ci_content.extend_from_slice(enveloped_data_oid);
        ci_content.extend_from_slice(&ctx0);
        der_sequence(&ci_content)
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        der_tlv(0x30, content)
    }

    fn der_set(content: &[u8]) -> Vec<u8> {
        der_tlv(0x31, content)
    }

    fn der_octet_string(content: &[u8]) -> Vec<u8> {
        der_tlv(0x04, content)
    }

    fn der_context_explicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
        der_tlv(0xA0 | tag_num, content) // constructed context-specific
    }

    fn der_context_implicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
        der_tlv(0x80 | tag_num, content) // primitive context-specific
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut buf = vec![tag];
        let len = content.len();
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else if len < 0x10000 {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        } else {
            buf.push(0x83);
            buf.push((len >> 16) as u8);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
        buf.extend_from_slice(content);
        buf
    }

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
