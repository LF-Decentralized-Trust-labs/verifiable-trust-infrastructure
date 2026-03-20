use crate::error::AppError;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Encrypt plaintext with AES-256-GCM.
/// Output: `[12-byte random nonce][ciphertext + 16-byte auth tag]`
pub fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("AES key error: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Internal(format!("AES-GCM encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt AES-256-GCM encrypted value.
/// Input: `[12-byte nonce][ciphertext + 16-byte auth tag]`
fn decrypt_value(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, AppError> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::Internal(
            "encrypted value too short (missing nonce or auth tag)".into(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("AES key error: {e}")))?;

    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let ciphertext = &data[NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AppError::Internal(format!("AES-GCM decryption failed (data may be corrupt or key mismatch): {e}")))
}

/// Decrypt bytes if an encryption key is provided, otherwise return a copy.
pub fn maybe_decrypt_bytes(key: Option<&[u8; 32]>, data: &[u8]) -> Result<Vec<u8>, AppError> {
    match key {
        Some(k) => decrypt_value(k, data),
        None => Ok(data.to_vec()),
    }
}
