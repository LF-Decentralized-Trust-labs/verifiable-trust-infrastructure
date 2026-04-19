//! CLI-side consumer helpers for `vta_sdk::sealed_transfer`.
//!
//! Generates ephemeral X25519 keypairs and persists the secret under
//! `<config_dir>/bootstrap-secrets/<bundle_id>.key` (mode 0600 on Unix) so a
//! subsequent open call can retrieve it.
//!
//! The pnm-cli and cnm-cli bootstrap subcommands both route through this
//! module — the only per-CLI concern is which `config_dir` to use.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use vta_sdk::credentials::CredentialBundle;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, bundle_digest, generate_keypair, open_bundle,
};

const SECRETS_SUBDIR: &str = "bootstrap-secrets";

/// Resolve the per-config bootstrap secrets directory, creating it on first
/// use with 0700 permissions on Unix.
pub fn secrets_dir(config_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = config_dir.join(SECRETS_SUBDIR);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            let mut perm = fs::metadata(&dir)?.permissions();
            perm.set_mode(0o700);
            fs::set_permissions(&dir, perm)?;
        }
    }
    Ok(dir)
}

fn secret_path(
    config_dir: &Path,
    bundle_id_hex: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(secrets_dir(config_dir)?.join(format!("{bundle_id_hex}.key")))
}

fn write_secret(path: &Path, secret: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(path)?;
    file.write_all(secret)?;
    Ok(())
}

fn read_secret(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("secret file {} is not 32 bytes", path.display()).into())
}

/// The outcome of [`create_bootstrap_request`]: the serialized request body
/// and the bundle id (for the "secret stored at <path>" banner).
pub struct CreatedRequest {
    pub request: BootstrapRequest,
    pub bundle_id_hex: String,
    pub secret_path: PathBuf,
}

/// Generate a fresh keypair + nonce, persist the secret under `config_dir`,
/// and return a [`BootstrapRequest`] ready to hand to the producer.
pub fn create_bootstrap_request(
    config_dir: &Path,
    label: Option<String>,
) -> Result<CreatedRequest, Box<dyn std::error::Error>> {
    let (secret, public) = generate_keypair();
    let nonce: [u8; 16] = rand::random();
    let bundle_id_hex = hex_lower(&nonce);
    let sp = secret_path(config_dir, &bundle_id_hex)?;
    write_secret(&sp, &secret)?;
    let request = BootstrapRequest::new(public, nonce, label);
    Ok(CreatedRequest {
        request,
        bundle_id_hex,
        secret_path: sp,
    })
}

/// The result of [`open_armored_bundle`] — the full sealed payload plus the
/// producer assertion, ready for caller-specific trust verification.
#[derive(Debug)]
pub struct OpenedArmored {
    pub payload: SealedPayloadV1,
    pub producer: vta_sdk::sealed_transfer::ProducerAssertion,
    pub bundle_id: [u8; 16],
    pub bundle_id_hex: String,
    pub digest: String,
}

/// Read an armored sealed bundle from `bundle_path`, load the corresponding
/// secret from `config_dir`, open and verify. The caller is responsible for
/// passing an `expect_digest` unless `no_verify_digest` is set.
///
/// Best-effort removal of the used secret file on success — the bundle id is
/// single-use, and keeping the secret around only widens blast radius.
pub fn open_armored_bundle(
    bundle_path: &Path,
    config_dir: &Path,
    expect_digest: Option<&str>,
    no_verify_digest: bool,
) -> Result<OpenedArmored, Box<dyn std::error::Error>> {
    if expect_digest.is_none() && !no_verify_digest {
        return Err(
            "--expect-digest <hex> is required (or pass --no-verify-digest to opt out)".into(),
        );
    }

    let armored = fs::read_to_string(bundle_path)
        .map_err(|e| format!("read {}: {e}", bundle_path.display()))?;
    let bundles = armor::decode(&armored)?;
    if bundles.len() != 1 {
        return Err(format!(
            "expected exactly one bundle in {}, found {}",
            bundle_path.display(),
            bundles.len()
        )
        .into());
    }
    let bundle = &bundles[0];
    let bundle_id_hex = hex_lower(&bundle.bundle_id);

    let sp = secret_path(config_dir, &bundle_id_hex)?;
    if !sp.exists() {
        return Err(format!(
            "no stored secret for bundle_id {bundle_id_hex} (expected at {}). \
             Did you run `bootstrap request` on this host?",
            sp.display()
        )
        .into());
    }
    let secret = read_secret(&sp)?;

    let digest = bundle_digest(bundle);
    let opened = open_bundle(&secret, bundle, expect_digest)?;

    // Best-effort cleanup. If the caller later fails, the secret is gone —
    // that's fine because the bundle id is single-use anyway; a retry would
    // need a fresh request.
    if let Err(e) = fs::remove_file(&sp) {
        eprintln!(
            "warning: could not remove used secret {}: {e}",
            sp.display()
        );
    }

    Ok(OpenedArmored {
        payload: opened.payload,
        producer: opened.producer,
        bundle_id: opened.bundle_id,
        bundle_id_hex,
        digest,
    })
}

/// Extract the [`CredentialBundle`] from an opened payload.
///
/// Accepts `AdminCredential` directly and `ContextProvision` (unwrapping the
/// inner admin credential) — both are "install an admin identity" flows for a
/// consumer. Other variants are rejected with a descriptive error.
pub fn extract_admin_credential(
    payload: SealedPayloadV1,
) -> Result<CredentialBundle, Box<dyn std::error::Error>> {
    match payload {
        SealedPayloadV1::AdminCredential(c) => Ok(c),
        SealedPayloadV1::ContextProvision(p) => Ok(p.credential),
        SealedPayloadV1::DidSecrets(_) => Err(
            "cannot install a DidSecrets bundle as an admin credential — use `bootstrap open` to inspect it"
                .into(),
        ),
        SealedPayloadV1::AdminKeySet(_) => Err(
            "cannot install an AdminKeySet bundle as an admin credential — use `bootstrap open` to inspect it"
                .into(),
        ),
        SealedPayloadV1::RawPrivateKey(_) => Err(
            "cannot install a RawPrivateKey bundle as an admin credential".into(),
        ),
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_producer::{SealedRecipient, seal_for_recipient};

    #[test]
    fn secrets_dir_creates_when_missing() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));
        let dir = secrets_dir(&tmp).unwrap();
        assert!(dir.exists());
        assert!(dir.ends_with("bootstrap-secrets"));
        // Clean up — test only uses the dir once.
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn create_request_persists_secret() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));
        let req = create_bootstrap_request(&tmp, Some("unit-test".into())).unwrap();
        assert!(req.secret_path.exists());
        let bytes = fs::read(&req.secret_path).unwrap();
        assert_eq!(bytes.len(), 32);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn request_seal_open_round_trip() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));

        // Consumer: create request + persist secret.
        let created = create_bootstrap_request(&tmp, None).unwrap();

        // Producer: seal to the request's pubkey.
        let recipient =
            SealedRecipient::from_json_str(&serde_json::to_string(&created.request).unwrap())
                .unwrap();
        let payload =
            SealedPayloadV1::AdminCredential(vta_sdk::credentials::CredentialBundle::new(
                "did:key:z6Mk123",
                "z1234567890",
                "did:key:z6MkVTA",
            ));
        let sealed = seal_for_recipient(&recipient, &payload).await.unwrap();

        // Write armored to file.
        let bundle_path = tmp.join("bundle.armor");
        fs::write(&bundle_path, sealed.armored.as_bytes()).unwrap();

        // Consumer: open.
        let opened = open_armored_bundle(&bundle_path, &tmp, Some(&sealed.digest), false).unwrap();
        assert_eq!(opened.bundle_id, created.request.decode_nonce().unwrap());

        let cred = extract_admin_credential(opened.payload).unwrap();
        assert_eq!(cred.did, "did:key:z6Mk123");

        // Secret file is removed after successful open.
        assert!(!created.secret_path.exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn open_rejects_missing_digest_without_opt_out() {
        let tmp = std::env::temp_dir().join(format!("vta-test-{}", rand::random::<u32>()));
        fs::create_dir_all(&tmp).unwrap();
        let bundle_path = tmp.join("bundle.armor");
        fs::write(&bundle_path, b"armor placeholder").unwrap();
        let err = open_armored_bundle(&bundle_path, &tmp, None, false).unwrap_err();
        assert!(err.to_string().contains("expect-digest"));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn extract_rejects_did_secrets() {
        let payload = SealedPayloadV1::DidSecrets(vta_sdk::did_secrets::DidSecretsBundle {
            did: "did:key:z6Mk".into(),
            secrets: vec![],
        });
        let err = extract_admin_credential(payload).unwrap_err();
        assert!(err.to_string().contains("DidSecrets"));
    }

    #[test]
    fn extract_accepts_context_provision() {
        let payload =
            SealedPayloadV1::ContextProvision(vta_sdk::context_provision::ContextProvisionBundle {
                context_id: "app".into(),
                context_name: "App".into(),
                vta_url: None,
                vta_did: None,
                credential: vta_sdk::credentials::CredentialBundle::new(
                    "did:key:z6Mk123",
                    "z1234567890",
                    "did:key:z6MkVTA",
                ),
                admin_did: "did:key:z6Mk123".into(),
                did: None,
            });
        let cred = extract_admin_credential(payload).unwrap();
        assert_eq!(cred.did, "did:key:z6Mk123");
    }
}
