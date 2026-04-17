//! `pnm bootstrap` — sealed-transfer consumer commands.
//!
//! Phase 1 implements the offline (Mode C) consumer flow:
//!
//! - `pnm bootstrap request` generates a fresh X25519 keypair, persists the
//!   secret on disk under `~/.config/pnm/bootstrap-secrets/<bundle_id>.key`,
//!   and writes a `BootstrapRequest` JSON the operator can hand to the
//!   producer.
//! - `pnm bootstrap open` reads an armored sealed bundle, looks up the secret
//!   by bundle_id, opens it, prints the payload, and (for `AdminCredential`
//!   payloads) optionally hands off to `pnm auth login` so the new credential
//!   is installed in the keyring.
//!
//! `--expect-digest <hex>` is required by default. `--no-verify-digest` is
//! available but prints a warning — there is no silent TOFU.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, bundle_digest, generate_keypair, open_bundle,
};

use crate::config;

const SECRETS_SUBDIR: &str = "bootstrap-secrets";

fn secrets_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = config::config_dir()?.join(SECRETS_SUBDIR);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        // Restrict to owner; the directory itself reveals nothing but the
        // files inside contain raw 32-byte X25519 secrets.
        #[cfg(unix)]
        {
            let mut perm = fs::metadata(&dir)?.permissions();
            perm.set_mode(0o700);
            fs::set_permissions(&dir, perm)?;
        }
    }
    Ok(dir)
}

fn secret_path(bundle_id_hex: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(secrets_dir()?.join(format!("{bundle_id_hex}.key")))
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

fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0xf) as usize] as char);
    }
    s
}

/// `pnm bootstrap request --out <PATH> [--label <NAME>]`
pub async fn run_request(
    out: PathBuf,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (secret, public) = generate_keypair();
    let nonce: [u8; 16] = rand::random();
    let bundle_id_hex = hex_lower(&nonce);

    let path = secret_path(&bundle_id_hex)?;
    write_secret(&path, &secret)?;

    let request = BootstrapRequest::new(public, nonce, label);
    let json = serde_json::to_string_pretty(&request)?;
    fs::write(&out, json.as_bytes())?;

    println!("Bootstrap request written to {}", out.display());
    println!();
    println!("  Bundle-Id:     {bundle_id_hex}");
    println!("  Client pubkey: {}", B64URL.encode(public));
    println!("  Secret stored: {}", path.display());
    println!();
    println!("Hand the request to the producer. They will return an armored bundle.");
    println!("Verify the SHA-256 digest they print to you out-of-band, then run:");
    println!("  pnm bootstrap open --bundle <file> --expect-digest <hex>");
    Ok(())
}

/// `pnm bootstrap open --bundle <PATH> [--expect-digest <HEX>] [--no-verify-digest]`
pub async fn run_open(
    bundle_path: PathBuf,
    expect_digest: Option<String>,
    no_verify_digest: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if expect_digest.is_none() && !no_verify_digest {
        return Err(
            "--expect-digest <hex> is required (or pass --no-verify-digest to opt out)".into(),
        );
    }
    if no_verify_digest {
        eprintln!(
            "WARNING: --no-verify-digest disables out-of-band integrity verification.\n\
             You are trusting the producer pubkey embedded in the bundle without\n\
             any external anchor. Use only for testing."
        );
    }

    let armored = fs::read_to_string(&bundle_path)
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

    let secret_path = secret_path(&bundle_id_hex)?;
    if !secret_path.exists() {
        return Err(format!(
            "no stored secret for bundle_id {bundle_id_hex} (expected at {}). \
             Did you run `pnm bootstrap request` on this host?",
            secret_path.display()
        )
        .into());
    }
    let secret = read_secret(&secret_path)?;

    let opened = open_bundle(&secret, bundle, expect_digest.as_deref())?;

    println!("Sealed bundle opened.");
    println!();
    println!("  Bundle-Id:        {bundle_id_hex}");
    println!("  Digest (sha256):  {}", bundle_digest(bundle));
    println!(
        "  Producer pubkey:  {}",
        opened.producer.producer_pubkey_b64
    );
    println!("  Producer proof:   {:?}", opened.producer.proof);
    println!();
    match &opened.payload {
        SealedPayloadV1::AdminCredential(c) => {
            println!("Payload: AdminCredential");
            println!("  DID:     {}", c.did);
            println!("  VTA DID: {}", c.vta_did);
            if let Some(ref u) = c.vta_url {
                println!("  VTA URL: {u}");
            }
            println!();
            println!("To install this credential, run:");
            println!("  pnm auth login <base64-credential>");
            println!();
            println!("Encoded credential:");
            println!("  {}", c.encode()?);
        }
        SealedPayloadV1::ContextProvision(p) => {
            println!("Payload: ContextProvision");
            println!("  Context:   {} ({})", p.context_id, p.context_name);
            println!("  Admin DID: {}", p.admin_did);
        }
        SealedPayloadV1::DidSecrets(s) => {
            println!("Payload: DidSecrets");
            println!("  DID:     {}", s.did);
            println!("  Secrets: {}", s.secrets.len());
        }
        SealedPayloadV1::AdminKeySet(keys) => {
            println!("Payload: AdminKeySet ({} keys)", keys.len());
            for k in keys {
                println!("  - {}", k.label);
            }
        }
    }

    // Best-effort cleanup of the now-used secret. The bundle_id is single-use
    // by design; keeping the secret around offers no value and slightly
    // expands the blast radius if the host is later compromised.
    if let Err(e) = fs::remove_file(&secret_path) {
        eprintln!(
            "warning: could not remove used secret {}: {e}",
            secret_path.display()
        );
    }

    Ok(())
}
