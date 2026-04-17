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
use serde::{Deserialize, Serialize};
use vta_sdk::attestation::verify_nitro_assertion;
use vta_sdk::sealed_transfer::{
    BootstrapRequest, SealedPayloadV1, armor, bundle_digest, generate_keypair, open_bundle,
};

use crate::auth;
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

// ── online flow (Mode A) ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct BootstrapRequestWire {
    version: u8,
    client_pubkey: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BootstrapResponseWire {
    bundle: String,
    digest: String,
}

/// `pnm bootstrap connect --vta-url <URL> --token <TOKEN> [--expect-digest <HEX>]`
///
/// One-command online bootstrap against a running VTA. Generates an ephemeral
/// keypair, POSTs to `/bootstrap/request` with the supplied token, opens the
/// returned sealed bundle, installs the minted credential via `pnm auth
/// login`, and registers the VTA under a slug in `pnm` config.
pub async fn run_connect(
    vta_url: String,
    token: Option<String>,
    expect_digest: Option<String>,
    vta_slug: Option<String>,
    pnm_config: &mut crate::config::PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let (secret, public) = generate_keypair();
    let nonce: [u8; 16] = rand::random();
    let bundle_id_hex = hex_lower(&nonce);
    let is_mode_b = token.is_none();

    let body = BootstrapRequestWire {
        version: 1,
        client_pubkey: B64URL.encode(public),
        nonce: B64URL.encode(nonce),
        token,
        label: None,
    };

    let url = format!("{}/bootstrap/request", vta_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&body).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("bootstrap request failed ({status}): {body}").into());
    }
    let wire: BootstrapResponseWire = resp.json().await?;

    // Optional client-side digest verification. The token + TLS give the
    // primary integrity anchor; this is a belt-and-suspenders check the
    // operator can opt into by communicating the digest out-of-band at
    // token-issue time.
    if let Some(expected) = &expect_digest {
        if expected.to_ascii_lowercase() != wire.digest.to_ascii_lowercase() {
            return Err(format!(
                "server-reported digest {} does not match expected {}",
                wire.digest, expected
            )
            .into());
        }
    }

    let bundles = armor::decode(&wire.bundle)?;
    if bundles.len() != 1 {
        return Err(format!(
            "expected exactly one armored bundle from server, got {}",
            bundles.len()
        )
        .into());
    }
    let bundle = &bundles[0];
    if hex_lower(&bundle.bundle_id) != bundle_id_hex {
        return Err("server-returned bundle_id does not match our nonce".into());
    }

    let opened = open_bundle(&secret, bundle, expect_digest.as_deref())?;

    if is_mode_b {
        let attest = verify_nitro_assertion(&opened.producer, &public, &nonce)?;
        println!("Mode B attestation verified.");
        println!("  Enclave module: {}", attest.module_id);
        if !attest.pcr0_hex.is_empty() {
            println!("  PCR0:           {}", attest.pcr0_hex);
        }
        if !attest.pcr8_hex.is_empty() {
            println!("  PCR8:           {}", attest.pcr8_hex);
        }
    }

    let credential = match opened.payload {
        SealedPayloadV1::AdminCredential(c) => c,
        other => {
            return Err(format!(
                "expected AdminCredential payload from online bootstrap, got {}",
                variant_name(&other)
            )
            .into());
        }
    };

    let encoded = credential.encode()?;

    let slug = vta_slug.unwrap_or_else(|| default_slug(&credential.vta_did));
    pnm_config.vtas.insert(
        slug.clone(),
        crate::config::VtaConfig {
            name: slug.clone(),
            url: Some(vta_url.clone()),
            vta_did: Some(credential.vta_did.clone()),
        },
    );
    if pnm_config.default_vta.is_none() {
        pnm_config.default_vta = Some(slug.clone());
    }
    crate::config::save_config(pnm_config)?;

    let keyring_key = crate::config::vta_keyring_key(&slug);
    auth::login(&encoded, &vta_url, &keyring_key).await?;

    println!();
    println!("Bootstrap complete.");
    println!("  VTA slug:   {slug}");
    println!("  Client DID: {}", credential.did);
    println!("  VTA DID:    {}", credential.vta_did);
    println!("  Digest:     {}", bundle_digest(bundle));
    Ok(())
}

fn variant_name(p: &SealedPayloadV1) -> &'static str {
    match p {
        SealedPayloadV1::AdminCredential(_) => "AdminCredential",
        SealedPayloadV1::ContextProvision(_) => "ContextProvision",
        SealedPayloadV1::DidSecrets(_) => "DidSecrets",
        SealedPayloadV1::AdminKeySet(_) => "AdminKeySet",
    }
}

fn default_slug(vta_did: &str) -> String {
    vta_did.rsplit(':').next().unwrap_or("vta").to_string()
}
