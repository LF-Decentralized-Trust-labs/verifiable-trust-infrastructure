//! `vta bootstrap` — sealed-transfer producer-side commands.
//!
//! - `seal` (Phase 1) — offline Mode-C: produce an armored bundle for a
//!   consumer's BootstrapRequest.
//! - `issue-token` / `list-tokens` / `revoke-token` (Phase 2) — operator
//!   lifecycle for `PendingBootstrap` entries that `POST /bootstrap/request`
//!   consumes on the online path.

use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use vta_sdk::sealed_transfer::{
    AssertionProof, BootstrapRequest, InMemoryNonceStore, ProducerAssertion, SealedPayloadV1,
    armor, bundle_digest, generate_keypair, seal_payload,
};

use crate::acl::{
    PendingBootstrap, Role, delete_pending_bootstrap, list_pending_bootstraps,
    store_pending_bootstrap,
};
use crate::config::AppConfig;
use crate::store::Store;

/// Seal a payload to a consumer's BootstrapRequest (Mode C, offline).
pub async fn run_seal(
    request_path: PathBuf,
    payload_path: PathBuf,
    out_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_json = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("parse BootstrapRequest: {e}"))?;
    if request.version != 1 {
        return Err(format!("unsupported request version: {}", request.version).into());
    }

    let recipient_pk = request.decode_client_pubkey()?;
    let bundle_id = request.decode_nonce()?;

    let payload_json = std::fs::read_to_string(&payload_path)
        .map_err(|e| format!("read {}: {e}", payload_path.display()))?;
    let payload: SealedPayloadV1 =
        serde_json::from_str(&payload_json).map_err(|e| format!("parse SealedPayloadV1: {e}"))?;

    // Fresh per-seal producer identity. In Mode C the consumer pins this
    // pubkey out-of-band — it is not tied to the VTA's long-lived DID.
    let (_producer_sk, producer_pk) = generate_keypair();
    let producer = ProducerAssertion {
        producer_pubkey_b64: B64URL.encode(producer_pk),
        proof: AssertionProof::PinnedOnly,
    };

    // Phase 1 offline seal uses an in-memory nonce store; the online path in
    // Phase 2 gets a persistent store so restarts can't lose the anti-replay
    // record.
    let nonce_store = InMemoryNonceStore::new();
    let bundle = seal_payload(&recipient_pk, bundle_id, producer, &payload, &nonce_store)?;

    let armored = armor::encode(&bundle);
    std::fs::write(&out_path, armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;

    let digest = bundle_digest(&bundle);
    eprintln!("Sealed bundle written to {}", out_path.display());
    eprintln!();
    eprintln!("  Bundle-Id:        {}", hex_lower(&bundle.bundle_id));
    eprintln!("  Chunks:           {}", bundle.chunks.len());
    eprintln!("  Producer pubkey:  {}", B64URL.encode(producer_pk));
    eprintln!("  SHA-256 digest:   {digest}");
    eprintln!();
    eprintln!(
        "Communicate the digest to the consumer out-of-band so they can run\n  \
         pnm bootstrap open --bundle <file> --expect-digest {digest}"
    );
    Ok(())
}

/// Issue a one-time bootstrap token. Stores a `PendingBootstrap` row keyed
/// by hash(token); the token itself is shown exactly once.
pub async fn run_issue_token(
    config_path: Option<PathBuf>,
    role: String,
    contexts: Vec<String>,
    expires: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_role = Role::parse(&role)?;
    if target_role == Role::Bootstrap {
        return Err(
            "the bootstrap role cannot be assigned via a token — it is a transient marker only"
                .into(),
        );
    }
    // Admin-without-contexts is unrestricted (super admin). All other roles
    // must have at least one context, mirroring `validate_acl_modification`
    // semantics. This mirrors the server-side check that applies when the
    // token is consumed.
    if target_role != Role::Admin && contexts.is_empty() {
        return Err(format!(
            "role '{}' requires at least one --contexts entry (only admin can be unrestricted)",
            role
        )
        .into());
    }

    let duration_secs = parse_duration(&expires)?;
    if duration_secs == 0 {
        return Err("--expires must be a positive duration".into());
    }

    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    let token = generate_token();
    let now = now_epoch();
    let entry = PendingBootstrap {
        token_hash: PendingBootstrap::hash_token(&token),
        target_role: target_role.clone(),
        target_contexts: contexts.clone(),
        expires_at: now + duration_secs,
        issued_by: "cli:vta-bootstrap".to_string(),
        issued_at: now,
        label: label.clone(),
    };
    store_pending_bootstrap(&acl_ks, &entry).await?;
    store.persist().await?;

    eprintln!("Bootstrap token issued (one-time display — save it now).");
    eprintln!();
    eprintln!("  Token:       {token}");
    eprintln!("  Token hash:  {}", entry.hash_hex());
    eprintln!("  Role:        {target_role}");
    eprintln!(
        "  Contexts:    {}",
        if contexts.is_empty() {
            "<unrestricted>".to_string()
        } else {
            contexts.join(", ")
        }
    );
    eprintln!("  Expires at:  {} (unix)", entry.expires_at);
    if let Some(l) = &label {
        eprintln!("  Label:       {l}");
    }
    eprintln!();
    eprintln!("Hand the token to the consumer, who should run:");
    eprintln!("  pnm bootstrap connect --vta-url <URL> --token {token}");
    Ok(())
}

/// List all `PendingBootstrap` rows (metadata only — token hashes are
/// one-way).
pub async fn run_list_tokens(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    let entries = list_pending_bootstraps(&acl_ks).await?;
    if entries.is_empty() {
        println!("No pending bootstrap tokens.");
        return Ok(());
    }
    let now = now_epoch();
    println!(
        "{:<64}  {:<12}  {:<10}  {}",
        "TOKEN HASH", "ROLE", "STATUS", "LABEL / CONTEXTS"
    );
    for e in &entries {
        let status = if e.is_expired(now) {
            "expired"
        } else {
            "valid"
        };
        let label_or_contexts = match &e.label {
            Some(l) => l.clone(),
            None if e.target_contexts.is_empty() => "<unrestricted>".to_string(),
            None => e.target_contexts.join(","),
        };
        println!(
            "{}  {:<12}  {:<10}  {}",
            e.hash_hex(),
            e.target_role,
            status,
            label_or_contexts
        );
    }
    Ok(())
}

/// Revoke a pending token by its hex-encoded hash or by its operator-visible
/// label.
pub async fn run_revoke_token(
    config_path: Option<PathBuf>,
    id_or_label: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    let entries = list_pending_bootstraps(&acl_ks).await?;
    let mut matching: Vec<&PendingBootstrap> = entries
        .iter()
        .filter(|e| {
            e.hash_hex() == id_or_label.to_lowercase()
                || e.label.as_deref() == Some(id_or_label.as_str())
        })
        .collect();

    if matching.is_empty() {
        return Err(format!("no pending bootstrap matched '{id_or_label}'").into());
    }
    if matching.len() > 1 {
        return Err(format!(
            "'{id_or_label}' matched {} entries — pass the full hex hash to disambiguate",
            matching.len()
        )
        .into());
    }
    let entry = matching.pop().unwrap();
    let hex = entry.hash_hex();
    delete_pending_bootstrap(&acl_ks, &hex).await?;
    store.persist().await?;
    println!("Revoked pending bootstrap {hex}");
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Parse a short duration string like `7d`, `24h`, `30m`, `3600s` into
/// seconds. Plain integers (no unit) are treated as seconds.
fn parse_duration(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty --expires value".into());
    }
    let (num_str, mult) = match s.as_bytes().last().copied() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'd') => (&s[..s.len() - 1], 86400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(format!("invalid duration '{s}' (use N[s|m|h|d])").into()),
    };
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration number in '{s}'"))?;
    Ok(n.saturating_mul(mult))
}

/// Generate a 120-bit bootstrap token formatted as six groups of four
/// base32 characters: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. Base32-Crockford-style
/// alphabet (excludes `I`, `L`, `O`, `U` for legibility).
fn generate_token() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bits: [u8; 15] = rand::random();
    // 120 bits → 24 base32 chars
    let mut buf: u64 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::with_capacity(29); // 24 chars + 5 dashes
    let mut emitted: u32 = 0;
    for &b in &bits {
        buf = (buf << 8) | (b as u64);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((buf >> nbits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
            emitted += 1;
            if emitted % 4 == 0 && emitted < 24 {
                out.push('-');
            }
        }
    }
    out
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        assert_eq!(parse_duration("3600").unwrap(), 3600);
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("7x").is_err());
    }

    #[test]
    fn generated_token_format() {
        let t = generate_token();
        assert_eq!(t.len(), 29); // 24 chars + 5 dashes
        let parts: Vec<&str> = t.split('-').collect();
        assert_eq!(parts.len(), 6);
        for p in parts {
            assert_eq!(p.len(), 4);
            assert!(
                p.chars()
                    .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
            );
        }
    }

    #[test]
    fn tokens_are_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
    }
}
