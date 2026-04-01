use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::prelude::*;

use crate::render::print_widget;

pub async fn cmd_key_create(
    client: &VtaClient,
    key_type: &str,
    derivation_path: Option<String>,
    mnemonic: Option<String>,
    label: Option<String>,
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        other => {
            return Err(format!("unknown key type '{other}', expected ed25519 or x25519").into());
        }
    };
    let mut req = CreateKeyRequest::new(key_type);
    if let Some(p) = derivation_path {
        req = req.derivation_path(p);
    }
    if let Some(m) = mnemonic {
        req = req.mnemonic(m);
    }
    if let Some(l) = label {
        req = req.label(l);
    }
    if let Some(c) = context_id {
        req = req.context(c);
    }
    let resp = client.create_key(req).await?;
    println!("Key created:");
    println!("  Key ID:          {}", resp.key_id);
    println!("  Key Type:        {}", resp.key_type);
    println!("  Derivation Path: {}", resp.derivation_path);
    println!("  Public Key:      {}", resp.public_key);
    println!("  Status:          {}", resp.status);
    if let Some(label) = &resp.label {
        println!("  Label:           {label}");
    }
    println!("  Created At:      {}", resp.created_at);
    Ok(())
}

pub async fn cmd_key_import(
    client: &VtaClient,
    key_type: &str,
    private_key: Option<String>,
    private_key_file: Option<std::path::PathBuf>,
    label: Option<String>,
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_type = match key_type {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        "p256" => KeyType::P256,
        other => {
            return Err(
                format!("unknown key type '{other}', expected ed25519, x25519, or p256").into(),
            );
        }
    };

    // Read private key bytes
    let private_key_multibase = if let Some(key_str) = private_key {
        key_str
    } else if let Some(path) = private_key_file {
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("failed to read key file '{}': {e}", path.display()))?;
        // If file is text (multibase), use as-is; otherwise encode as multibase
        match String::from_utf8(bytes.clone()) {
            Ok(s) if s.starts_with('z') || s.starts_with('f') || s.starts_with('u') => {
                s.trim().to_string()
            }
            _ => multibase::encode(multibase::Base::Base58Btc, &bytes),
        }
    } else {
        return Err("either --private-key or --private-key-file is required".into());
    };

    // For REST transport, fetch wrapping key and create JWE
    // For DIDComm, send multibase directly
    let (jwe, multibase) = match client.get_wrapping_key().await {
        Ok(wrapping_key) => {
            // REST path: wrap with ECDH-ES
            let jwe = wrap_private_key(&wrapping_key.kid, &wrapping_key.x, &private_key_multibase)?;
            (Some(jwe), None)
        }
        Err(_) => {
            // DIDComm path (or wrapping key not available): send multibase
            (None, Some(private_key_multibase))
        }
    };

    let req = ImportKeyRequest {
        key_type,
        private_key_jwe: jwe,
        private_key_multibase: multibase,
        label,
        context_id,
    };
    let resp = client.import_key(req).await?;

    println!("Key imported successfully:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Key Type:   {}", resp.key_type);
    println!("  Public Key: {}", resp.public_key);
    println!("  Status:     {}", resp.status);
    println!("  Origin:     imported");
    if let Some(label) = &resp.label {
        println!("  Label:      {label}");
    }
    println!("  Created At: {}", resp.created_at);
    eprintln!();
    eprintln!(
        "\x1b[1;33mWarning: securely delete the source key material \u{2014} the VTA now holds this secret.\x1b[0m"
    );

    Ok(())
}

/// Wrap a multibase-encoded private key with ECDH-ES+AES-256-GCM for REST transport.
fn wrap_private_key(
    kid: &str,
    vta_pub_b64: &str,
    private_key_multibase: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;

    // Decode the VTA's wrapping public key
    let vta_pub_bytes: [u8; 32] = BASE64
        .decode(vta_pub_b64)?
        .try_into()
        .map_err(|_| "wrapping public key must be 32 bytes")?;

    // Decode the private key from multibase
    let (_, key_bytes) = multibase::decode(private_key_multibase)?;

    // Generate ephemeral X25519 keypair for client side
    let client_secret = x25519_dalek::StaticSecret::random_from_rng(aes_gcm::aead::OsRng);
    let client_pub = x25519_dalek::PublicKey::from(&client_secret);

    // ECDH
    let vta_pub = x25519_dalek::PublicKey::from(vta_pub_bytes);
    let shared = client_secret.diffie_hellman(&vta_pub);

    // HKDF to derive AES key
    use sha2::Sha256;
    let hkdf = hkdf::Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(b"vta-key-import-wrapping", &mut aes_key)
        .map_err(|e| format!("hkdf: {e}"))?;

    // AES-256-GCM encrypt
    use aes_gcm::aead::Aead;
    use aes_gcm::aead::rand_core::RngCore;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new_from_slice(&aes_key)?;
    let mut nonce_bytes = [0u8; 12];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, key_bytes.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    // Format: kid.ephemeral_pub.nonce.ciphertext
    Ok(format!(
        "{}.{}.{}.{}",
        kid,
        BASE64.encode(client_pub.as_bytes()),
        BASE64.encode(nonce_bytes),
        BASE64.encode(ciphertext),
    ))
}

pub async fn cmd_key_get(
    client: &VtaClient,
    key_id: &str,
    secret: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if secret {
        let resp = client.get_key_secret(key_id).await?;
        println!("Key ID:               {}", resp.key_id);
        println!("Key Type:             {}", resp.key_type);
        println!("Public Key Multibase: {}", resp.public_key_multibase);
        println!("Secret Key Multibase: {}", resp.private_key_multibase);
    } else {
        let resp = client.get_key(key_id).await?;
        println!("Key ID:          {}", resp.key_id);
        println!("Key Type:        {}", resp.key_type);
        println!("Derivation Path: {}", resp.derivation_path);
        println!("Public Key:      {}", resp.public_key);
        println!("Status:          {}", resp.status);
        if let Some(label) = &resp.label {
            println!("Label:           {label}");
        }
        println!("Created At:      {}", resp.created_at);
        println!("Updated At:      {}", resp.updated_at);
    }
    Ok(())
}

pub async fn cmd_key_revoke(
    client: &VtaClient,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.invalidate_key(key_id).await?;
    println!("Key revoked:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Status:     {}", resp.status);
    println!("  Updated At: {}", resp.updated_at);
    Ok(())
}

pub async fn cmd_key_rename(
    client: &VtaClient,
    key_id: &str,
    new_key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.rename_key(key_id, new_key_id).await?;
    println!("Key renamed:");
    println!("  Key ID:     {}", resp.key_id);
    println!("  Updated At: {}", resp.updated_at);
    Ok(())
}

pub async fn cmd_key_list(
    client: &VtaClient,
    offset: u64,
    limit: u64,
    status: Option<String>,
    context_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .list_keys(offset, limit, status.as_deref(), context_id.as_deref())
        .await?;

    if resp.keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    let end = (offset + resp.keys.len() as u64).min(resp.total);

    let dim = Style::default().fg(Color::DarkGray);
    let bold = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);

    let rows: Vec<Row> = resp
        .keys
        .iter()
        .map(|key| {
            let label = key.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = key.created_at.format("%Y-%m-%d").to_string();

            let status_span = match key.status {
                vta_sdk::keys::KeyStatus::Active => {
                    Span::styled(key.status.to_string(), Style::default().fg(Color::Green))
                }
                vta_sdk::keys::KeyStatus::Revoked => {
                    Span::styled(key.status.to_string(), Style::default().fg(Color::Red))
                }
            };

            let id_line = Line::from(vec![
                Span::styled("\u{25b8} ", Style::default().fg(Color::Cyan)),
                Span::styled(key.key_id.clone(), bold),
            ]);

            let detail_line = Line::from(vec![
                Span::raw("  "),
                Span::styled(label, Style::default().fg(Color::Yellow)),
                Span::styled("  \u{2502}  ", dim),
                Span::raw(key.key_type.to_string()),
                Span::styled("  \u{2502}  ", dim),
                status_span,
                Span::styled("  \u{2502}  ", dim),
                Span::styled(key.derivation_path.clone(), dim),
                Span::styled("  \u{2502}  ", dim),
                Span::styled(created, dim),
            ]);

            Row::new(vec![Cell::from(Text::from(vec![id_line, detail_line]))])
                .height(2)
                .bottom_margin(1)
        })
        .collect();

    let title = format!(" Keys ({}\u{2013}{} of {}) ", offset + 1, end, resp.total);

    let table = Table::new(rows, [Constraint::Min(1)])
        .block(Block::bordered().title(title).border_style(dim));

    let height = (resp.keys.len() as u16 * 3).saturating_sub(1) + 2;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_seeds_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_seeds().await?;

    if resp.seeds.is_empty() {
        println!("No seed records found.");
        println!("  (pre-rotation state: using external seed store as generation 0)");
        println!("  Active seed ID: {}", resp.active_seed_id);
        return Ok(());
    }

    println!("{} seed generation(s):\n", resp.seeds.len());
    for seed in &resp.seeds {
        println!("  Seed ID:     {}", seed.id);
        println!("  Status:      {}", seed.status);
        println!(
            "  Created:     {}",
            seed.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        if let Some(retired_at) = seed.retired_at {
            println!(
                "  Retired:     {}",
                retired_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }
        println!();
    }
    println!("Active seed ID: {}", resp.active_seed_id);

    Ok(())
}

pub async fn cmd_seeds_rotate(
    client: &VtaClient,
    mnemonic: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.rotate_seed(mnemonic).await?;

    println!("Seed rotated successfully.");
    println!("  Previous seed ID: {} (retired)", resp.previous_seed_id);
    println!("  New active seed ID: {}", resp.new_seed_id);

    Ok(())
}

pub async fn cmd_key_bundle(
    client: &VtaClient,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch all secrets for this context as a portable bundle
    let bundle = client.fetch_did_secrets_bundle(context).await?;
    let encoded = bundle.encode().map_err(|e| format!("{e}"))?;

    // 5. Print with security warning
    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: The secrets bundle contains private keys.      ║");
    eprintln!("║  Store it securely and do not share it publicly.         ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    println!("{encoded}");
    eprintln!();

    Ok(())
}

pub async fn cmd_key_secrets(
    client: &VtaClient,
    key_ids: Vec<String>,
    context: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_ids = if key_ids.is_empty() {
        let ctx = context.as_deref().ok_or(
            "provide key IDs as arguments, or use --context to export all active keys in a context",
        )?;
        let resp = client
            .list_keys(0, 10000, Some("active"), Some(ctx))
            .await?;
        resp.keys.into_iter().map(|k| k.key_id).collect()
    } else {
        key_ids
    };
    if key_ids.is_empty() {
        println!("No active keys found.");
        return Ok(());
    }
    for (i, key_id) in key_ids.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let resp = client.get_key_secret(key_id).await?;
        println!("Key ID:               {}", resp.key_id);
        println!("Key Type:             {}", resp.key_type);
        println!("Public Key Multibase: {}", resp.public_key_multibase);
        println!("Secret Key Multibase: {}", resp.private_key_multibase);
    }
    Ok(())
}
