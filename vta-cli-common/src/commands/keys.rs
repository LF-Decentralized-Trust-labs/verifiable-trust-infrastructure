use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{CreateKeyRequest, VtaClient};
use vta_sdk::keys::KeyType;

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
    let req = CreateKeyRequest {
        key_type,
        derivation_path,
        key_id: None,
        mnemonic,
        label,
        context_id,
    };
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
