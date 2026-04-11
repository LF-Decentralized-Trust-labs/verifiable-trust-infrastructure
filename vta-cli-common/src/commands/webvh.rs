use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{AddWebvhServerRequest, CreateDidWebvhRequest, UpdateWebvhServerRequest};
use vta_sdk::prelude::*;

use crate::render::print_widget;

pub async fn cmd_webvh_server_add(
    client: &VtaClient,
    id: String,
    did: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = AddWebvhServerRequest { id, did, label };
    let record = client.add_webvh_server(req).await?;
    println!("WebVH server added:");
    println!("  ID:  {}", record.id);
    println!("  DID: {}", record.did);
    if let Some(label) = &record.label {
        println!("  Label: {label}");
    }
    Ok(())
}

pub async fn cmd_webvh_server_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_webvh_servers().await?;

    if resp.servers.is_empty() {
        println!("No WebVH servers configured.");
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["ID", "DID", "Label", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .servers
        .iter()
        .map(|s| {
            let label = s.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = s.created_at.format("%Y-%m-%d %H:%M").to_string();

            Row::new(vec![
                Cell::from(s.id.clone()),
                Cell::from(s.did.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(label),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" WebVH Servers ({}) ", resp.servers.len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(16), // ID
            Constraint::Min(40),    // DID
            Constraint::Min(16),    // Label
            Constraint::Length(18), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.servers.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_webvh_server_update(
    client: &VtaClient,
    id: &str,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateWebvhServerRequest { label };
    let record = client.update_webvh_server(id, req).await?;
    println!("WebVH server updated:");
    println!("  ID:  {}", record.id);
    println!("  DID: {}", record.did);
    if let Some(label) = &record.label {
        println!("  Label: {label}");
    }
    Ok(())
}

pub async fn cmd_webvh_server_remove(
    client: &VtaClient,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.remove_webvh_server(id).await?;
    println!("WebVH server removed: {id}");
    Ok(())
}

// ── DID commands ────────────────────────────────────────────────────

pub async fn cmd_webvh_did_create(
    client: &VtaClient,
    req: CreateDidWebvhRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.create_did_webvh(req).await?;
    println!("WebVH DID created:");
    println!("  DID:              {}", result.did);
    println!("  Context:          {}", result.context_id);
    if let Some(ref server_id) = result.server_id {
        println!("  Server:           {}", server_id);
    }
    if let Some(ref mnemonic) = result.mnemonic {
        println!("  Mnemonic:         {}", mnemonic);
    }
    println!("  SCID:             {}", result.scid);
    println!("  Portable:         {}", result.portable);
    println!("  Signing key:      {}", result.signing_key_id);
    println!("  KA key:           {}", result.ka_key_id);
    println!("  Pre-rotation keys: {}", result.pre_rotation_key_count);

    if let Some(ref did_document) = result.did_document {
        println!();
        println!("DID Document:");
        println!(
            "{}",
            serde_json::to_string_pretty(did_document)
                .unwrap_or_else(|_| format!("{did_document}"))
        );
    }
    if let Some(ref log_entry) = result.log_entry {
        println!();
        println!("Log Entry (did.jsonl):");
        println!("{}", log_entry);
        println!();
        println!("To self-host this DID, place the log entry in a file named `did.jsonl`");
        println!("at the URL path corresponding to your DID URL.");
    }

    Ok(())
}

/// Helper that reads optional file inputs before building a `CreateDidWebvhRequest`.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_webvh_did_create_with_files(
    client: &VtaClient,
    context_id: String,
    server_id: Option<String>,
    url: Option<String>,
    path: Option<String>,
    label: Option<String>,
    portable: bool,
    add_mediator_service: bool,
    services: Option<String>,
    pre_rotation_count: u32,
    did_document_path: Option<String>,
    did_log_path: Option<String>,
    no_primary: bool,
    signing_key_id: Option<String>,
    ka_key_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let did_document = match did_document_path {
        Some(p) => {
            let content =
                std::fs::read_to_string(&p).map_err(|e| format!("failed to read {p}: {e}"))?;
            Some(
                serde_json::from_str::<serde_json::Value>(&content)
                    .map_err(|e| format!("invalid JSON in {p}: {e}"))?,
            )
        }
        None => None,
    };
    let did_log = match did_log_path {
        Some(p) => {
            Some(std::fs::read_to_string(&p).map_err(|e| format!("failed to read {p}: {e}"))?)
        }
        None => None,
    };
    let additional_services = services
        .map(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s))
        .transpose()
        .map_err(|e| format!("invalid --services JSON: {e}"))?;

    let req = CreateDidWebvhRequest {
        context_id,
        server_id,
        url,
        path,
        label,
        portable,
        add_mediator_service,
        additional_services,
        pre_rotation_count,
        did_document,
        did_log,
        set_primary: !no_primary,
        signing_key_id,
        ka_key_id,
    };
    cmd_webvh_did_create(client, req).await
}

pub async fn cmd_webvh_did_list(
    client: &VtaClient,
    context_id: Option<&str>,
    server_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_dids_webvh(context_id, server_id).await?;

    if resp.dids.is_empty() {
        println!("No WebVH DIDs found.");
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["DID", "Context", "Server", "Portable", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .dids
        .iter()
        .map(|d| {
            let portable = if d.portable { "yes" } else { "no" };
            let created = d.created_at.format("%Y-%m-%d %H:%M").to_string();

            Row::new(vec![
                Cell::from(d.did.clone()),
                Cell::from(d.context_id.clone()),
                Cell::from(d.server_id.clone()),
                Cell::from(portable.to_string()),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" WebVH DIDs ({}) ", resp.dids.len());

    let table = Table::new(
        rows,
        [
            Constraint::Min(40),    // DID
            Constraint::Length(16), // Context
            Constraint::Length(16), // Server
            Constraint::Length(10), // Portable
            Constraint::Length(18), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.dids.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_webvh_did_get(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = client.get_did_webvh(did).await?;
    println!("WebVH DID:");
    println!("  DID:             {}", record.did);
    println!("  Context:         {}", record.context_id);
    println!("  Server:          {}", record.server_id);
    println!("  Mnemonic:        {}", record.mnemonic);
    println!("  SCID:            {}", record.scid);
    println!("  Portable:        {}", record.portable);
    println!("  Log entries:     {}", record.log_entry_count);
    println!(
        "  Created:         {}",
        record.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "  Updated:         {}",
        record.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    Ok(())
}

pub async fn cmd_webvh_did_delete(
    client: &VtaClient,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.delete_did_webvh(did).await?;
    println!("WebVH DID deleted: {did}");
    Ok(())
}
