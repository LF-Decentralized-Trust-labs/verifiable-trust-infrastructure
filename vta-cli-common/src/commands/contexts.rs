use std::io::{self, Write};

use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{
    CreateContextRequest, CreateDidWebvhRequest, GenerateCredentialsRequest, UpdateContextRequest,
    VtaClient,
};
use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
use vta_sdk::did_secrets::SecretEntry;

use crate::render::print_widget;

pub struct ProvisionDidOptions {
    pub server_id: Option<String>,
    pub did_url: Option<String>,
    pub portable: bool,
    pub add_mediator_service: bool,
    pub pre_rotation_count: u32,
}

pub async fn cmd_context_bootstrap(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
    admin_label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx_req = CreateContextRequest {
        id: id.to_string(),
        name: name.to_string(),
        description,
    };
    let ctx = client.create_context(ctx_req).await?;
    println!("Context created:");
    println!("  ID:        {}", ctx.id);
    println!("  Name:      {}", ctx.name);
    println!("  Base Path: {}", ctx.base_path);

    let cred_req = GenerateCredentialsRequest {
        role: "admin".to_string(),
        label: admin_label,
        allowed_contexts: vec![id.to_string()],
    };
    let resp = client.generate_credentials(cred_req).await?;
    println!();
    println!("Admin credential created:");
    println!("  DID:  {}", resp.did);
    println!("  Role: admin");
    println!();
    println!("Credential (one-time secret — save this now):");
    println!("{}", resp.credential);

    Ok(())
}

pub async fn cmd_context_list(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_contexts().await?;

    if resp.contexts.is_empty() {
        println!("No contexts found.");
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["ID", "Name", "DID", "Base Path", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .contexts
        .iter()
        .map(|ctx| {
            let did = ctx.did.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = ctx.created_at.format("%Y-%m-%d").to_string();

            Row::new(vec![
                Cell::from(ctx.id.clone()),
                Cell::from(ctx.name.clone()),
                Cell::from(did).style(Style::default().fg(Color::DarkGray)),
                Cell::from(ctx.base_path.clone()),
                Cell::from(created),
            ])
        })
        .collect();

    let title = format!(" Contexts ({}) ", resp.contexts.len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(16), // ID
            Constraint::Min(20),    // Name
            Constraint::Length(30), // DID
            Constraint::Length(16), // Base Path
            Constraint::Length(10), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.contexts.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_context_get(
    client: &VtaClient,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get_context(id).await?;
    println!("ID:          {}", resp.id);
    println!("Name:        {}", resp.name);
    println!(
        "DID:         {}",
        resp.did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "Description: {}",
        resp.description.as_deref().unwrap_or("(not set)")
    );
    println!("Base Path:   {}", resp.base_path);
    println!("Created At:  {}", resp.created_at);
    println!("Updated At:  {}", resp.updated_at);
    Ok(())
}

pub async fn cmd_context_create(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = CreateContextRequest {
        id: id.to_string(),
        name: name.to_string(),
        description,
    };
    let resp = client.create_context(req).await?;
    println!("Context created:");
    println!("  ID:        {}", resp.id);
    println!("  Name:      {}", resp.name);
    println!("  Base Path: {}", resp.base_path);
    Ok(())
}

pub async fn cmd_context_update(
    client: &VtaClient,
    id: &str,
    name: Option<String>,
    did: Option<String>,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateContextRequest {
        name,
        did,
        description,
    };
    let resp = client.update_context(id, req).await?;
    println!("Context updated:");
    println!("  ID:          {}", resp.id);
    println!("  Name:        {}", resp.name);
    println!(
        "  DID:         {}",
        resp.did.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Description: {}",
        resp.description.as_deref().unwrap_or("(not set)")
    );
    println!("  Updated At:  {}", resp.updated_at);
    Ok(())
}

pub async fn cmd_context_delete(
    client: &VtaClient,
    id: &str,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fetch a preview of what will be removed
    let preview = client.preview_delete_context(id).await?;

    let has_resources = !preview.keys.is_empty()
        || !preview.webvh_dids.is_empty()
        || !preview.acl_entries_removed.is_empty()
        || !preview.acl_entries_updated.is_empty();

    if has_resources {
        println!("Deleting context '{}' will remove the following resources:\n", id);

        if !preview.keys.is_empty() {
            println!("  Keys ({}):", preview.keys.len());
            for key in &preview.keys {
                println!("    - {key}");
            }
        }

        if !preview.webvh_dids.is_empty() {
            println!("  WebVH DIDs ({}):", preview.webvh_dids.len());
            for did in &preview.webvh_dids {
                println!("    - {did}");
            }
        }

        if !preview.acl_entries_removed.is_empty() {
            println!("  ACL entries removed ({}):", preview.acl_entries_removed.len());
            for did in &preview.acl_entries_removed {
                println!("    - {did}");
            }
        }

        if !preview.acl_entries_updated.is_empty() {
            println!(
                "  ACL entries updated (context removed from access list) ({}):",
                preview.acl_entries_updated.len()
            );
            for did in &preview.acl_entries_updated {
                println!("    - {did}");
            }
        }

        println!();

        if !force {
            print!("Proceed with deletion? [y/N] ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();

            if input != "y" && input != "yes" {
                println!("Aborted.");
                return Ok(());
            }
        }
    }

    client.delete_context(id, true).await?;
    println!("Context deleted: {id}");
    Ok(())
}

pub async fn cmd_context_provision(
    client: &VtaClient,
    id: &str,
    name: &str,
    description: Option<String>,
    admin_label: Option<String>,
    did_opts: Option<ProvisionDidOptions>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create the context
    eprintln!("Creating context '{id}'...");
    let ctx_req = CreateContextRequest {
        id: id.to_string(),
        name: name.to_string(),
        description,
    };
    client.create_context(ctx_req).await?;

    // 2. Generate admin credentials scoped to this context
    eprintln!("Generating admin credentials...");
    let cred_req = GenerateCredentialsRequest {
        role: "admin".to_string(),
        label: admin_label,
        allowed_contexts: vec![id.to_string()],
    };
    let cred_resp = client.generate_credentials(cred_req).await?;

    // 3. Fetch VTA config for URL/DID
    let config = client.get_config().await?;

    // 4. Optionally create a DID and collect its secrets
    let provisioned_did = if let Some(opts) = did_opts {
        eprintln!("Creating WebVH DID...");
        let req = CreateDidWebvhRequest {
            context_id: id.to_string(),
            server_id: opts.server_id,
            url: opts.did_url,
            path: None,
            label: Some(id.to_string()),
            portable: opts.portable,
            add_mediator_service: opts.add_mediator_service,
            additional_services: None,
            pre_rotation_count: opts.pre_rotation_count,
        };
        let did_result = client.create_did_webvh(req).await?;

        // Collect secrets for the DID keys
        eprintln!("Fetching DID key secrets...");
        let mut secrets = Vec::new();
        // Signing key
        let signing = client.get_key_secret(&did_result.signing_key_id).await?;
        secrets.push(SecretEntry {
            key_id: signing.key_id,
            key_type: signing.key_type,
            private_key_multibase: signing.private_key_multibase,
        });
        // Key-agreement key
        let ka = client.get_key_secret(&did_result.ka_key_id).await?;
        secrets.push(SecretEntry {
            key_id: ka.key_id,
            key_type: ka.key_type,
            private_key_multibase: ka.private_key_multibase,
        });
        // Pre-rotation keys
        for i in 0..did_result.pre_rotation_key_count {
            let pre_rot_id = format!("{}#pre-rotation-{i}", did_result.did);
            let pre_rot = client.get_key_secret(&pre_rot_id).await?;
            secrets.push(SecretEntry {
                key_id: pre_rot.key_id,
                key_type: pre_rot.key_type,
                private_key_multibase: pre_rot.private_key_multibase,
            });
        }

        Some(ProvisionedDid {
            id: did_result.did,
            did_document: did_result.did_document,
            log_entry: did_result.log_entry,
            secrets,
        })
    } else {
        None
    };

    // 5. Build the provision bundle
    let bundle = ContextProvisionBundle {
        context_id: id.to_string(),
        context_name: name.to_string(),
        vta_url: config.public_url,
        vta_did: config.community_vta_did,
        credential: cred_resp.credential,
        admin_did: cred_resp.did,
        did: provisioned_did,
    };

    let encoded = bundle.encode().map_err(|e| format!("{e}"))?;

    // 6. Output
    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  Context provision bundle (contains secrets — save securely) ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("  Context:   {} ({})", id, name);
    eprintln!("  Admin DID: {}", bundle.admin_did);
    if let Some(ref did) = bundle.did {
        eprintln!("  DID:       {}", did.id);
        if did.log_entry.is_some() {
            eprintln!("             (includes log entry for self-hosting)");
        }
    }
    eprintln!();
    println!("{encoded}");
    eprintln!();

    Ok(())
}
