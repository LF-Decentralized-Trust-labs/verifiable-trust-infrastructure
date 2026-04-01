use std::io::{self, Write};

use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{CreateDidWebvhRequest, UpdateContextRequest};
use vta_sdk::context_provision::{ContextProvisionBundle, ProvisionedDid};
use vta_sdk::prelude::*;

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
    let mut ctx_req = CreateContextRequest::new(id, name);
    if let Some(desc) = description {
        ctx_req = ctx_req.description(desc);
    }
    let ctx = client.create_context(ctx_req).await?;
    println!("Context created:");
    println!("  ID:        {}", ctx.id);
    println!("  Name:      {}", ctx.name);
    println!("  Base Path: {}", ctx.base_path);

    let mut cred_req = GenerateCredentialsRequest::new("admin").contexts(vec![id.to_string()]);
    if let Some(l) = admin_label {
        cred_req = cred_req.label(l);
    }
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

pub async fn cmd_context_update_did(
    client: &VtaClient,
    id: &str,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.update_context_did(id, did).await?;
    println!("Context DID updated:");
    println!("  ID:         {}", resp.id);
    println!(
        "  DID:        {}",
        resp.did.as_deref().unwrap_or("(not set)")
    );
    println!("  Updated At: {}", resp.updated_at);
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
        println!(
            "Deleting context '{}' will remove the following resources:\n",
            id
        );

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
            println!(
                "  ACL entries removed ({}):",
                preview.acl_entries_removed.len()
            );
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
    let mut ctx_req = CreateContextRequest::new(id, name);
    if let Some(desc) = description {
        ctx_req = ctx_req.description(desc);
    }
    client.create_context(ctx_req).await?;

    // 2. Generate admin credentials scoped to this context
    eprintln!("Generating admin credentials...");
    let mut cred_req = GenerateCredentialsRequest::new("admin").contexts(vec![id.to_string()]);
    if let Some(l) = admin_label {
        cred_req = cred_req.label(l);
    }
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
        let mut secrets: Vec<SecretEntry> = Vec::new();
        // Signing key
        secrets.push(
            client
                .get_key_secret(&did_result.signing_key_id)
                .await?
                .into(),
        );
        // Key-agreement key
        secrets.push(client.get_key_secret(&did_result.ka_key_id).await?.into());
        // Pre-rotation keys
        for i in 0..did_result.pre_rotation_key_count {
            let pre_rot_id = format!("{}#pre-rotation-{i}", did_result.did);
            secrets.push(client.get_key_secret(&pre_rot_id).await?.into());
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

/// Build a `CredentialBundle` from a VTA-stored key, deriving its `did:key`.
async fn credential_from_key(
    client: &VtaClient,
    key_id: &str,
    vta_did: &str,
    vta_url: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let secret = client.get_key_secret(key_id).await?;
    let seed = decode_private_key_multibase(&secret.private_key_multibase)
        .map_err(|e| format!("Cannot decode key secret: {e}"))?;
    let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let did = format!("did:key:{}", ed25519_multibase_pubkey(&public_key));

    let bundle = CredentialBundle {
        did: did.clone(),
        private_key_multibase: secret.private_key_multibase,
        vta_did: vta_did.to_string(),
        vta_url: vta_url.map(String::from),
    };
    let encoded = bundle.encode().map_err(|e| format!("{e}"))?;
    Ok((encoded, did))
}

pub async fn cmd_context_reprovision(
    client: &VtaClient,
    id: &str,
    key_id: Option<String>,
    admin_label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Fetch the existing context
    eprintln!("Fetching context '{id}'...");
    let ctx = client.get_context(id).await?;

    // 2. Fetch VTA config for URL/DID
    let config = client.get_config().await?;
    let vta_did = config
        .community_vta_did
        .as_deref()
        .ok_or("VTA DID not configured")?;

    // 3. Resolve admin credential
    let (admin_credential, admin_did) = if let Some(ref kid) = key_id {
        // Direct key ID specified
        eprintln!("Using key '{kid}'...");
        credential_from_key(client, kid, vta_did, config.public_url.as_deref()).await?
    } else {
        // Interactive: list existing Ed25519 keys and let user choose
        let keys_resp = client.list_keys(0, 10000, Some("active"), Some(id)).await?;
        let ed25519_keys: Vec<_> = keys_resp
            .keys
            .iter()
            .filter(|k| k.key_type == KeyType::Ed25519)
            .collect();

        eprintln!();
        eprintln!("Select an admin credential key for context '{id}':");
        eprintln!();
        for (i, key) in ed25519_keys.iter().enumerate() {
            let label = key
                .label
                .as_deref()
                .map(|l| format!(" ({l})"))
                .unwrap_or_default();
            eprintln!("  [{}] {}{}", i + 1, key.key_id, label);
        }
        let new_option = ed25519_keys.len() + 1;
        eprintln!("  [{}] Create a new admin key", new_option);
        eprintln!();
        eprint!("Choice [{}]: ", new_option);
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        // Default to creating a new key if empty
        let choice: usize = if input.is_empty() {
            new_option
        } else {
            input
                .parse()
                .map_err(|_| format!("Invalid choice: {input}"))?
        };

        if choice == new_option {
            // Create a new Ed25519 key in VTA scoped to this context
            eprintln!("Creating new admin key...");
            let key_resp = client
                .create_key(CreateKeyRequest {
                    key_type: KeyType::Ed25519,
                    derivation_path: None,
                    key_id: None,
                    mnemonic: None,
                    label: admin_label.or_else(|| Some("admin".to_string())),
                    context_id: Some(id.to_string()),
                })
                .await?;
            credential_from_key(
                client,
                &key_resp.key_id,
                vta_did,
                config.public_url.as_deref(),
            )
            .await?
        } else if choice >= 1 && choice <= ed25519_keys.len() {
            let selected = &ed25519_keys[choice - 1];
            eprintln!("Using key '{}'...", selected.key_id);
            credential_from_key(
                client,
                &selected.key_id,
                vta_did,
                config.public_url.as_deref(),
            )
            .await?
        } else {
            return Err(format!("Invalid choice: {choice}").into());
        }
    };

    // 4. Ensure an ACL entry exists for this admin DID
    if client.get_acl(&admin_did).await.is_err() {
        eprintln!("Creating ACL entry for {admin_did}...");
        client
            .create_acl(
                vta_sdk::client::CreateAclRequest::new(&admin_did, "admin")
                    .contexts(vec![id.to_string()]),
            )
            .await?;
    }

    // 5. Collect DID material (document, log, secrets) when the context has a DID
    let provisioned_did = if let Some(ref did_id) = ctx.did {
        eprintln!("Fetching DID material...");

        // Fetch the DID log and extract the DID document from it
        let log_resp = client.get_did_webvh_log(did_id).await?;
        let (did_document, log_entry) = if let Some(ref log_str) = log_resp.log {
            let parsed: serde_json::Value = serde_json::from_str(log_str)
                .map_err(|e| format!("failed to parse DID log: {e}"))?;
            let doc = parsed.get("state").cloned();
            (doc, Some(log_str.clone()))
        } else {
            (None, None)
        };

        // Fetch all active key secrets for this context
        let secrets_bundle = client.fetch_did_secrets_bundle(id).await?;

        Some(ProvisionedDid {
            id: did_id.clone(),
            did_document,
            log_entry,
            secrets: secrets_bundle.secrets,
        })
    } else {
        None
    };

    // 6. Build the provision bundle
    let bundle = ContextProvisionBundle {
        context_id: id.to_string(),
        context_name: ctx.name.clone(),
        vta_url: config.public_url,
        vta_did: config.community_vta_did,
        credential: admin_credential,
        admin_did,
        did: provisioned_did,
    };

    let encoded = bundle.encode().map_err(|e| format!("{e}"))?;

    // 7. Output
    eprintln!();
    eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  Context provision bundle (contains secrets — save securely) ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();
    eprintln!("  Context:   {} ({})", id, ctx.name);
    eprintln!("  Admin DID: {}", bundle.admin_did);
    if let Some(ref did) = bundle.did {
        eprintln!("  DID:       {}", did.id);
    }
    eprintln!();
    println!("{encoded}");
    eprintln!();

    Ok(())
}
