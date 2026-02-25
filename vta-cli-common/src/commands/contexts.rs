use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{
    CreateContextRequest, GenerateCredentialsRequest, UpdateContextRequest, VtaClient,
};

use crate::render::print_widget;

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
) -> Result<(), Box<dyn std::error::Error>> {
    client.delete_context(id).await?;
    println!("Context deleted: {id}");
    Ok(())
}
