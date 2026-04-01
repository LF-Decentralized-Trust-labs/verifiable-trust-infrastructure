use ratatui::layout::Constraint;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Cell, Row, Table};
use vta_sdk::prelude::*;

use crate::render::print_widget;

/// Display audit logs with beautiful colored formatting.
pub async fn cmd_list_audit_logs(
    client: &VtaClient,
    params: &ListAuditLogsBody,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.list_audit_logs(params).await?;

    if result.entries.is_empty() {
        println!("  No audit log entries found.");
        return Ok(());
    }

    // Page info header
    println!(
        "\n  \x1b[1mAudit Log\x1b[0m  \x1b[2m(page {}/{}, {} total entries)\x1b[0m\n",
        result.page, result.total_pages, result.total
    );

    // Build table rows
    let rows: Vec<Row> = result
        .entries
        .iter()
        .map(|entry| {
            // Format timestamp
            let ts = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| entry.timestamp.to_string());

            // Color the outcome
            let outcome_style = if entry.outcome == "success" {
                Style::default().fg(Color::Green)
            } else if entry.outcome.starts_with("denied") {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow)
            };

            // Color the action
            let action_style = if entry.action.starts_with("auth.") {
                Style::default().fg(Color::Cyan)
            } else if entry.action.starts_with("key.") || entry.action.starts_with("seed.") {
                Style::default().fg(Color::Magenta)
            } else if entry.action.starts_with("acl.") {
                Style::default().fg(Color::Yellow)
            } else if entry.action.starts_with("session.") {
                Style::default().fg(Color::Blue)
            } else {
                Style::default()
            };

            // Truncate actor DID for display
            let actor_display = if entry.actor.len() > 30 {
                format!("{}…", &entry.actor[..29])
            } else {
                entry.actor.clone()
            };

            let resource_display = entry.resource.as_deref().unwrap_or("\u{2014}");

            Row::new(vec![
                Cell::from(Span::styled(ts, Style::default().fg(Color::DarkGray))),
                Cell::from(Span::styled(entry.action.clone(), action_style)),
                Cell::from(Span::styled(
                    actor_display,
                    Style::default().fg(Color::DarkGray),
                )),
                Cell::from(resource_display.to_string()),
                Cell::from(Span::styled(entry.outcome.clone(), outcome_style)),
            ])
        })
        .collect();

    let header = Row::new(vec![
        Cell::from(Span::styled(
            "Timestamp",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Action",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Actor",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Resource",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::styled(
            "Outcome",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
    ]);

    let row_count = result.entries.len();

    let table = Table::new(
        rows,
        [
            Constraint::Length(19), // Timestamp
            Constraint::Length(22), // Action
            Constraint::Length(30), // Actor
            Constraint::Min(16),    // Resource
            Constraint::Length(20), // Outcome
        ],
    )
    .header(header)
    .column_spacing(2);

    let height = row_count as u16 + 2; // rows + header + spacing
    print_widget(table, height);

    // Footer with pagination info
    if result.total_pages > 1 {
        println!(
            "\n  \x1b[2mPage {}/{} \u{2014} use --page N to navigate\x1b[0m",
            result.page, result.total_pages
        );
    }

    Ok(())
}

/// Display the current audit retention period.
pub async fn cmd_get_retention(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.get_audit_retention().await?;
    println!("\n  \x1b[1mAudit Retention\x1b[0m");
    println!(
        "  Retention period: \x1b[36m{}\x1b[0m days",
        result.retention_days
    );
    println!();
    Ok(())
}

/// Update the audit retention period.
pub async fn cmd_update_retention(
    client: &VtaClient,
    days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.update_audit_retention(days).await?;
    println!(
        "\n  \x1b[32m\u{2713}\x1b[0m Audit retention updated to \x1b[36m{}\x1b[0m days",
        result.retention_days
    );
    println!();
    Ok(())
}
