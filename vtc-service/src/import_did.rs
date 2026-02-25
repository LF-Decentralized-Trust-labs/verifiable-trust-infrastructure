use std::path::PathBuf;

use dialoguer::{Confirm, Select};

use crate::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
use crate::config::AppConfig;
use crate::store::Store;

pub struct ImportDidArgs {
    pub config_path: Option<PathBuf>,
    pub did: String,
    pub role: Option<String>,
    pub label: Option<String>,
}

pub async fn run_import_did(args: ImportDidArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(args.config_path)?;
    let store = Store::open(&config.store)?;
    let acl_ks = store.keyspace("acl")?;

    // Validate DID format
    if !args.did.starts_with("did:") {
        return Err("invalid DID: must start with \"did:\"".into());
    }

    // Determine role
    let role = match args.role {
        Some(r) => Role::from_str(&r)?,
        None => {
            let roles = ["admin", "initiator", "application"];
            let selection = Select::new()
                .with_prompt("Select role for this DID")
                .items(roles)
                .default(0)
                .interact()?;
            Role::from_str(roles[selection])?
        }
    };

    // Check for existing entry
    if let Some(existing) = get_acl_entry(&acl_ks, &args.did).await? {
        eprintln!(
            "ACL entry already exists for {} (role: {})",
            args.did, existing.role
        );
        if !Confirm::new()
            .with_prompt("Overwrite?")
            .default(false)
            .interact()?
        {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let entry = AclEntry {
        did: args.did.clone(),
        role: role.clone(),
        label: args.label.clone(),
        allowed_contexts: vec![],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        created_by: "cli:import-did".into(),
    };

    store_acl_entry(&acl_ks, &entry).await?;
    store.persist().await?;

    // Print summary
    eprintln!();
    eprintln!("DID imported: {}", args.did);
    eprintln!("Role: {role}");
    if let Some(label) = &args.label {
        eprintln!("Label: {label}");
    }

    // Print connection info for the DID owner
    eprintln!();
    eprintln!("--- Connection info (share with DID owner) ---");
    if let Some(vtc_did) = &config.vtc_did {
        eprintln!("Community VTC DID: {vtc_did}");
    } else {
        eprintln!("Community VTC DID: (not configured)");
    }
    if let Some(url) = &config.public_url {
        eprintln!("Community VTC URL: {url}");
    } else {
        eprintln!("Community VTC URL: (not configured)");
    }

    Ok(())
}
