use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

use crate::acl::Role;
use crate::auth::extractor::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::keys::seed_store::create_seed_store;
use crate::operations;
use crate::store::Store;

/// Create a synthetic super-admin AuthClaims for CLI operations.
fn cli_super_admin() -> AuthClaims {
    AuthClaims {
        did: "cli:local".to_string(),
        role: Role::Admin,
        allowed_contexts: vec![],
    }
}

pub async fn run_add_server(
    config_path: Option<PathBuf>,
    id: String,
    did: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;

    let auth = cli_super_admin();
    let result = operations::did_webvh::add_webvh_server(
        &webvh_ks,
        &auth,
        &id,
        &did,
        label,
        &did_resolver,
        "cli",
    )
    .await?;
    store.persist().await?;

    eprintln!("WebVH server added:");
    eprintln!("  ID:  {}", result.id);
    eprintln!("  DID: {}", result.did);
    if let Some(label) = &result.label {
        eprintln!("  Label: {label}");
    }
    Ok(())
}

pub async fn run_list_servers(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    let result = operations::did_webvh::list_webvh_servers(&webvh_ks, &auth, "cli").await?;

    if result.servers.is_empty() {
        eprintln!("No WebVH servers configured.");
        return Ok(());
    }

    eprintln!("{} WebVH server(s):\n", result.servers.len());
    for server in &result.servers {
        eprintln!("  ID:      {}", server.id);
        eprintln!("  DID:     {}", server.did);
        if let Some(label) = &server.label {
            eprintln!("  Label:   {label}");
        }
        eprintln!(
            "  Created: {}",
            server.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        eprintln!();
    }
    Ok(())
}

pub async fn run_update_server(
    config_path: Option<PathBuf>,
    id: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    let result =
        operations::did_webvh::update_webvh_server(&webvh_ks, &auth, &id, label, "cli").await?;
    store.persist().await?;

    eprintln!("WebVH server updated:");
    eprintln!("  ID:  {}", result.id);
    eprintln!("  DID: {}", result.did);
    if let Some(label) = &result.label {
        eprintln!("  Label: {label}");
    }
    Ok(())
}

pub async fn run_remove_server(
    config_path: Option<PathBuf>,
    id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    operations::did_webvh::remove_webvh_server(&webvh_ks, &auth, &id, "cli").await?;
    store.persist().await?;

    eprintln!("WebVH server removed: {id}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_create_did(
    config_path: Option<PathBuf>,
    context_id: String,
    server_id: String,
    path: Option<String>,
    label: Option<String>,
    portable: bool,
    mediator_service: bool,
    services_json: Option<String>,
    pre_rotation: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path.clone())?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let contexts_ks = store.keyspace("contexts")?;
    let webvh_ks = store.keyspace("webvh")?;
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&config)?);

    let additional_services: Option<Vec<serde_json::Value>> = match services_json {
        Some(json) => Some(serde_json::from_str(&json)?),
        None => None,
    };

    let auth = cli_super_admin();
    let params = operations::did_webvh::CreateDidWebvhParams {
        context_id: context_id.clone(),
        server_id,
        path,
        label,
        portable,
        add_mediator_service: mediator_service,
        additional_services,
        pre_rotation_count: pre_rotation.unwrap_or(0),
    };

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<OnceLock<DIDCommBridge>> = Arc::new(OnceLock::new());
    let result = operations::did_webvh::create_did_webvh(
        &keys_ks,
        &contexts_ks,
        &webvh_ks,
        &*seed_store,
        &config,
        &auth,
        params,
        &did_resolver,
        &no_bridge,
        "cli",
    )
    .await?;
    store.persist().await?;

    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {}", result.did);
    eprintln!("  Context:    {}", result.context_id);
    eprintln!("  Server:     {}", result.server_id);
    eprintln!("  SCID:       {}", result.scid);
    eprintln!("  Mnemonic:   {}", result.mnemonic);
    eprintln!("  Portable:   {}", result.portable);
    eprintln!("  Signing:    {}", result.signing_key_id);
    eprintln!("  KA:         {}", result.ka_key_id);
    if result.pre_rotation_key_count > 0 {
        eprintln!("  Pre-rot:    {} keys", result.pre_rotation_key_count);
    }
    Ok(())
}

pub async fn run_list_dids(
    config_path: Option<PathBuf>,
    context_id: Option<String>,
    server_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let webvh_ks = store.keyspace("webvh")?;

    let auth = cli_super_admin();
    let result = operations::did_webvh::list_dids_webvh(
        &webvh_ks,
        &auth,
        context_id.as_deref(),
        server_id.as_deref(),
        "cli",
    )
    .await?;

    if result.dids.is_empty() {
        eprintln!("No WebVH DIDs found.");
        return Ok(());
    }

    eprintln!("{} WebVH DID(s):\n", result.dids.len());
    for d in &result.dids {
        eprintln!("  DID:      {}", d.did);
        eprintln!("  Context:  {}", d.context_id);
        eprintln!("  Server:   {}", d.server_id);
        eprintln!("  SCID:     {}", d.scid);
        eprintln!("  Portable: {}", d.portable);
        eprintln!(
            "  Created:  {}",
            d.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        eprintln!();
    }
    Ok(())
}

pub async fn run_delete_did(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = Store::open(&config.store)?;
    let keys_ks = store.keyspace("keys")?;
    let webvh_ks = store.keyspace("webvh")?;
    let seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&config)?);

    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<OnceLock<DIDCommBridge>> = Arc::new(OnceLock::new());
    operations::did_webvh::delete_did_webvh(
        &webvh_ks,
        &keys_ks,
        &*seed_store,
        &config,
        &auth,
        &did,
        &did_resolver,
        &no_bridge,
        "cli",
    )
    .await?;
    store.persist().await?;

    eprintln!("WebVH DID deleted: {did}");
    Ok(())
}
