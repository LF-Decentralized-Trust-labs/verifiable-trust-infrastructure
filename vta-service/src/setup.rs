use std::path::PathBuf;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use bip39::Mnemonic;
use chrono::Utc;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use didwebvh_rs::url::WebVHURL;
use rand::Rng;
use serde_json::json;
use url::Url;

use crate::acl::{AclEntry, Role, store_acl_entry};
use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};

use crate::config::{
    AppConfig, AuthConfig, LogConfig, LogFormat, MessagingConfig, SecretsConfig, ServerConfig,
    ServicesConfig, StoreConfig,
};
use crate::contexts::{self, ContextRecord, store_context};
use crate::keys::seed_store::create_seed_store;
use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
use crate::keys::{self, KeyType as SdkKeyType};
use crate::operations;
use crate::operations::did_webvh::CreateDidWebvhParams;
use crate::store::{KeyspaceHandle, Store};
use crate::webvh_cli::cli_super_admin;

/// Create a seed application context and store it.
async fn create_seed_context(
    contexts_ks: &KeyspaceHandle,
    id: &str,
    name: &str,
) -> Result<ContextRecord, Box<dyn std::error::Error>> {
    contexts::create_context(contexts_ks, id, name).await
}

/// Derive an admin did:key Ed25519 key from the BIP-32 seed using a
/// counter-allocated path under `base`, store it as a `KeyRecord`,
/// and return `(did, private_key_multibase)`.
///
/// The key_id uses the standard did:key fragment format: `{did}#{multibase_pubkey}`.
async fn derive_and_store_did_key(
    seed: &[u8],
    base: &str,
    context_id: &str,
    keys_ks: &KeyspaceHandle,
    seed_id: Option<u32>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    keys::derive_and_store_did_key(seed, base, context_id, "Admin did:key", keys_ks, seed_id).await
}

/// Prompt the user to select which services to enable.
///
/// Returns `(rest_enabled, didcomm_enabled)`. At least one must be selected.
fn prompt_services() -> Result<(bool, bool), Box<dyn std::error::Error>> {
    let items = vec!["REST API", "DIDComm Messaging"];
    loop {
        let selected = MultiSelect::new()
            .with_prompt("Services to enable (select at least one)")
            .items(&items)
            .defaults(&[true, true])
            .interact()?;

        if selected.is_empty() {
            eprintln!("\x1b[31mPlease select at least one service.\x1b[0m");
            continue;
        }

        let rest = selected.contains(&0);
        let didcomm = selected.contains(&1);
        return Ok((rest, didcomm));
    }
}

/// Prompt for seed store backend configuration based on compiled features.
///
/// Dynamically builds a list of available backends and lets the user choose
/// when more than one is compiled. Supported backends:
/// - **aws-secrets**: AWS Secrets Manager
/// - **gcp-secrets**: GCP Secret Manager
/// - **config-seed**: hex-encoded seed stored in config.toml
/// - **keyring**: OS keyring (the default)
async fn configure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let mut labels: Vec<&str> = Vec::new();
    let mut tags: Vec<&str> = Vec::new();

    #[cfg(feature = "aws-secrets")]
    {
        labels.push("AWS Secrets Manager");
        tags.push("aws");
    }

    #[cfg(feature = "gcp-secrets")]
    {
        labels.push("GCP Secret Manager");
        tags.push("gcp");
    }

    #[cfg(feature = "azure-secrets")]
    {
        labels.push("Azure Key Vault");
        tags.push("azure");
    }

    #[cfg(feature = "config-seed")]
    {
        labels.push("Config file (hex-encoded seed in config.toml)");
        tags.push("config");
    }

    #[cfg(feature = "keyring")]
    {
        labels.push("OS keyring");
        tags.push("keyring");
    }

    labels.push("Plaintext file (NOT recommended)");
    tags.push("plaintext");

    // If only one backend is compiled, use it without prompting
    let choice = if labels.len() == 1 {
        0
    } else {
        Select::new()
            .with_prompt("Seed storage backend")
            .items(&labels)
            .default(0)
            .interact()?
    };

    let tag = tags[choice];

    #[cfg(feature = "aws-secrets")]
    if tag == "aws" {
        return prompt_aws_secrets().await;
    }

    #[cfg(feature = "gcp-secrets")]
    if tag == "gcp" {
        return prompt_gcp_secrets().await;
    }

    #[cfg(feature = "azure-secrets")]
    if tag == "azure" {
        return prompt_azure_secrets().await;
    }

    #[cfg(feature = "config-seed")]
    if tag == "config" {
        // Marker: seed field will be populated with hex after mnemonic derivation
        return Ok(SecretsConfig {
            seed: Some(String::new()),
            ..Default::default()
        });
    }

    #[cfg(feature = "keyring")]
    if tag == "keyring" {
        return prompt_keyring_service(SecretsConfig::default());
    }

    if tag == "plaintext" {
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: Plaintext storage is NOT secure.               ║");
        eprintln!("║  Seeds will be stored in a plaintext file on disk.       ║");
        eprintln!("║  Use only for development or testing.                    ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        return Ok(SecretsConfig::default());
    }

    // All compiled backends are covered above; this is truly unreachable
    unreachable!("selected backend tag does not match any compiled feature")
}

/// Prompt for the OS keyring service name.
///
/// Each VTA instance needs a unique keyring service name to store its seed
/// separately. The default is "vta".
#[cfg(feature = "keyring")]
fn prompt_keyring_service(
    mut config: SecretsConfig,
) -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let service: String = Input::new()
        .with_prompt("Keyring service name (use a unique name per VTA instance)")
        .default("vta".into())
        .interact_text()?;
    config.keyring_service = service;
    Ok(config)
}

#[cfg(feature = "aws-secrets")]
async fn prompt_aws_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    // Prompt for region first so we can list secrets from that region
    let region: String = Input::new()
        .with_prompt("AWS region (leave empty for SDK default)")
        .allow_empty(true)
        .interact_text()?;
    let region = if region.is_empty() {
        None
    } else {
        Some(region)
    };

    // Try to list existing secrets
    let secret_name = match list_aws_secrets(region.as_deref()).await {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let choice = Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if choice == items.len() - 1 {
                Input::new()
                    .with_prompt("AWS Secrets Manager secret name")
                    .default("vta-master-seed".into())
                    .interact_text()?
            } else {
                items.swap_remove(choice)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found.");
            Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
        Err(e) => {
            eprintln!("  Warning: could not list secrets: {e}");
            Input::new()
                .with_prompt("AWS Secrets Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
    };

    Ok(SecretsConfig {
        aws_secret_name: Some(secret_name),
        aws_region: region,
        ..Default::default()
    })
}

/// List secret names from AWS Secrets Manager (single page).
#[cfg(feature = "aws-secrets")]
async fn list_aws_secrets(region: Option<&str>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut config_loader = aws_config::from_env();
    if let Some(region) = region {
        config_loader = config_loader.region(aws_config::Region::new(region.to_owned()));
    }
    let sdk_config = config_loader.load().await;
    let client = aws_sdk_secretsmanager::Client::new(&sdk_config);

    let output = client.list_secrets().send().await?;
    let names: Vec<String> = output
        .secret_list()
        .iter()
        .filter_map(|entry| entry.name().map(String::from))
        .collect();
    Ok(names)
}

#[cfg(feature = "gcp-secrets")]
async fn prompt_gcp_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;

    // Try to list existing secrets
    let secret_name = match list_gcp_secrets(&project).await {
        Ok(names) if !names.is_empty() => {
            let mut items: Vec<String> = names;
            items.push("Create new secret".into());
            let choice = Select::new()
                .with_prompt("Select an existing secret or create a new one")
                .items(&items)
                .default(0)
                .interact()?;
            if choice == items.len() - 1 {
                Input::new()
                    .with_prompt("GCP Secret Manager secret name")
                    .default("vta-master-seed".into())
                    .interact_text()?
            } else {
                items.swap_remove(choice)
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found.");
            Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
        Err(e) => {
            eprintln!("  Warning: could not list secrets: {e}");
            Input::new()
                .with_prompt("GCP Secret Manager secret name")
                .default("vta-master-seed".into())
                .interact_text()?
        }
    };

    Ok(SecretsConfig {
        gcp_project: Some(project),
        gcp_secret_name: Some(secret_name),
        ..Default::default()
    })
}

/// List secret names from GCP Secret Manager (single page).
#[cfg(feature = "gcp-secrets")]
async fn list_gcp_secrets(project: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
        .build()
        .await?;
    let response = client
        .list_secrets()
        .set_parent(format!("projects/{project}"))
        .send()
        .await?;

    let prefix = format!("projects/{project}/secrets/");
    let names: Vec<String> = response
        .secrets
        .iter()
        .map(|s| s.name.strip_prefix(&prefix).unwrap_or(&s.name).to_owned())
        .collect();
    Ok(names)
}

#[cfg(feature = "azure-secrets")]
async fn prompt_azure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let vault_url: String = Input::new()
        .with_prompt("Azure Key Vault URL (e.g. https://my-vault.vault.azure.net)")
        .interact_text()?;

    let secret_name: String = Input::new()
        .with_prompt("Azure Key Vault secret name")
        .default("vta-master-seed".into())
        .interact_text()?;

    Ok(SecretsConfig {
        azure_vault_url: Some(vault_url),
        azure_secret_name: Some(secret_name),
        ..Default::default()
    })
}

pub async fn run_setup_wizard(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Welcome to the VTA setup wizard.\n");

    // 1. Config file path
    let default_path = config_path
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            std::env::var("VTA_CONFIG_PATH").unwrap_or_else(|_| "config.toml".into())
        });
    let config_path: String = Input::new()
        .with_prompt("Config file path")
        .default(default_path)
        .interact_text()?;
    let config_path = PathBuf::from(&config_path);

    if config_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                config_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 2. VTA name
    let vta_name: String = Input::new()
        .with_prompt("VTA name (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let vta_name = if vta_name.is_empty() {
        None
    } else {
        Some(vta_name)
    };

    // 3. Services to enable
    let (enable_rest, enable_didcomm) = prompt_services()?;

    // 4. Public URL, host, port (only when REST is enabled)
    let (public_url, host, port) = if enable_rest {
        let public_url: String = Input::new()
            .with_prompt("Public URL for this VTA (leave empty to skip)")
            .allow_empty(true)
            .interact_text()?;
        let public_url = if public_url.is_empty() {
            None
        } else {
            Some(public_url)
        };

        let host: String = Input::new()
            .with_prompt("Server host")
            .default("0.0.0.0".into())
            .interact_text()?;

        let port: u16 = Input::new()
            .with_prompt("Server port")
            .default(8100u16)
            .interact_text()?;

        (public_url, host, port)
    } else {
        (
            None,
            ServerConfig::default().host,
            ServerConfig::default().port,
        )
    };

    // 6. Log level
    let log_level: String = Input::new()
        .with_prompt("Log level")
        .default("info".into())
        .interact_text()?;

    // 7. Log format
    let log_format_items = &["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(log_format_items)
        .default(0)
        .interact()?;
    let log_format = match log_format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 8. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/vta".into())
        .interact_text()?;

    // 9. If data directory already exists, offer to delete and start fresh
    let data_path = PathBuf::from(&data_dir);
    if data_path.exists() {
        let delete = Confirm::new()
            .with_prompt(format!(
                "Data directory \"{}\" already exists. Delete and start fresh?",
                data_dir
            ))
            .default(false)
            .interact()?;
        if delete {
            std::fs::remove_dir_all(&data_path)?;
            eprintln!("  Deleted existing data directory.");
        } else {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 10. Open the store so we can persist key records during DID creation
    let store = Store::open(&StoreConfig {
        data_dir: PathBuf::from(&data_dir),
    })?;
    let keys_ks = store.keyspace("keys")?;
    let imported_ks = store.keyspace("imported_secrets")?;
    let contexts_ks = store.keyspace("contexts")?;
    let webvh_ks = store.keyspace("webvh")?;

    // Create seed application contexts
    let mut vta_ctx = create_seed_context(&contexts_ks, "vta", "Verifiable Trust Agent").await?;
    eprintln!("  Created application context: vta");

    // 10. BIP-39 mnemonic
    let mnemonic_options = &["Generate new 24-word mnemonic", "Import existing mnemonic"];
    let mnemonic_choice = Select::new()
        .with_prompt("BIP-39 mnemonic")
        .items(mnemonic_options)
        .default(0)
        .interact()?;

    let mnemonic: Mnemonic = match mnemonic_choice {
        0 => {
            let mut entropy = [0u8; 32];
            rand::rng().fill_bytes(&mut entropy);
            let m = Mnemonic::from_entropy(&entropy)?;

            eprintln!();
            eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
            eprintln!("║  WARNING: Write down your mnemonic phrase and store it   ║");
            eprintln!("║  securely. It is the ONLY way to recover your keys.      ║");
            eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
            eprintln!();
            eprintln!("\x1b[1m{}\x1b[0m", m);
            eprintln!();

            let confirmed = Confirm::new()
                .with_prompt("I have saved my mnemonic phrase")
                .default(false)
                .interact()?;
            if !confirmed {
                eprintln!("Setup cancelled — please save your mnemonic before proceeding.");
                return Ok(());
            }

            m
        }
        _ => {
            let phrase: String = Input::new()
                .with_prompt("Enter your BIP-39 mnemonic phrase")
                .validate_with(|input: &String| -> Result<(), String> {
                    Mnemonic::parse(input.as_str())
                        .map(|_| ())
                        .map_err(|e| format!("Invalid mnemonic: {e}"))
                })
                .interact_text()?;
            Mnemonic::parse(&phrase)?
        }
    };

    // Prompt for seed store backend configuration
    let mut secrets_config = configure_secrets().await?;

    // Derive BIP-39 seed
    let seed = mnemonic.to_seed("");

    // Store seed via the configured backend
    if secrets_config.seed.is_some() {
        // config-seed backend: hex-encode seed into the config (persisted when config is saved)
        secrets_config.seed = Some(hex::encode(seed));
    } else {
        // All other backends: store via the seed store
        let seed_store = create_seed_store(&AppConfig {
            vta_did: None,
            vta_name: None,
            public_url: None,
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: StoreConfig {
                data_dir: PathBuf::from("data/vta"),
            },
            services: ServicesConfig::default(),
            messaging: None,
            auth: AuthConfig::default(),
            audit: Default::default(),
            secrets: secrets_config.clone(),
            #[cfg(feature = "tee")]
            tee: Default::default(),
            resolver_url: None,
            config_path: config_path.clone(),
        })
        .map_err(|e| format!("{e}"))?;
        seed_store.set(&seed).await.map_err(|e| format!("{e}"))?;
    }

    // Create initial seed record (generation 0)
    let initial_seed_record = SeedRecord {
        id: 0,
        seed_hex: None,
        created_at: Utc::now(),
        retired_at: None,
    };
    save_seed_record(&keys_ks, &initial_seed_record).await?;
    set_active_seed_id(&keys_ks, 0).await?;

    // 11. Generate random JWT signing key
    let mut jwt_key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut jwt_key_bytes);
    let jwt_signing_key = BASE64.encode(jwt_key_bytes);

    // Create a temporary AppConfig for the seed store (config hasn't been saved yet)
    let wizard_config = AppConfig {
        vta_did: None,
        vta_name: None,
        public_url: public_url.clone(),
        server: ServerConfig {
            host: host.clone(),
            port,
        },
        log: LogConfig::default(),
        store: StoreConfig {
            data_dir: PathBuf::from(&data_dir),
        },
        services: ServicesConfig::default(),
        messaging: None,
        auth: AuthConfig::default(),
        audit: Default::default(),
        secrets: secrets_config.clone(),
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path: config_path.clone(),
    };
    let wizard_seed_store: Arc<dyn crate::keys::seed_store::SeedStore> =
        Arc::from(create_seed_store(&wizard_config).map_err(|e| format!("{e}"))?);

    // 12. DIDComm messaging
    let messaging = if enable_didcomm {
        configure_messaging(
            &keys_ks,
            &imported_ks,
            &contexts_ks,
            &webvh_ks,
            &*wizard_seed_store,
            &wizard_config,
        )
        .await?
    } else {
        None
    };

    // 13. VTA DID (after mediator so we can embed it as a service endpoint)
    let vta_did = create_vta_did(
        messaging.as_ref(),
        &public_url,
        &keys_ks,
        &imported_ks,
        &contexts_ks,
        &webvh_ks,
        &*wizard_seed_store,
        &wizard_config,
    )
    .await?;

    // Update VTA context with the DID
    if let Some(ref did) = vta_did {
        vta_ctx.did = Some(did.clone());
        vta_ctx.updated_at = Utc::now();
        store_context(&contexts_ks, &vta_ctx)
            .await
            .map_err(|e| format!("{e}"))?;
    }

    // 14. Bootstrap admin DID in ACL (optional)
    let admin_did = if let Some((admin_did, _credential)) = create_admin_did(
        &seed,
        &vta_did,
        &public_url,
        &vta_ctx.base_path,
        &keys_ks,
        &imported_ks,
        &contexts_ks,
        &webvh_ks,
        &*wizard_seed_store,
        &wizard_config,
    )
    .await?
    {
        let acl_ks = store.keyspace("acl")?;
        let admin_entry = AclEntry {
            did: admin_did.clone(),
            role: Role::Admin,
            label: Some("Initial admin".into()),
            allowed_contexts: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: "setup".into(),
        };
        store_acl_entry(&acl_ks, &admin_entry).await?;
        eprintln!("  Admin DID added to ACL: {admin_did}");
        Some(admin_did)
    } else {
        None
    };

    // Flush all store writes to disk before exiting
    store.persist().await?;

    // 15. Save config
    let config = AppConfig {
        vta_did,
        vta_name,
        public_url: public_url.clone(),
        server: ServerConfig { host, port },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(data_dir),
        },
        services: ServicesConfig {
            rest: enable_rest,
            didcomm: enable_didcomm,
        },
        messaging,
        auth: AuthConfig {
            jwt_signing_key: Some(jwt_signing_key),
            ..AuthConfig::default()
        },
        audit: Default::default(),
        secrets: secrets_config,
        #[cfg(feature = "tee")]
        tee: Default::default(),
        resolver_url: None,
        config_path: config_path.clone(),
    };
    config.save()?;

    // 16. Summary
    eprintln!();
    eprintln!("\x1b[1;32mSetup complete!\x1b[0m");
    eprintln!("  Config saved to: {}", config_path.display());
    eprintln!("  Seed stored in configured backend");
    // Print which seed backend was chosen
    {
        let mut _printed = false;
        #[cfg(feature = "aws-secrets")]
        if let Some(ref name) = config.secrets.aws_secret_name {
            let region = config
                .secrets
                .aws_region
                .as_deref()
                .unwrap_or("SDK default");
            eprintln!("  Seed backend: AWS Secrets Manager ({name} in {region})");
            _printed = true;
        }
        #[cfg(feature = "gcp-secrets")]
        if !_printed && let Some(ref name) = config.secrets.gcp_secret_name {
            let project = config.secrets.gcp_project.as_deref().unwrap_or("unknown");
            eprintln!("  Seed backend: GCP Secret Manager ({project}/{name})");
            _printed = true;
        }
        #[cfg(feature = "azure-secrets")]
        if !_printed && let Some(ref url) = config.secrets.azure_vault_url {
            let name = config
                .secrets
                .azure_secret_name
                .as_deref()
                .unwrap_or("vta-master-seed");
            eprintln!("  Seed backend: Azure Key Vault ({url}/{name})");
            _printed = true;
        }
        if !_printed && config.secrets.seed.is_some() {
            eprintln!("  Seed backend: config file (hex-encoded in config.toml)");
            _printed = true;
        }
        #[cfg(feature = "keyring")]
        if !_printed {
            eprintln!(
                "  Seed backend: OS keyring (service: \"{}\")",
                config.secrets.keyring_service
            );
        }
    }
    if let Some(name) = &config.vta_name {
        eprintln!("  VTA Name: {name}");
    }
    if let Some(url) = &config.public_url {
        eprintln!("  Public URL: {url}");
    }
    if let Some(did) = &config.vta_did {
        eprintln!("  VTA DID: {did}");
    }
    let mut svc_list = Vec::new();
    if config.services.rest {
        svc_list.push("REST");
    }
    if config.services.didcomm {
        svc_list.push("DIDComm");
    }
    eprintln!("  Services: {}", svc_list.join(", "));
    eprintln!("  Server: {}:{}", config.server.host, config.server.port);
    if let Some(msg) = &config.messaging {
        eprintln!("  Mediator DID: {}", msg.mediator_did);
        if !msg.mediator_url.is_empty() {
            eprintln!("  Mediator URL: {}", msg.mediator_url);
        }
    }
    eprintln!("  Contexts: vta ({})", vta_ctx.base_path);
    if let Some(did) = &admin_did {
        eprintln!("  Admin DID: {did}");
    } else {
        eprintln!("  Admin DID: (skipped — use `vta import-did` or the API to add one later)");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared DID creation helper
// ---------------------------------------------------------------------------

/// Interactive did:webvh creation using the operations layer.
///
/// Prompts for URL, offers simple/advanced mode, builds params, calls
/// `operations::create_did_webvh()`, saves did.jsonl, optionally exports secrets.
///
/// `additional_services` lets callers inject custom services (e.g. mediator endpoints).
#[allow(clippy::too_many_arguments)]
async fn build_wizard_did(
    label: &str,
    context_id: &str,
    additional_services: Option<Vec<serde_json::Value>>,
    add_mediator_service: bool,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    // Prompt for URL
    let webvh_url = prompt_webvh_url(label)?;
    let url_str = webvh_url
        .get_http_url(None)
        .map_err(|e| format!("{e}"))?
        .to_string();

    // Simple vs advanced toggle
    let mode_options = &[
        "Simple — VTA creates keys and document (recommended)",
        "Advanced — provide your own document, keys, or pre-signed log",
    ];
    let mode_choice = Select::new()
        .with_prompt("DID creation mode")
        .items(mode_options)
        .default(0)
        .interact()?;

    let (did_document, did_log, signing_key_id, ka_key_id) = if mode_choice == 1 {
        // Advanced mode
        let adv_options = &[
            "Provide a DID Document template (VTA signs it)",
            "Import a pre-signed did.jsonl",
            "Use existing imported keys",
        ];
        let adv_choice = Select::new()
            .with_prompt("Advanced option")
            .items(adv_options)
            .default(0)
            .interact()?;

        match adv_choice {
            0 => {
                // Template mode
                let path: String = Input::new()
                    .with_prompt("Path to DID Document JSON file")
                    .interact_text()?;
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read {path}: {e}"))?;
                let doc: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|e| format!("invalid JSON in {path}: {e}"))?;
                (Some(doc), None, None, None)
            }
            1 => {
                // Final mode
                let path: String = Input::new()
                    .with_prompt("Path to did.jsonl file")
                    .interact_text()?;
                let log = std::fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read {path}: {e}"))?;
                (None, Some(log), None, None)
            }
            _ => {
                // User-specified keys
                let signing: String = Input::new()
                    .with_prompt("Signing key ID (Ed25519)")
                    .interact_text()?;
                let ka: String = Input::new()
                    .with_prompt("Key-agreement key ID (X25519, leave empty to skip)")
                    .allow_empty(true)
                    .interact_text()?;
                let ka_id = if ka.is_empty() { None } else { Some(ka) };
                (None, None, Some(signing), ka_id)
            }
        }
    } else {
        (None, None, None, None)
    };

    // Portability (skip for final mode — document is already signed)
    let portable = if did_log.is_none() {
        Confirm::new()
            .with_prompt("Make this DID portable (can move to a different domain later)?")
            .default(true)
            .interact()?
    } else {
        true
    };

    // Pre-rotation count (skip for final mode)
    let pre_rotation_count = if did_log.is_none() {
        eprintln!();
        eprintln!("  \x1b[2mPre-rotation protects against key compromise by publishing hashes");
        eprintln!("  of future keys now. Recommended: 1-3 keys.\x1b[0m");
        Input::new()
            .with_prompt("Number of pre-rotation keys")
            .default(1u32)
            .interact_text()?
    } else {
        0
    };

    let auth = cli_super_admin();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    let no_bridge: Arc<crate::didcomm_bridge::DIDCommBridge> =
        Arc::new(crate::didcomm_bridge::DIDCommBridge::new());

    let params = CreateDidWebvhParams {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(url_str.clone()),
        path: None,
        label: Some(label.to_string()),
        portable,
        add_mediator_service,
        additional_services,
        pre_rotation_count,
        did_document,
        did_log,
        set_primary: true,
        signing_key_id,
        ka_key_id,
    };

    let result = operations::did_webvh::create_did_webvh(
        keys_ks,
        imported_ks,
        contexts_ks,
        webvh_ks,
        seed_store,
        config,
        &auth,
        params,
        &did_resolver,
        &no_bridge,
        "setup",
    )
    .await
    .map_err(|e| format!("{e}"))?;

    let final_did = result.did.clone();
    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Save did.jsonl (serverless mode returns it in the response)
    if let Some(ref log_entry) = result.log_entry {
        let default_file = format!("{label}-did.jsonl");
        let did_file: String = Input::new()
            .with_prompt("Save DID log to file")
            .default(default_file)
            .interact_text()?;

        std::fs::write(&did_file, log_entry)?;
        eprintln!("  DID log saved to: {did_file}");
        eprintln!();
        eprintln!("  \x1b[2mTo self-host this DID, upload {did_file} to:");
        eprintln!("  {url_str}\x1b[0m");
    }

    // Optionally export secrets bundle
    if !result.signing_key_id.is_empty()
        && Confirm::new()
            .with_prompt("Export DID secrets bundle?")
            .default(false)
            .interact()?
    {
        // Use a temporary config to create a seed store for secret fetching
        let temp_seed_store: Arc<dyn crate::keys::seed_store::SeedStore> = Arc::from(
            crate::keys::seed_store::create_seed_store(config).map_err(|e| format!("{e}"))?,
        );
        let audit_ks = keys_ks; // Reuse keys_ks as dummy audit (no audit during setup)

        let signing_secret = operations::keys::get_key_secret(
            keys_ks,
            imported_ks,
            &temp_seed_store,
            audit_ks,
            &auth,
            &result.signing_key_id,
            "setup",
        )
        .await
        .map_err(|e| format!("failed to fetch signing key: {e}"))?;

        let mut secrets = vec![SecretEntry {
            key_id: result.signing_key_id.clone(),
            key_type: SdkKeyType::Ed25519,
            private_key_multibase: signing_secret.private_key_multibase,
        }];

        if !result.ka_key_id.is_empty() {
            let ka_secret = operations::keys::get_key_secret(
                keys_ks,
                imported_ks,
                &temp_seed_store,
                audit_ks,
                &auth,
                &result.ka_key_id,
                "setup",
            )
            .await
            .map_err(|e| format!("failed to fetch KA key: {e}"))?;

            secrets.push(SecretEntry {
                key_id: result.ka_key_id.clone(),
                key_type: SdkKeyType::X25519,
                private_key_multibase: ka_secret.private_key_multibase,
            });
        }

        let bundle = DidSecretsBundle {
            did: final_did.clone(),
            secrets,
        };
        let encoded = bundle.encode().map_err(|e| format!("{e}"))?;
        eprintln!();
        eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  WARNING: The secrets bundle contains private keys.      ║");
        eprintln!("║  Store it securely and do not share it publicly.         ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
        eprintln!();
        println!("{encoded}");
        eprintln!();
    }

    Ok(final_did)
}

// ---------------------------------------------------------------------------
// DID creation steps
// ---------------------------------------------------------------------------

/// Guide the user through creating or entering an admin DID.
///
/// Returns `Some((did, Option<credential_string>))` or `None` if skipped.
/// The credential string is only produced for the `did:key` option.
#[allow(clippy::too_many_arguments)]
async fn create_admin_did(
    seed: &[u8],
    vta_did: &Option<String>,
    public_url: &Option<String>,
    vta_base_path: &str,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<Option<(String, Option<String>)>, Box<dyn std::error::Error>> {
    let admin_options = &[
        "Generate a new did:key (Ed25519)",
        "Create a new did:webvh DID",
        "Enter an existing DID",
        "Skip (no admin credential for now)",
    ];
    let choice = Select::new()
        .with_prompt("Admin DID")
        .items(admin_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            let (did, private_key_multibase) =
                derive_and_store_did_key(seed, vta_base_path, "vta", keys_ks, Some(0)).await?;

            // Build credential bundle (same format as POST /auth/credentials)
            let vta_did_str = vta_did.clone().unwrap_or_default();
            let mut bundle = serde_json::json!({
                "did": did,
                "privateKeyMultibase": private_key_multibase,
                "vtaDid": vta_did_str,
            });
            if let Some(url) = public_url {
                bundle["vtaUrl"] = serde_json::json!(url);
            }
            let bundle_json = serde_json::to_string(&bundle)?;
            let credential = BASE64.encode(bundle_json.as_bytes());

            eprintln!();
            eprintln!("\x1b[1;32mGenerated admin DID:\x1b[0m {did}");
            eprintln!();
            eprintln!("\x1b[1;33m╔══════════════════════════════════════════════════════════╗");
            eprintln!("║  IMPORTANT: Save the credential string below.            ║");
            eprintln!("║  It contains your private key and is the ONLY way to     ║");
            eprintln!("║  authenticate as admin.                                  ║");
            eprintln!("╚══════════════════════════════════════════════════════════╝\x1b[0m");
            eprintln!();
            eprintln!("  \x1b[1m{credential}\x1b[0m");
            eprintln!();

            let confirmed = Confirm::new()
                .with_prompt("I have saved the admin credential")
                .default(false)
                .interact()?;
            if !confirmed {
                eprintln!("Setup cancelled — please save your admin credential before proceeding.");
                return Err("Admin credential not saved".into());
            }

            Ok(Some((did, Some(credential))))
        }
        1 => {
            let did = build_wizard_did(
                "admin",
                "vta",
                None,
                false,
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                seed_store,
                config,
            )
            .await?;
            Ok(Some((did, None)))
        }
        2 => {
            // Enter existing DID — just record it, no local key derivation
            let did: String = Input::new().with_prompt("Admin DID").interact_text()?;
            Ok(Some((did, None)))
        }
        _ => Ok(None),
    }
}

/// Guide the user through creating (or entering) a did:webvh DID for the VTA.
///
/// Uses the operations layer via `build_wizard_did()` with simple/advanced toggle.
///
/// Returns `Some(did_string)` or `None` if skipped.
#[allow(clippy::too_many_arguments)]
async fn create_vta_did(
    messaging: Option<&MessagingConfig>,
    public_url: &Option<String>,
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did_options = &[
        "Create a new did:webvh DID",
        "Enter an existing DID",
        "Skip (no VTA DID for now)",
    ];
    let choice = Select::new()
        .with_prompt("VTA DID")
        .items(did_options)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            // Build additional services based on config
            let mut additional_services = Vec::new();
            let add_mediator = messaging.is_some();

            // Add VTA REST service endpoint if public URL is configured
            if let Some(url) = public_url {
                additional_services.push(json!({
                    "id": "{DID}#vta-rest",
                    "type": "VTARest",
                    "serviceEndpoint": url
                }));
            }

            let services = if additional_services.is_empty() {
                None
            } else {
                Some(additional_services)
            };

            let did = build_wizard_did(
                "VTA",
                "vta",
                services,
                add_mediator,
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                seed_store,
                config,
            )
            .await?;
            Ok(Some(did))
        }
        1 => {
            let did: String = Input::new().with_prompt("VTA DID").interact_text()?;

            Ok(Some(did))
        }
        _ => Ok(None),
    }
}

/// Guide the user through DIDComm messaging configuration.
///
/// Offers three choices:
/// 1. Use an existing mediator DID (no URL needed — ATM resolves endpoints from the DID document)
/// 2. Create a new did:webvh mediator DID (creates a "mediator" context for key storage)
/// 3. Skip DIDComm messaging entirely
///
/// Returns `None` when the user chooses to skip.
#[allow(clippy::too_many_arguments)]
async fn configure_messaging(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    seed_store: &dyn crate::keys::seed_store::SeedStore,
    config: &AppConfig,
) -> Result<Option<MessagingConfig>, Box<dyn std::error::Error>> {
    let options = &[
        "Use an existing mediator DID",
        "Create a new mediator DID (did:webvh)",
        "Do not use DIDComm messaging",
    ];
    let choice = Select::new()
        .with_prompt("DIDComm messaging")
        .items(options)
        .default(0)
        .interact()?;

    match choice {
        // Existing DID — no local keys or context needed
        0 => {
            let did: String = Input::new()
                .with_prompt("Mediator DID")
                .validate_with(|input: &String| -> Result<(), String> {
                    if input.starts_with("did:") {
                        Ok(())
                    } else {
                        Err("DID must start with 'did:' (e.g. did:webvh:... or did:key:...)".into())
                    }
                })
                .interact_text()?;

            Ok(Some(MessagingConfig {
                mediator_url: String::new(),
                mediator_did: did,
                mediator_host: None,
            }))
        }
        // Create new did:webvh — needs a mediator context
        1 => {
            let mediator_url: String = Input::new().with_prompt("Mediator URL").interact_text()?;

            // Create mediator context
            let _med_ctx =
                create_seed_context(contexts_ks, "mediator", "DIDComm Messaging Mediator").await?;

            // Build mediator-specific services (DIDComm + Auth endpoints)
            let wss_url = mediator_url
                .replace("https://", "wss://")
                .replace("http://", "ws://");
            let mediator_services = vec![
                json!({
                    "id": "{DID}#didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [
                        { "accept": ["didcomm/v2"], "uri": &mediator_url },
                        { "accept": ["didcomm/v2"], "uri": format!("{wss_url}/ws") }
                    ]
                }),
                json!({
                    "id": "{DID}#auth",
                    "type": "Authentication",
                    "serviceEndpoint": format!("{mediator_url}/authenticate")
                }),
            ];

            let mediator_did = build_wizard_did(
                "mediator",
                "mediator",
                Some(mediator_services),
                false,
                keys_ks,
                imported_ks,
                contexts_ks,
                webvh_ks,
                seed_store,
                config,
            )
            .await?;

            Ok(Some(MessagingConfig {
                mediator_url,
                mediator_did,
                mediator_host: None,
            }))
        }
        // Skip DIDComm
        _ => Ok(None),
    }
}

/// Prompt the user for a URL (e.g. `https://example.com/dids/vta`) and convert
/// it to a [`WebVHURL`].  Re-prompts on invalid input.
pub(crate) fn prompt_webvh_url(label: &str) -> Result<WebVHURL, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Enter the URL where the {label} DID document will be hosted.");
    eprintln!("  Examples:");
    eprintln!("    https://example.com                -> did:webvh:{{SCID}}:example.com");
    eprintln!("    https://example.com/dids/vta       -> did:webvh:{{SCID}}:example.com:dids:vta");
    eprintln!("    http://localhost:8000               -> did:webvh:{{SCID}}:localhost%3A8000");
    eprintln!();

    loop {
        let raw: String = Input::new()
            .with_prompt(format!("{label} DID URL"))
            .default("http://localhost:8000/".into())
            .interact_text()?;

        let parsed = match Url::parse(&raw) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("\x1b[31mInvalid URL: {e} — please try again.\x1b[0m");
                continue;
            }
        };

        match WebVHURL::parse_url(&parsed) {
            Ok(webvh_url) => {
                let did_display = webvh_url.to_string();
                let http_url = webvh_url.get_http_url(None).map_err(|e| format!("{e}"))?;

                eprintln!("  DID:  {did_display}");
                eprintln!("  URL:  {http_url}");

                if Confirm::new()
                    .with_prompt("Is this correct?")
                    .default(true)
                    .interact()?
                {
                    return Ok(webvh_url);
                }
            }
            Err(e) => {
                eprintln!(
                    "\x1b[31mCould not convert to a webvh DID: {e} — please try again.\x1b[0m"
                );
            }
        }
    }
}
