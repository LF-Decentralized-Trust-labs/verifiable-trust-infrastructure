use std::path::PathBuf;
use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use bip39::Mnemonic;
use chrono::Utc;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::parameters::Parameters as WebVHParameters;
use didwebvh_rs::url::WebVHURL;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
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
use crate::keys::paths::allocate_path;
use crate::keys::seed_store::create_seed_store;
use crate::keys::seeds::{SeedRecord, save_seed_record, set_active_seed_id};
use crate::keys::{self, DerivedEntityKeys, KeyType as SdkKeyType, PreRotationKeyData};
use crate::store::{KeyspaceHandle, Store};

/// Create a seed application context and store it.
async fn create_seed_context(
    contexts_ks: &KeyspaceHandle,
    id: &str,
    name: &str,
) -> Result<ContextRecord, Box<dyn std::error::Error>> {
    contexts::create_context(contexts_ks, id, name).await
}

/// Derive an admin did:key Ed25519 key from the BIP-32 seed using a
/// counter-allocated path under `base`, store it as a [`KeyRecord`],
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
    let contexts_ks = store.keyspace("contexts")?;

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
            store: StoreConfig::default(),
            services: ServicesConfig::default(),
            messaging: None,
            auth: AuthConfig::default(),
            secrets: secrets_config.clone(),
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

    // 12. DIDComm messaging
    let messaging = if enable_didcomm {
        configure_messaging(&seed, &keys_ks, &contexts_ks).await?
    } else {
        None
    };

    // 13. VTA DID (after mediator so we can embed it as a service endpoint)
    let vta_did = create_vta_did(
        &seed,
        messaging.as_ref(),
        &public_url,
        &vta_ctx.base_path,
        &keys_ks,
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
    let admin_did = if let Some((admin_did, _credential)) =
        create_admin_did(&seed, &vta_did, &public_url, &vta_ctx.base_path, &keys_ks).await?
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
        secrets: secrets_config,
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

/// Guide the user through creating or entering an admin DID.
///
/// Returns `Some((did, Option<credential_string>))` or `None` if skipped.
/// The credential string is only produced for the `did:key` option
/// (base64-encoded JSON bundle).
async fn create_admin_did(
    seed: &[u8],
    vta_did: &Option<String>,
    public_url: &Option<String>,
    vta_base_path: &str,
    keys_ks: &KeyspaceHandle,
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
            let mut derived = keys::derive_entity_keys(
                seed,
                vta_base_path,
                "Admin signing key",
                "Admin key-agreement key",
                keys_ks,
            )
            .await?;

            let did = create_webvh_did(
                &mut derived,
                "admin",
                None,
                None,
                None,
                seed,
                vta_base_path,
                "vta",
                keys_ks,
            )
            .await?;
            Ok(Some((did, None)))
        }
        2 => {
            // Enter existing DID
            let did: String = Input::new().with_prompt("Admin DID").interact_text()?;

            // Store admin entity keys with the imported DID
            let derived = keys::derive_entity_keys(
                seed,
                vta_base_path,
                "Admin signing key",
                "Admin key-agreement key",
                keys_ks,
            )
            .await?;
            keys::save_entity_key_records(&did, &derived, keys_ks, Some("vta"), Some(0)).await?;

            // Also derive and store the did:key
            let _ = derive_and_store_did_key(seed, vta_base_path, "vta", keys_ks, Some(0)).await?;

            Ok(Some((did, None)))
        }
        _ => Ok(None),
    }
}

/// Guide the user through creating (or entering) a did:webvh DID for the VTA.
///
/// The mediator is added as a DIDCommMessaging service endpoint in the VTA's
/// DID document.
///
/// Returns `Some(did_string)` or `None` if skipped.
async fn create_vta_did(
    seed: &[u8],
    messaging: Option<&MessagingConfig>,
    public_url: &Option<String>,
    vta_base_path: &str,
    keys_ks: &KeyspaceHandle,
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
            let mut derived = keys::derive_entity_keys(
                seed,
                vta_base_path,
                "VTA signing key",
                "VTA key-agreement key",
                keys_ks,
            )
            .await?;

            let did = create_webvh_did(
                &mut derived,
                "VTA",
                None,
                messaging,
                public_url.as_deref(),
                seed,
                vta_base_path,
                "vta",
                keys_ks,
            )
            .await?;
            Ok(Some(did))
        }
        1 => {
            let did: String = Input::new().with_prompt("VTA DID").interact_text()?;

            let derived = keys::derive_entity_keys(
                seed,
                vta_base_path,
                "VTA signing key",
                "VTA key-agreement key",
                keys_ks,
            )
            .await?;
            keys::save_entity_key_records(&did, &derived, keys_ks, Some("vta"), Some(0)).await?;

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
async fn configure_messaging(
    seed: &[u8],
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
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
            let did: String = Input::new().with_prompt("Mediator DID").interact_text()?;

            Ok(Some(MessagingConfig {
                mediator_url: String::new(),
                mediator_did: did,
            }))
        }
        // Create new did:webvh — needs a mediator context
        1 => {
            let mediator_url: String = Input::new().with_prompt("Mediator URL").interact_text()?;

            let mut med_ctx =
                create_seed_context(contexts_ks, "mediator", "DIDComm Messaging Mediator").await?;

            let mut derived = keys::derive_entity_keys(
                seed,
                &med_ctx.base_path,
                "Mediator signing key",
                "Mediator key-agreement key",
                keys_ks,
            )
            .await?;

            let mediator_did = create_webvh_did(
                &mut derived,
                "mediator",
                Some(&mediator_url),
                None,
                None,
                seed,
                &med_ctx.base_path,
                "mediator",
                keys_ks,
            )
            .await?;

            // Update the mediator context with the created DID
            med_ctx.did = Some(mediator_did.clone());
            med_ctx.updated_at = Utc::now();
            store_context(contexts_ks, &med_ctx)
                .await
                .map_err(|e| format!("{e}"))?;

            Ok(Some(MessagingConfig {
                mediator_url,
                mediator_did,
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

/// Prompt the user to optionally generate pre-rotation keys.
///
/// Keys are derived from the BIP-32 seed using counter-allocated paths under
/// `base`.  Key records are **not** stored here — the caller saves them after
/// the DID is created so the key_id can use the DID verification method format.
///
/// Returns `(hashes, key_data)`.  Both vecs are empty when the user declines.
pub(crate) async fn prompt_pre_rotation_keys(
    seed: &[u8],
    base: &str,
    label: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<(Vec<String>, Vec<PreRotationKeyData>), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Pre-rotation protects against an attacker changing your authorization keys.");
    eprintln!("  You generate future keys now and only publish their hashes.  When you later");
    eprintln!("  need to rotate keys, you reveal the actual key that matches the hash.");

    if !Confirm::new()
        .with_prompt("Enable key pre-rotation?")
        .default(true)
        .interact()?
    {
        return Ok((vec![], vec![]));
    }

    let root = ExtendedSigningKey::from_seed(seed)
        .map_err(|e| format!("Failed to create BIP-32 root key: {e}"))?;

    let mut hashes: Vec<String> = Vec::new();
    let mut key_data: Vec<PreRotationKeyData> = Vec::new();

    loop {
        let path = allocate_path(keys_ks, base)
            .await
            .map_err(|e| format!("{e}"))?;
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| format!("Invalid derivation path: {e}"))?;
        let derived = root
            .derive(&derivation_path)
            .map_err(|e| format!("Key derivation failed: {e}"))?;

        let secret = Secret::generate_ed25519(None, Some(derived.signing_key.as_bytes()));

        let pub_mb = secret
            .get_public_keymultibase()
            .map_err(|e| format!("{e}"))?;
        let hash = secret
            .get_public_keymultibase_hash()
            .map_err(|e| format!("{e}"))?;

        let idx = hashes.len();
        key_data.push(PreRotationKeyData {
            path,
            public_key: pub_mb.clone(),
            label: format!("{label} pre-rotation key {idx}"),
        });

        eprintln!();
        eprintln!("  publicKeyMultibase: {pub_mb}");

        hashes.push(hash);

        if !Confirm::new()
            .with_prompt(format!(
                "Generated {} pre-rotation key(s). Generate another?",
                hashes.len()
            ))
            .default(false)
            .interact()?
        {
            break;
        }
    }

    Ok((hashes, key_data))
}

/// Interactive did:webvh creation flow shared by VTA and mediator DID setup.
///
/// Prompts for a URL, builds a DID document, creates the log entry,
/// saves the `did.jsonl` file, and stores key records with DID-based key_ids.
///
/// `label` is used in prompts (e.g. "VTA" or "mediator").
///
/// Service endpoints are added based on the optional parameters:
/// - `mediator_url`: when set, adds `#didcomm` (HTTPS + WSS) and `#auth`
///   service endpoints for a mediator DID document.
/// - `messaging`: when set, adds a `#vta-didcomm` service referencing the
///   mediator DID for routing (used for the VTA DID document).
#[allow(clippy::too_many_arguments)]
async fn create_webvh_did(
    derived: &mut DerivedEntityKeys,
    label: &str,
    mediator_url: Option<&str>,
    messaging: Option<&MessagingConfig>,
    vta_public_url: Option<&str>,
    seed: &[u8],
    base: &str,
    context_id: &str,
    keys_ks: &KeyspaceHandle,
) -> Result<String, Box<dyn std::error::Error>> {
    // Prompt for URL and convert to WebVHURL
    let webvh_url = prompt_webvh_url(label)?;
    let did_id = webvh_url.to_string(); // e.g. did:webvh:{SCID}:example.com

    // Convert the Signing Key ID to be correct
    derived.signing_secret.id = [
        "did:key:",
        &derived.signing_secret.get_public_keymultibase().unwrap(),
        "#",
        &derived.signing_secret.get_public_keymultibase().unwrap(),
    ]
    .concat();

    // Build DID document
    let mut did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1"
        ],
        "id": &did_id,
        "verificationMethod": [
            {
                "id": format!("{did_id}#key-0"),
                "type": "Multikey",
                "controller": &did_id,
                "publicKeyMultibase": &derived.signing_pub
            }
        ],
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")]
    });

    // Add X25519 key agreement method
    did_document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{did_id}#key-1"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": &derived.ka_pub
        }));
    did_document["keyAgreement"] = json!([format!("{did_id}#key-1")]);

    // Add service endpoints
    let mut services = Vec::new();

    if let Some(url) = mediator_url {
        // Mediator DID: add #didcomm with HTTPS + WSS endpoints, and #auth
        let wss_url = url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        services.push(json!({
            "id": format!("{did_id}#didcomm"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [
                {
                    "accept": ["didcomm/v2"],
                    "uri": url
                },
                {
                    "accept": ["didcomm/v2"],
                    "uri": format!("{wss_url}/ws")
                }
            ]
        }));
        services.push(json!({
            "id": format!("{did_id}#auth"),
            "type": "Authentication",
            "serviceEndpoint": format!("{url}/authenticate")
        }));
    } else if let Some(msg) = messaging {
        // VTA DID: add #vta-didcomm referencing the mediator DID
        services.push(json!({
            "id": format!("{did_id}#vta-didcomm"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": msg.mediator_did
            }]
        }));
    }

    // Add #vta-rest service endpoint if a public URL is configured
    if let Some(url) = vta_public_url {
        services.push(json!({
            "id": format!("{did_id}#vta-rest"),
            "type": "VTARest",
            "serviceEndpoint": url
        }));
    }

    if !services.is_empty() {
        did_document["service"] = serde_json::Value::Array(services);
    }

    eprintln!();
    eprintln!(
        "\x1b[2mDID Document:\n{}\x1b[0m",
        serde_json::to_string_pretty(&did_document)?
    );
    eprintln!();

    // Portability
    let portable = Confirm::new()
        .with_prompt("Make this DID portable (can move to a different domain later)?")
        .default(true)
        .interact()?;

    // Pre-rotation keys (share the same counter/base as entity keys)
    let (next_key_hashes, pre_rotation_keys) =
        prompt_pre_rotation_keys(seed, base, label, keys_ks).await?;

    // Build parameters
    let parameters = WebVHParameters {
        update_keys: Some(Arc::new(vec![derived.signing_pub.clone()])),
        portable: Some(portable),
        next_key_hashes: if next_key_hashes.is_empty() {
            None
        } else {
            Some(Arc::new(next_key_hashes))
        },
        ..Default::default()
    };

    // Create the log entry
    let mut did_state = DIDWebVHState::default();
    did_state
        .create_log_entry(None, &did_document, &parameters, &derived.signing_secret)
        .map_err(|e| format!("Failed to create DID log entry: {e}"))?;

    let scid = did_state.scid.clone();
    let log_entry_state = did_state.log_entries.last().unwrap();

    let fallback_did = format!("did:webvh:{scid}:{}", webvh_url.domain);
    let final_did = match log_entry_state.log_entry.get_did_document() {
        Ok(doc) => doc
            .get("id")
            .and_then(|id| id.as_str())
            .map(String::from)
            .unwrap_or(fallback_did),
        Err(_) => fallback_did,
    };

    eprintln!("\x1b[1;32mCreated DID:\x1b[0m {final_did}");

    // Save key records now that we have the final DID
    keys::save_entity_key_records(&final_did, derived, keys_ks, Some(context_id), Some(0)).await?;

    // Save pre-rotation key records
    for (i, pk) in pre_rotation_keys.iter().enumerate() {
        keys::save_key_record(
            keys_ks,
            &format!("{final_did}#pre-rotation-{i}"),
            &pk.path,
            SdkKeyType::Ed25519,
            &pk.public_key,
            &pk.label,
            Some(context_id),
            Some(0),
        )
        .await?;
    }

    // Save did.jsonl
    let default_file = format!("{label}-did.jsonl");
    let did_file: String = Input::new()
        .with_prompt("Save DID log to file")
        .default(default_file)
        .interact_text()?;

    log_entry_state
        .log_entry
        .save_to_file(&did_file)
        .map_err(|e| format!("Failed to save DID log file: {e}"))?;

    eprintln!("  DID log saved to: {did_file}");

    // Optionally export secrets bundle
    if Confirm::new()
        .with_prompt("Export DID secrets bundle?")
        .default(false)
        .interact()?
    {
        let bundle = DidSecretsBundle {
            did: final_did.clone(),
            secrets: vec![
                SecretEntry {
                    key_id: format!("{final_did}#key-0"),
                    key_type: SdkKeyType::Ed25519,
                    private_key_multibase: derived.signing_priv.clone(),
                },
                SecretEntry {
                    key_id: format!("{final_did}#key-1"),
                    key_type: SdkKeyType::X25519,
                    private_key_multibase: derived.ka_priv.clone(),
                },
            ],
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
