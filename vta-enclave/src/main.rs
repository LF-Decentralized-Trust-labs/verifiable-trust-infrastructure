//! VTA binary for AWS Nitro Enclaves (TEE mode).
//!
//! This binary handles TEE-specific bootstrapping:
//! - VsockStore connection to parent's persistent storage proxy
//! - KMS secret bootstrap (seed + JWT key generation/decryption)
//! - TEE provider initialization (Nitro/SEV-SNP/Simulated)
//! - Mnemonic export guard
//! - Automatic did:webvh identity generation
//!
//! After bootstrapping, it calls vta_service::server::run() with
//! the TeeContext — the same server code as the local VTA binary.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use clap::Parser;
use tracing::info;

use vta_service::config::AppConfig;
use vta_service::keys::seed_store::{KmsTeeSeedStore, SeedStore};
use vta_service::server::TeeContext;
use vta_service::store;
use vta_service::tee;

#[cfg(not(any(feature = "rest", feature = "didcomm")))]
compile_error!("At least one of 'rest' or 'didcomm' must be enabled.");

#[derive(Parser)]
#[command(name = "vta", about = "Verifiable Trust Agent (TEE Enclave mode)")]
struct Cli {
    /// Path to config file
    #[arg(long, short)]
    config: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load config
    let config = match AppConfig::load(cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    vta_service::init_tracing(&config);
    print_banner();

    // ── Open store (vsock-proxied or local) ──
    #[cfg(feature = "vsock-store")]
    let store = if config.tee.kms.is_some() {
        let vs = store::VsockStore::connect(None)
            .await
            .expect("failed to connect to vsock storage proxy");
        store::Store::Vsock(vs)
    } else {
        store::Store::open(&config.store).expect("failed to open store")
    };
    #[cfg(not(feature = "vsock-store"))]
    let store = store::Store::open(&config.store).expect("failed to open store");

    // ── KMS secret bootstrap (uses the store for ciphertext K/V storage) ──
    let tee_bootstrap = if let Some(ref kms_config) = config.tee.kms {
        Some(
            tee::kms_bootstrap::bootstrap_secrets(
                kms_config,
                &config.tee.storage_key_salt,
                &store,
            )
            .await
            .expect("TEE KMS bootstrap failed"),
        )
    } else {
        None
    };

    // ── Seed store ──
    let seed_store: Arc<dyn SeedStore> = if let Some(ref bootstrap) = tee_bootstrap {
        let kms_config = config.tee.kms.as_ref().unwrap();
        Arc::new(KmsTeeSeedStore::new(
            bootstrap.seed.clone(),
            kms_config.key_arn.clone(),
            kms_config.region.clone(),
        ))
    } else {
        Arc::from(
            vta_service::keys::seed_store::create_seed_store(&config)
                .expect("failed to create seed store"),
        )
    };

    // ── JWT signing key + storage encryption key from bootstrap ──
    let (mut config, storage_encryption_key) = if let Some(ref bootstrap) = tee_bootstrap {
        let mut config = config;
        let jwt_b64 = BASE64.encode(&bootstrap.jwt_signing_key);
        config.auth.jwt_signing_key = Some(jwt_b64);
        (config, Some(bootstrap.storage_key))
    } else {
        (config, None)
    };

    // ── Mnemonic export guard ──
    let mnemonic_guard = {
        let export_window: Option<u64> = std::env::var("VTA_MNEMONIC_EXPORT_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok());

        if let Some(ref bootstrap) = tee_bootstrap {
            if let (Some(entropy), Some(window_secs)) = (bootstrap.entropy, export_window) {
                Some(Arc::new(
                    tee::mnemonic_guard::MnemonicExportGuard::new(entropy, window_secs),
                ))
            } else if bootstrap.entropy.is_some() && export_window.is_none() {
                info!("first boot but VTA_MNEMONIC_EXPORT_WINDOW not set — mnemonic export disabled");
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::empty()))
            } else {
                Some(Arc::new(tee::mnemonic_guard::MnemonicExportGuard::empty()))
            }
        } else {
            None
        }
    };

    // ── Auto-generate DID identity on first boot ──
    if let Err(e) = tee::did_autogen::maybe_generate_vta_did(
        &mut config,
        &*seed_store,
        &store,
        storage_encryption_key,
    )
    .await
    {
        tracing::warn!("VTA DID auto-generation failed: {e}");
    }

    // ── Initialize TEE provider + build context ──
    let tee_context = {
        let tee_state = tee::init_tee(&config.tee).expect("TEE initialization failed");
        tee_state.map(|state| TeeContext {
            state,
            mnemonic_guard,
        })
    };

    // ── Start the server ──
    if let Err(e) = vta_service::server::run(
        config,
        store,
        seed_store,
        storage_encryption_key,
        tee_context,
    )
    .await
    {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}

// init_tracing is in vta_service::init_tracing (shared with all front-ends)

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let red = "\x1b[31m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██╗   ██╗{magenta}████████╗{yellow} █████╗{reset}
{cyan} ██║   ██║{magenta}╚══██╔══╝{yellow}██╔══██╗{reset}
{cyan} ██║   ██║{magenta}   ██║   {yellow}███████║{reset}
{cyan} ╚██╗ ██╔╝{magenta}   ██║   {yellow}██╔══██║{reset}
{cyan}  ╚████╔╝ {magenta}   ██║   {yellow}██║  ██║{reset}
{cyan}   ╚═══╝  {magenta}   ╚═╝   {yellow}╚═╝  ╚═╝{reset}
{dim}  Verifiable Trust Agent v{version}{reset}  {red}[TEE ENCLAVE]{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}
