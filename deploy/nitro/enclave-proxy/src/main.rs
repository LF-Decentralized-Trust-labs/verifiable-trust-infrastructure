mod bridge;
mod channels;
mod config;
mod detect;

use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use config::ProxyConfig;

#[derive(Parser)]
#[command(
    name = "enclave-proxy",
    about = "VTA Nitro Enclave parent-instance proxy",
    long_about = "Bridges networking between a Nitro Enclave and the outside world.\n\
                  Reads mediator config from the VTA's config.toml automatically.\n\
                  Run on the parent EC2 instance (not inside the enclave)."
)]
pub struct Cli {
    /// Path to the VTA config.toml (auto-reads mediator, KMS region, etc.)
    #[arg(short, long, default_value = "deploy/nitro/config.toml")]
    config: PathBuf,

    /// Enclave CID (auto-detected from nitro-cli if 0)
    #[arg(long, default_value_t = 0)]
    enclave_cid: u32,

    /// External REST API listen port
    #[arg(long, default_value_t = 8443)]
    listen_port: u16,

    /// Vsock port for inbound REST (enclave-side)
    #[arg(long, default_value_t = 5100)]
    vsock_inbound: u32,

    /// Vsock port for outbound mediator (enclave-side)
    #[arg(long, default_value_t = 5200)]
    vsock_mediator: u32,

    /// Vsock port for outbound HTTPS (enclave-side)
    #[arg(long, default_value_t = 5300)]
    vsock_https: u32,

    /// DID resolver URL (enclave resolves DIDs through this)
    #[arg(long, default_value = "https://dev.uniresolver.io")]
    resolver_url: String,

    /// Additional hosts to allowlist for HTTPS proxy (host:port)
    #[arg(trailing_var_arg = true)]
    allowlist: Vec<String>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let mut cli = Cli::parse();

    // Auto-detect enclave CID if not provided
    if cli.enclave_cid == 0 {
        cli.enclave_cid = match detect::detect_enclave_cid() {
            Some(cid) => cid,
            None => {
                error!("no running enclave found — start one first:");
                error!("  nitro-cli run-enclave --eif-path vta.eif --cpu-count 1 --memory 512");
                std::process::exit(1);
            }
        };
    }

    // Load proxy config from VTA config.toml
    let config = ProxyConfig::load(&cli.config, &cli);
    let allowlist = config.build_allowlist();

    // Print banner
    eprintln!();
    eprintln!("=========================================");
    eprintln!("  VTA Enclave Proxy");
    eprintln!("=========================================");
    eprintln!();
    eprintln!("  Config:      {}", cli.config.display());
    eprintln!("  Enclave CID: {}", config.enclave_cid);
    eprintln!();
    eprintln!("  [1] Inbound  REST:     0.0.0.0:{} → vsock:{}", config.listen_port, config.vsock_inbound_port);
    if let Some(ref host) = config.mediator_host {
        eprintln!("  [2] Outbound Mediator: vsock:{} → {}:{} (TLS)", config.vsock_mediator_port, host, config.mediator_port);
    } else {
        eprintln!("  [2] Outbound Mediator: DISABLED (no mediator configured)");
    }
    eprintln!("  [3] Outbound HTTPS:    vsock:{} → {} hosts allowlisted", config.vsock_https_port, allowlist.len());
    for (host, port) in &allowlist {
        eprintln!("       - {host}:{port}");
    }
    eprintln!();
    eprintln!("  Test:");
    eprintln!("    curl http://localhost:{}/health", config.listen_port);
    eprintln!("    curl http://localhost:{}/attestation/status", config.listen_port);
    eprintln!();

    // Spawn all proxy channels as concurrent tasks
    let inbound = tokio::spawn(channels::run_inbound(
        config.listen_port,
        config.enclave_cid,
        config.vsock_inbound_port,
    ));

    let mediator = if let Some(host) = config.mediator_host.clone() {
        Some(tokio::spawn(channels::run_mediator(
            config.vsock_mediator_port,
            host,
            config.mediator_port,
        )))
    } else {
        None
    };

    let https = tokio::spawn(channels::run_https_proxy(
        config.vsock_https_port,
        allowlist,
    ));

    info!("all proxy channels started — press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await.ok();
    info!("shutting down");

    // Cancel all tasks
    inbound.abort();
    if let Some(m) = mediator {
        m.abort();
    }
    https.abort();
}
