use serde::Deserialize;
use std::path::Path;

/// Proxy configuration, read from the VTA's config.toml.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Mediator DID (resolved via DID resolver to get the endpoint).
    pub mediator_did: Option<String>,
    /// Manual mediator host override (skips DID resolution).
    pub mediator_host_override: Option<String>,
    /// Mediator port override (default: from resolved URL, or 443).
    pub mediator_port_override: Option<u16>,
    /// KMS region (for allowlisting kms.<region>.amazonaws.com).
    pub kms_region: String,
    /// Enclave CID (auto-detected or from CLI).
    pub enclave_cid: u32,
    /// External listen port for inbound REST API.
    pub listen_port: u16,
    /// Vsock port assignments.
    pub vsock_inbound_port: u32,
    pub vsock_mediator_port: u32,
    pub vsock_https_port: u32,
    pub vsock_imds_port: u32,
    /// Extra hosts to allowlist for HTTPS proxy.
    pub allowlist_hosts: Vec<(String, u16)>,
    /// DID resolver URL.
    pub resolver_url: String,
}

/// Partial VTA config — only the fields we need.
#[derive(Debug, Deserialize, Default)]
struct VtaConfig {
    messaging: Option<MessagingConfig>,
    tee: Option<TeeConfig>,
}

#[derive(Debug, Deserialize)]
struct MessagingConfig {
    mediator_did: Option<String>,
    /// Manual override — skips DID resolution if set.
    mediator_host: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TeeConfig {
    kms: Option<KmsConfig>,
}

#[derive(Debug, Deserialize)]
struct KmsConfig {
    region: Option<String>,
}

impl ProxyConfig {
    pub fn load(config_path: &Path, cli: &super::Cli) -> Self {
        // Parse VTA config.toml (best-effort — proxy still works without it)
        let vta_config = if config_path.exists() {
            let contents = std::fs::read_to_string(config_path).unwrap_or_default();
            toml::from_str::<VtaConfig>(&contents).unwrap_or_default()
        } else {
            tracing::warn!("config file not found: {} — using defaults", config_path.display());
            VtaConfig::default()
        };

        // Mediator DID from config
        let mediator_did = std::env::var("MEDIATOR_DID").ok().or_else(|| {
            vta_config
                .messaging
                .as_ref()
                .and_then(|m| m.mediator_did.clone())
        });

        // Manual host override (env var > config > None)
        let mediator_host_override = std::env::var("MEDIATOR_HOST").ok().or_else(|| {
            vta_config
                .messaging
                .as_ref()
                .and_then(|m| m.mediator_host.clone())
        });

        let mediator_port_override = std::env::var("MEDIATOR_PORT")
            .ok()
            .and_then(|p| p.parse().ok());

        let kms_region = std::env::var("AWS_REGION").ok().unwrap_or_else(|| {
            vta_config
                .tee
                .as_ref()
                .and_then(|t| t.kms.as_ref())
                .and_then(|k| k.region.clone())
                .unwrap_or_else(|| "us-east-1".to_string())
        });

        let listen_port = std::env::var("LISTEN_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(cli.listen_port);

        let resolver_url = std::env::var("RESOLVER_URL")
            .ok()
            .unwrap_or_else(|| cli.resolver_url.clone());

        // Parse extra allowlisted hosts
        let mut allowlist_hosts: Vec<(String, u16)> = cli
            .allowlist
            .iter()
            .map(|s| parse_host_port(s))
            .collect();

        if let Ok(hosts) = std::env::var("ALLOWLIST_HOSTS") {
            for entry in hosts.split(',') {
                let entry = entry.trim();
                if !entry.is_empty() {
                    allowlist_hosts.push(parse_host_port(entry));
                }
            }
        }

        ProxyConfig {
            mediator_did,
            mediator_host_override,
            mediator_port_override,
            kms_region,
            enclave_cid: cli.enclave_cid,
            listen_port,
            vsock_inbound_port: cli.vsock_inbound,
            vsock_mediator_port: cli.vsock_mediator,
            vsock_https_port: cli.vsock_https,
            vsock_imds_port: cli.vsock_imds,
            allowlist_hosts,
            resolver_url,
        }
    }

    /// Build the full allowlist including default + mediator + resolver + extras.
    pub fn build_allowlist(&self) -> Vec<(String, u16)> {
        let mut hosts = vec![
            (format!("kms.{}.amazonaws.com", self.kms_region), 443),
        ];

        // Add manual mediator host if set
        if let Some(ref mh) = self.mediator_host_override {
            let port = self.mediator_port_override.unwrap_or(443);
            hosts.push((mh.clone(), port));
        }

        // Add resolver host
        if let Some(host) = extract_host_from_url(&self.resolver_url) {
            let port = extract_port_from_url(&self.resolver_url).unwrap_or(443);
            hosts.push((host, port));
        }

        hosts.extend(self.allowlist_hosts.clone());
        hosts
    }
}

fn extract_host_from_url(url: &str) -> Option<String> {
    url.split("://")
        .nth(1)
        .map(|rest| rest.split('/').next().unwrap_or(rest))
        .map(|host_port| host_port.split(':').next().unwrap_or(host_port).to_string())
}

fn extract_port_from_url(url: &str) -> Option<u16> {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .and_then(|host_port| host_port.split(':').nth(1))
        .and_then(|p| p.parse().ok())
}

fn parse_host_port(s: &str) -> (String, u16) {
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (s.to_string(), 443)
}
