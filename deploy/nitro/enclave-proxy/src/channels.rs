//! Proxy channels: inbound REST, outbound mediator, outbound HTTPS.

use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{debug, error, info, warn};

use crate::bridge::bridge;

// ---------------------------------------------------------------------------
// [1] Inbound: TCP → vsock (clients → enclave REST API)
// ---------------------------------------------------------------------------

pub async fn run_inbound(listen_port: u16, enclave_cid: u32, vsock_port: u32) {
    let listener = match TcpListener::bind(format!("0.0.0.0:{listen_port}")).await {
        Ok(l) => l,
        Err(e) => {
            error!("failed to bind TCP:{listen_port}: {e}");
            return;
        }
    };
    info!("[inbound] listening on TCP:{listen_port} → vsock CID {enclave_cid}:{vsock_port}");

    loop {
        let (tcp_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[inbound] accept error: {e}");
                continue;
            }
        };
        debug!("[inbound] connection from {peer}");

        tokio::spawn(async move {
            match VsockStream::connect(VsockAddr::new(enclave_cid, vsock_port)).await {
                Ok(vsock_stream) => {
                    if let Err(e) = bridge(tcp_stream, vsock_stream).await {
                        debug!("[inbound] bridge error: {e}");
                    }
                }
                Err(e) => {
                    warn!("[inbound] vsock connect to CID {enclave_cid}:{vsock_port} failed: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// [2] Outbound: vsock → TLS (enclave DIDComm → mediator)
// ---------------------------------------------------------------------------

pub async fn run_mediator(
    vsock_port: u32,
    mediator_host: String,
    mediator_port: u16,
) {
    let tls_connector = match build_tls_connector() {
        Ok(c) => c,
        Err(e) => {
            error!("[mediator] failed to build TLS connector: {e}");
            return;
        }
    };

    let mut listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[mediator] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };
    info!("[mediator] listening on vsock:{vsock_port} → {mediator_host}:{mediator_port} (TLS)");

    loop {
        let (vsock_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[mediator] accept error: {e}");
                continue;
            }
        };
        debug!("[mediator] connection from vsock peer {peer:?}");

        let host = mediator_host.clone();
        let connector = tls_connector.clone();
        let port = mediator_port;

        tokio::spawn(async move {
            // Connect TCP to the mediator
            let tcp_stream = match TcpStream::connect(format!("{host}:{port}")).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("[mediator] TCP connect to {host}:{port} failed: {e}");
                    return;
                }
            };

            // Upgrade to TLS
            let server_name = match rustls::pki_types::ServerName::try_from(host.as_str()) {
                Ok(sn) => sn.to_owned(),
                Err(e) => {
                    warn!("[mediator] invalid server name {host}: {e}");
                    return;
                }
            };
            let tls_stream = match connector.connect(server_name, tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("[mediator] TLS handshake with {host}:{port} failed: {e}");
                    return;
                }
            };

            if let Err(e) = bridge(vsock_stream, tls_stream).await {
                debug!("[mediator] bridge error: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// [3] Outbound: vsock → TCP (enclave HTTPS → allowlisted hosts)
// ---------------------------------------------------------------------------

/// Simple HTTPS CONNECT proxy: reads the HTTP CONNECT request from the
/// enclave, validates the target against the allowlist, establishes a TCP
/// connection, and bridges bytes bidirectionally.
pub async fn run_https_proxy(
    vsock_port: u32,
    allowlist: Vec<(String, u16)>,
) {
    let allowlist = Arc::new(allowlist);

    let mut listener = match VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port)) {
        Ok(l) => l,
        Err(e) => {
            error!("[https] failed to bind vsock:{vsock_port}: {e}");
            return;
        }
    };
    info!(
        "[https] listening on vsock:{vsock_port} — {} hosts allowlisted",
        allowlist.len()
    );

    loop {
        let (vsock_stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("[https] accept error: {e}");
                continue;
            }
        };
        debug!("[https] connection from vsock peer {peer:?}");

        let allowlist = Arc::clone(&allowlist);
        tokio::spawn(async move {
            if let Err(e) = handle_connect_request(vsock_stream, &allowlist).await {
                debug!("[https] CONNECT handler error: {e}");
            }
        });
    }
}

/// Handle an HTTP CONNECT request from the enclave.
async fn handle_connect_request(
    mut stream: VsockStream,
    allowlist: &[(String, u16)],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut buf_reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    // Parse: CONNECT host:port HTTP/1.1
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        // Not a CONNECT request — could be a plain HTTP request.
        // Forward as-is to the first allowlisted host (for simple proxy use).
        let target = &allowlist[0];
        debug!("[https] non-CONNECT request, forwarding to {}:{}", target.0, target.1);
        let tcp = TcpStream::connect(format!("{}:{}", target.0, target.1)).await?;
        // Write back the original request line
        use tokio::io::AsyncWriteExt as _;
        let mut tcp = tcp;
        tcp.write_all(request_line.as_bytes()).await?;
        drop(buf_reader);
        bridge(stream, tcp).await?;
        return Ok(());
    }

    let target = parts[1];
    let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else {
        (target.to_string(), 443)
    };

    // Consume remaining headers
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Check allowlist
    let allowed = allowlist
        .iter()
        .any(|(h, p)| h == &host && *p == port);

    if !allowed {
        warn!("[https] CONNECT to {host}:{port} BLOCKED (not in allowlist)");
        use tokio::io::AsyncWriteExt as _;
        drop(buf_reader);
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await?;
        return Ok(());
    }

    debug!("[https] CONNECT to {host}:{port} (allowed)");

    // Establish TCP connection to the target
    let tcp_stream = TcpStream::connect(format!("{host}:{port}")).await?;

    // Send 200 OK to the enclave
    drop(buf_reader);
    use tokio::io::AsyncWriteExt as _;
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Bridge raw bytes (the enclave handles TLS itself)
    bridge(stream, tcp_stream).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

fn build_tls_connector() -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}
