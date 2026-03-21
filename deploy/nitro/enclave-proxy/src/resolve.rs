//! Resolve a DID via the Affinidi DID resolver and extract service endpoints.

use tracing::{debug, info, warn};

/// Resolved mediator endpoint.
#[derive(Debug, Clone)]
pub struct MediatorEndpoint {
    pub host: String,
    pub port: u16,
    /// Whether the endpoint uses TLS (wss:// or https://).
    pub tls: bool,
}

/// Resolve a mediator DID and extract the DIDComm messaging endpoint.
///
/// Calls the Universal Resolver at `resolver_url` and looks for a
/// `DIDCommMessaging` service with a `serviceEndpoint` URI.
///
/// Falls back to checking for a WebSocket URI in the endpoint.
pub async fn resolve_mediator_endpoint(
    resolver_url: &str,
    mediator_did: &str,
) -> Result<MediatorEndpoint, String> {
    let url = format!(
        "{}/1.0/identifiers/{}",
        resolver_url.trim_end_matches('/'),
        mediator_did
    );

    info!(did = mediator_did, url = %url, "resolving mediator DID via resolver");

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("resolver request to {url} failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "resolver returned HTTP {status} for {mediator_did}: {body}"
        ));
    }

    info!(did = mediator_did, "resolver returned HTTP {status}");

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("resolver response parse failed for {mediator_did}: {e}"))?;

    // The Universal Resolver returns { "didDocument": { ... } }
    // Some resolvers return the DID document directly at the top level.
    let did_doc = body
        .get("didDocument")
        .unwrap_or(&body);

    // Look for DIDCommMessaging service
    let services = did_doc
        .get("service")
        .and_then(|s| s.as_array())
        .ok_or_else(|| format!("DID document for {mediator_did} has no 'service' array"))?;

    info!(
        did = mediator_did,
        service_count = services.len(),
        "scanning DID document services for DIDCommMessaging"
    );

    for (i, svc) in services.iter().enumerate() {
        let svc_types = match svc.get("type") {
            Some(serde_json::Value::String(t)) => vec![t.as_str()],
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().filter_map(|v| v.as_str()).collect()
            }
            _ => {
                debug!(index = i, "skipping service with no/invalid type");
                continue;
            }
        };

        let svc_id = svc.get("id").and_then(|v| v.as_str()).unwrap_or("(no id)");
        debug!(index = i, id = svc_id, types = ?svc_types, "examining service");

        if !svc_types.iter().any(|t| *t == "DIDCommMessaging") {
            debug!(index = i, id = svc_id, "not DIDCommMessaging — skipping");
            continue;
        }

        // Extract the endpoint URI — handles both string and array forms
        if let Some(endpoint_uri) = extract_endpoint_uri(svc) {
            info!(
                did = mediator_did,
                service_id = svc_id,
                endpoint = %endpoint_uri,
                "found DIDCommMessaging endpoint"
            );
            let ep = parse_endpoint_url(&endpoint_uri)?;
            info!(
                host = %ep.host,
                port = ep.port,
                tls = ep.tls,
                "parsed mediator endpoint"
            );
            return Ok(ep);
        } else {
            warn!(
                index = i,
                id = svc_id,
                service_endpoint = ?svc.get("serviceEndpoint"),
                "DIDCommMessaging service found but could not extract endpoint URI"
            );
        }
    }

    // Log all service types found to help diagnose
    let all_types: Vec<&str> = services
        .iter()
        .filter_map(|s| s.get("type"))
        .flat_map(|t| match t {
            serde_json::Value::String(s) => vec![s.as_str()],
            serde_json::Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
            _ => vec![],
        })
        .collect();

    Err(format!(
        "no DIDCommMessaging service found in DID document for {mediator_did}. \
         Services present: {all_types:?}"
    ))
}

/// Extract the endpoint URI from a service entry.
///
/// Handles multiple formats:
/// - `"serviceEndpoint": "wss://example.com/ws"`
/// - `"serviceEndpoint": { "uri": "wss://..." }`
/// - `"serviceEndpoint": [{ "uri": "wss://...", "accept": [...] }]`
fn extract_endpoint_uri(svc: &serde_json::Value) -> Option<String> {
    let ep = svc.get("serviceEndpoint")?;

    // String form
    if let Some(s) = ep.as_str() {
        return Some(s.to_string());
    }

    // Object with "uri" field
    if let Some(uri) = ep.get("uri").and_then(|u| u.as_str()) {
        return Some(uri.to_string());
    }

    // Array form — take first entry with a "uri"
    if let Some(arr) = ep.as_array() {
        for item in arr {
            if let Some(uri) = item.get("uri").and_then(|u| u.as_str()) {
                return Some(uri.to_string());
            }
            // Some formats have the URI as a direct string in the array
            if let Some(s) = item.as_str() {
                return Some(s.to_string());
            }
        }
    }

    None
}

/// Parse a WebSocket or HTTPS URL into host, port, and TLS flag.
fn parse_endpoint_url(url: &str) -> Result<MediatorEndpoint, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("invalid endpoint URL (no scheme): {url}"))?;

    let tls = match scheme {
        "wss" | "https" => true,
        "ws" | "http" => false,
        _ => {
            warn!(scheme, url, "unknown scheme in mediator endpoint, assuming TLS");
            true
        }
    };

    // Split host:port from path
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p.parse::<u16>().unwrap_or(if tls { 443 } else { 80 });
        (h.to_string(), port)
    } else {
        (host_port.to_string(), if tls { 443 } else { 80 })
    };

    if host.is_empty() {
        return Err(format!("empty host in endpoint URL: {url}"));
    }

    Ok(MediatorEndpoint { host, port, tls })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wss_endpoint() {
        let ep = parse_endpoint_url("wss://mediator.example.com/ws").unwrap();
        assert_eq!(ep.host, "mediator.example.com");
        assert_eq!(ep.port, 443);
        assert!(ep.tls);
    }

    #[test]
    fn test_parse_https_with_port() {
        let ep = parse_endpoint_url("https://mediator.example.com:8443/didcomm").unwrap();
        assert_eq!(ep.host, "mediator.example.com");
        assert_eq!(ep.port, 8443);
        assert!(ep.tls);
    }

    #[test]
    fn test_parse_ws_no_tls() {
        let ep = parse_endpoint_url("ws://localhost:4443").unwrap();
        assert_eq!(ep.host, "localhost");
        assert_eq!(ep.port, 4443);
        assert!(!ep.tls);
    }

    #[test]
    fn test_extract_string_endpoint() {
        let svc = serde_json::json!({
            "type": "DIDCommMessaging",
            "serviceEndpoint": "wss://mediator.example.com/ws"
        });
        assert_eq!(
            extract_endpoint_uri(&svc).unwrap(),
            "wss://mediator.example.com/ws"
        );
    }

    #[test]
    fn test_extract_array_endpoint() {
        let svc = serde_json::json!({
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "uri": "wss://mediator.example.com/ws",
                "accept": ["didcomm/v2"]
            }]
        });
        assert_eq!(
            extract_endpoint_uri(&svc).unwrap(),
            "wss://mediator.example.com/ws"
        );
    }

    #[test]
    fn test_extract_object_endpoint() {
        let svc = serde_json::json!({
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": "wss://mediator.example.com/ws"
            }
        });
        assert_eq!(
            extract_endpoint_uri(&svc).unwrap(),
            "wss://mediator.example.com/ws"
        );
    }
}
