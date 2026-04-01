# vta-sdk

SDK for [Verifiable Trust Agents](https://github.com/OpenVTC/verifiable-trust-infrastructure)
operating in Verifiable Trust Communities. Part of the
[First Person Network](https://www.firstperson.network/white-paper) project.

## Overview

`vta-sdk` provides the types, HTTP/DIDComm client, session management, and
protocol constants needed to interact with a VTA service:

- **Types** -- shared data models for keys, contexts, ACL entries, sessions, and
  audit records.
- **HTTP client** -- typed REST client for all VTA endpoints (requires `client`
  feature).
- **DIDComm** -- DIDComm v2 message construction and secrets resolution
  (requires `didcomm` feature).
- **Session management** -- credential import, challenge-response auth, and
  automatic token refresh (requires `session` feature).
- **Integration module** -- unified startup pattern for services that manage
  their DID and keys through a VTA (requires `integration` feature).

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | No | VTA HTTP client (`reqwest`-based) with lightweight auth |
| `didcomm` | No | DIDComm v2 message support |
| `session` | No | Full session management (implies `client` + `didcomm`) |
| `integration` | No | Service startup module with offline resilience (implies `client` + `session`) |
| `keyring` | No | OS keyring session storage |
| `config-session` | No | File-based session storage |
| `azure-secrets` | No | Azure Key Vault secrets resolver |

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
# Types only (no network)
vta-sdk = "0.4"

# Full client with session management
vta-sdk = { version = "0.4", features = ["session", "keyring"] }

# Service integration with offline resilience
vta-sdk = { version = "0.4", features = ["integration"] }
```

### Quick Start: Service Integration

The `integration` module provides a one-call startup pattern for services
that delegate key management to a VTA:

```rust,ignore
use vta_sdk::integration::{startup, VtaServiceConfig, SecretCache};

// 1. Implement SecretCache for your storage backend
struct MyCache;
impl SecretCache for MyCache {
    async fn store(&self, bundle: &DidSecretsBundle) -> Result<(), Box<dyn Error>> { /* ... */ }
    async fn load(&self) -> Result<Option<DidSecretsBundle>, Box<dyn Error>> { /* ... */ }
}

// 2. Configure and start
let config = VtaServiceConfig {
    credential: std::fs::read_to_string("credential.b64")?,
    context: "my-service".into(),
    url_override: None,
};

let result = startup(&config, &MyCache).await?;
// result.did      — your service's DID
// result.bundle   — private keys for DIDComm/signing
// result.source   — SecretSource::Vta or SecretSource::Cache
// result.client   — Some(VtaClient) when VTA is reachable
```

See the [Integration Guide](../docs/integration-guide.md) for the full walkthrough.

### Quick Start: Direct Client

```rust,ignore
use vta_sdk::prelude::*;

// Authenticate with a credential bundle
let client = VtaClient::from_credential(&credential_b64, None).await?;

// Create a key
let key = client.create_key(
    CreateKeyRequest::new(KeyType::Ed25519)
        .label("signing-key")
        .context("my-app")
).await?;

// Sign a payload
let sig = client.sign(&key.key_id, b"hello", "EdDSA").await?;
```

## License

Apache-2.0
