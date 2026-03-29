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

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | No | VTA HTTP client (`reqwest`-based) |
| `didcomm` | No | DIDComm v2 message support |
| `session` | No | Full session management (implies `client` + `didcomm`) |
| `keyring` | No | OS keyring session storage |
| `config-session` | No | File-based session storage |
| `azure-secrets` | No | Azure Key Vault secrets resolver |

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
# Types only (no network)
vta-sdk = "0.2"

# Full client with session management
vta-sdk = { version = "0.2", features = ["session", "keyring"] }
```

## License

Apache-2.0
