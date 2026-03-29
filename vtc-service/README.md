# vtc-service

Verifiable Trust Community (VTC) service for the
[First Person Network](https://www.firstperson.network/white-paper). Part of the
[Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace.

## Overview

A VTC manages a community of Verifiable Trust Agents. Unlike the VTA (which
manages cryptographic keys), the VTC handles community management, access
control, and DIDComm messaging.

Key differences from the VTA:

- **No key management** -- no BIP-32 derivation or key storage.
- **No contexts** -- community-scoped rather than context-scoped.
- **DIDComm messaging** -- receives key material from VTAs rather than
  generating it locally.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `setup` | Yes | Interactive setup wizard and `did:webvh` creation |
| `keyring` | Yes | OS keyring seed storage backend |
| `config-secret` | No | Store secrets in the TOML config file |
| `aws-secrets` | No | AWS Secrets Manager backend |
| `gcp-secrets` | No | Google Cloud Secret Manager backend |
| `azure-secrets` | No | Azure Key Vault backend |

## Quick Start

```sh
# Build
cargo build --package vtc-service

# Run the interactive setup wizard
vtc setup

# Start the server
vtc

# Start with a custom config file
vtc --config /path/to/config.toml
```

The VTC listens on port 8200 by default (configurable via `VTC_SERVER_PORT`).

## Configuration

Configuration is loaded from a TOML file (default: `config.toml`). All fields
can be overridden with environment variables using the `VTC_` prefix (e.g.
`VTC_SERVER_HOST`, `VTC_SERVER_PORT`, `VTC_LOG_LEVEL`).

## License

Apache-2.0
