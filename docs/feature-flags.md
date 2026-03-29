# Feature Flags

The VTA workspace uses Cargo feature flags to control which capabilities are
compiled in. This document lists all flags, their purpose, dependencies, and
which deployment modes use them.

## vta-service features

These are the flags on the `vta-service` library crate. Front-end binaries
(`vta-enclave`, etc.) forward relevant flags to `vta-service`.

| Feature | Purpose | Dependencies |
|---------|---------|-------------|
| `rest` | REST API endpoints (axum routes) | None |
| `didcomm` | DIDComm v2 messaging transport | None |
| `tee` | TEE attestation types, providers, KMS bootstrap | `libc`, `hmac`, `aws-sdk-kms`, `aws-config`, `rsa`, `didwebvh-rs` |
| `webvh` | did:webvh DID management (create, update, delete) | `didwebvh-rs`, `url`, `reqwest` |
| `setup` | Interactive setup wizard (requires TTY) | `webvh`, `tempfile` |
| `keyring` | OS keyring seed storage | `keyring` |
| `config-seed` | Load seed from config file | None |
| `aws-secrets` | AWS Secrets Manager seed storage | `aws-sdk-secretsmanager`, `aws-config` |
| `gcp-secrets` | GCP Secret Manager seed storage | `google-cloud-secretmanager`, `google-cloud-auth`, `bytes` |
| `azure-secrets` | Azure Key Vault seed storage | `azure_security_keyvault_secrets`, `azure_identity` |
| `vsock-store` | Vsock-proxied persistent storage (for enclaves) | `vti-common/vsock-store` |
| `vsock-log` | Vsock-proxied log forwarding (for enclaves) | `vti-common/vsock-log` |

**Default features:** `setup`, `keyring`, `rest`, `didcomm`

**Compile-time constraint:** At least one of `rest` or `didcomm` must be
enabled, or the build fails with a compile error.

## Feature dependency graph

```
default = [setup, keyring, rest, didcomm]

setup ──→ webvh ──→ [didwebvh-rs, url, reqwest]

tee ──→ [libc, hmac, aws-sdk-kms, aws-config, rsa, didwebvh-rs]

vsock-store ──→ vti-common/vsock-store ──→ [tokio-vsock, libc]
```

**Key relationships:**
- `setup` automatically enables `webvh` (the wizard creates did:webvh identities)
- `tee` pulls in `didwebvh-rs` (for automatic DID generation on first boot)
- `vsock-store` is a cross-crate feature chain: `vta-enclave` → `vta-service` → `vti-common`

## vti-common features

| Feature | Purpose |
|---------|---------|
| `encryption` | AES-256-GCM encryption for `KeyspaceHandle.with_encryption()` |
| `vsock-store` | `VsockStore` and `VsockKeyspaceHandle` for vsock-proxied storage |

## vta-enclave features

| Feature | Purpose |
|---------|---------|
| `rest` | Forwards to `vta-service/rest` |
| `didcomm` | Forwards to `vta-service/didcomm` |
| `webvh` | Forwards to `vta-service/webvh` |
| `vsock-store` | Forwards to `vta-service/vsock-store` |

The `tee` feature is always enabled on `vta-service` (hardcoded in the
dependency: `features = ["tee"]`). No need to specify it.

## Deployment profiles

| Profile | vta-service binary | vta-enclave binary |
|---------|-------------------|-------------------|
| Local development | `default` (setup, keyring, rest, didcomm) | N/A |
| Nitro Hardened (DIDComm only) | N/A | `didcomm,vsock-store` |
| Nitro Full API (REST + DIDComm) | N/A | `rest,didcomm,vsock-store` |
| Nitro REST only | N/A | `rest,vsock-store` |
| Cloud (no TEE) | `rest,didcomm,aws-secrets` | N/A |

## Secret storage priority

When multiple secret storage features are enabled, the `create_seed_store()`
function checks backends in this order:

1. AWS Secrets Manager (`aws-secrets` + config set)
2. GCP Secret Manager (`gcp-secrets` + config set)
3. Azure Key Vault (`azure-secrets` + config set)
4. Config file (`config-seed` + config set)
5. OS keyring (`keyring` — default)
6. Plaintext file (always available fallback)

In TEE mode (vta-enclave), KMS bootstrap provides the seed directly —
none of the above backends are used.
