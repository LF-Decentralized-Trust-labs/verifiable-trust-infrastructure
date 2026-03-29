# vti-common

Shared server-side infrastructure for VTA and VTC services in the
[Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace.

## Overview

`vti-common` provides the foundational types and implementations shared across
the VTA and VTC service crates:

- **Store abstraction** -- `Store` and `KeyspaceHandle` enum dispatch to either
  a local fjall embedded database or a vsock-proxied backend (for TEE enclaves).
  Both variants support transparent AES-256-GCM encryption via `.with_encryption()`.
- **Auth infrastructure** -- JWT encoding/decoding (EdDSA / Ed25519), session
  management, and axum `FromRequestParts` extractors (`AuthClaims`, `ManageAuth`,
  `AdminAuth`, `SuperAdminAuth`).
- **ACL** -- `AclEntry`, `Role`, CRUD operations, and validation.
- **Error types** -- `AppError` enum with `IntoResponse` for consistent HTTP
  error handling.
- **Config types** -- `AuthConfig`, `LogConfig`, `StoreConfig`,
  `MessagingConfig`, `AuditConfig` shared across services.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `encryption` | No | AES-256-GCM encryption for `KeyspaceHandle.with_encryption()` |
| `vsock-store` | No | `VsockStore` + `VsockKeyspaceHandle` (Linux only -- requires `tokio-vsock`) |

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
vti-common = "0.2"

# With encryption support
vti-common = { version = "0.2", features = ["encryption"] }
```

## License

Apache-2.0
