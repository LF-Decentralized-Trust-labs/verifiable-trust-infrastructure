# CLAUDE.md — vti-common

## Purpose

`vti-common` is the **shared foundation crate** for the Verifiable Trust
Infrastructure (VTI) workspace. It provides types and implementations used
by both `vta-service` (VTA) and `vtc-service` (VTC).

## What belongs in vti-common

- **Store abstraction** — `Store`, `KeyspaceHandle` (enum dispatch to local
  fjall or vsock-proxied backends), `VsockStore`, encryption layer
- **Auth infrastructure** — JWT encoding/decoding, session management,
  auth extractors (axum `FromRequestParts` implementations)
- **ACL** — `AclEntry`, `Role`, CRUD operations, validation
- **Error types** — `AppError` enum used across all services
- **Config types** — `AuthConfig`, `LogConfig`, `StoreConfig`,
  `MessagingConfig`, `AuditConfig` (shared config shapes)

## What does NOT belong here

- VTA-specific business logic (key derivation, DID operations, credentials)
- VTC-specific logic (community management)
- CLI commands
- TEE bootstrap code (KMS, mnemonic guard)
- Route handlers

## Feature flags

| Feature | Purpose |
|---------|---------|
| `encryption` | AES-256-GCM encryption for `KeyspaceHandle.with_encryption()` |
| `vsock-store` | `VsockStore` + `VsockKeyspaceHandle` (Linux only — requires `tokio-vsock`) |

## Key modules

```
src/
├── lib.rs              Module declarations
├── acl/mod.rs          ACL types, CRUD, validation
├── auth/
│   ├── extractor.rs    AuthClaims, ManageAuth, AdminAuth, SuperAdminAuth
│   ├── jwt.rs          JWT encode/decode
│   ├── mod.rs          Re-exports
│   └── session.rs      Session state, cleanup
├── config.rs           Shared config types
├── error.rs            AppError enum + IntoResponse
└── store/
    ├── mod.rs          Store/KeyspaceHandle enums, LocalStore, LocalKeyspaceHandle
    ├── encryption.rs   AES-256-GCM encrypt/decrypt helpers
    └── vsock.rs        VsockStore, VsockKeyspaceHandle, file I/O (vsock-store feature)
```

## Store architecture

`Store` and `KeyspaceHandle` are **enums** that dispatch to either:
- `Local` — fjall embedded database (standard mode)
- `Vsock` — vsock-proxied store on the parent EC2 instance (enclave mode)

Both variants support `.with_encryption()` for transparent AES-256-GCM
encryption of values (keys remain plaintext for prefix scans).

See `docs/feature-flags.md` for the `vsock-store` feature chain.
