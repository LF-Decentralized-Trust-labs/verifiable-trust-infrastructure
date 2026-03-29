# Changelog

## 0.2.0 — 2026-03-29

### Architecture

- **vta-service / vta-enclave split** — `vta-service` is
  now a library crate exporting all business logic.
  `vta-enclave` is a separate binary crate for Nitro
  Enclave deployments with TEE-specific bootstrap (KMS,
  vsock-store, attestation). Future front-ends (SGX,
  serverless) follow the same pattern.
- **Soft restart** — The VTA server can now restart
  in-process without a process restart. Service threads
  shut down gracefully, auth/crypto re-initialize, and
  threads restart. Exposed via `POST /vta/restart`,
  DIDComm protocol, and `pnm vta restart`.
- **Patched affinidi-messaging-didcomm-service** — Local
  patch adds `tdk_config` field to `ListenerConfig` so
  the VTA can pass its network-mode DID resolver to the
  DIDComm service listener.

### TEE / Nitro Enclave

- **KMS-based secret bootstrap** — First boot generates
  BIP-39 seed and JWT key inside the enclave, encrypts
  with KMS `GenerateDataKey` (with Nitro attestation),
  stores ciphertext. Subsequent boots decrypt via KMS
  `Decrypt` with PCR enforcement.
- **Encrypted storage** — AES-256-GCM encryption of all
  sensitive keyspaces. Key derived from seed via HKDF.
- **Auto-generated VTA identity** — `did:webvh` DID
  created automatically on first boot from a template.
- **Admin credential bootstrap** — Operator-provided
  admin DID or auto-generated `did:key` with credential
  bundle stored for retrieval.
- **Seal mechanism** — Ed25519 challenge-response seal
  prevents offline CLI modification after bootstrap.
- **Nitro deployment infrastructure** — Dockerfile,
  enclave entrypoint, KMS setup scripts, IAM policies,
  full deployment guide (1,200+ lines).

### DIDComm

- **Migrated to affinidi-messaging-didcomm-service** —
  Replaced manual message dispatch with typed Router,
  handler functions, MessagePolicy middleware, and
  RequestLogging. Handlers use `Extension<Arc<VtaState>>`
  for shared state injection.
- **WebSocket-based DIDComm session** — PNM CLI now uses
  WebSocket streaming for response delivery, fixing
  reliability issues with REST-only polling.
- **Backup management protocol** —
  `backup-management/1.0/export` and
  `backup-management/1.0/import` DIDComm message types.
- **VTA restart protocol** —
  `vta-management/1.0/restart` DIDComm message type.

### P-256 Key Support

- **P-256 (secp256r1) key derivation** — New key type
  with BIP-32 derivation using domain-separated paths
  (`m/13'/256'/...`).
- **Signing oracle endpoint** — `POST /keys/{key_id}/sign`
  (REST) and `key-management/1.0/sign` (DIDComm) for
  server-side signing with managed keys.
- **Token cache API** — `GET/PUT/DELETE /cache/{key}` for
  ephemeral key-value storage with TTL support.

### Backup & Restore

- **Export** — `POST /backup/export` and DIDComm protocol
  serialize all VTA state (seed, keys, ACL, contexts,
  WebVH, config, optional audit logs) into a
  password-protected `.vtabak` file.
- **Encryption** — Argon2id (64 MiB, 3 iterations, 4
  parallel) derives AES-256-GCM key from user password.
- **Import** — `POST /backup/import` decrypts, validates,
  replaces all state, and triggers soft restart. Preview
  mode (`confirm=false`) shows what would change.
- **TEE re-encryption** — On import in TEE mode,
  `re_encrypt_bootstrap_secrets()` re-encrypts the
  imported seed and JWT key with the enclave's KMS key.
- **PNM CLI** — `pnm backup export [--include-audit]`
  and `pnm backup import <file> [--preview]`.

### Performance

- **DIDComm service DID resolver fix** — The DIDComm
  service listener was creating a local-mode DID resolver
  (ignoring network-mode config), causing ~1s of uncached
  HTTP DID resolution per message through the HTTPS proxy.
  Fixed via patched crate with `tdk_config` passthrough.
- **Reusable TrustPingSession** — PNM health command now
  creates one ATM + WebSocket connection for both mediator
  and VTA pings, eliminating ~4s of duplicate setup.
- **Shared DID resolver** — Single `DIDCacheClient` across
  all health check operations.

### CLI

- **DIDComm-only mode** — PNM CLI works without a REST
  URL, using DIDComm through the mediator for all
  operations.
- **Multi-VTA support** — `pnm vta list/use/remove/info`
  for managing connections to multiple VTAs.
- **`pnm vta restart`** — Trigger soft restart remotely.
- **`pnm backup export/import`** — Remote backup and
  restore with password protection.
- **Trust-ping in health** — `pnm health` now pings both
  the mediator and VTA through DIDComm with latency
  display.

### Enclave Proxy

- **Rust rewrite** — Replaced shell-based parent proxy
  with a Rust binary (`enclave-proxy`).
- **7-channel multiplexer** — Inbound REST, outbound
  mediator (TLS), HTTPS CONNECT proxy, IMDS credential
  proxy, persistent storage (fjall), DID resolver bridge,
  log forwarding.
- **Embedded Affinidi DID resolver** — Resolves mediator
  DID locally without external resolver service.
- **Connection limit** — Semaphore-based limit (256) per
  channel to prevent resource exhaustion.

### Breaking Changes

- **`vta-service` is now a library** — The local/dev
  binary is still included, but TEE deployments use
  `vta-enclave` which depends on `vta-service` as a
  library.
- **DIDComm handler signatures changed** — Handlers now
  use `(HandlerContext, Message, Extension<Arc<VtaState>>)`
  pattern from `affinidi-messaging-didcomm-service`.
- **Workspace version bumped to 0.2.0** — All crates
  updated.

### Dependency Updates

- `affinidi-messaging-didcomm-service` 0.1.2 (patched
  locally for TDK config passthrough)
- `didwebvh-rs` 0.3 → 0.4
- `tokio-vsock` 0.5 → 0.7
- `argon2` 0.5 (new — backup encryption)
- `aes-gcm` 0.10
- `hmac` 0.12

---

## 2026-03-21

### vti-common `0.1.1` (new crate)

- **Shared foundation crate** — Extracts common code
  from `vta-service` and `vtc-service` into a shared
  library: auth (JWT, sessions, extractors), ACL, error
  types, config types, and the fjall key-value store.
- **Key-only prefix scan** — New `prefix_keys()` method
  on `KeyspaceHandle` for efficient iteration when only
  keys are needed (no value decryption overhead).

### vta-service `0.1.3`

- **Audit logging system** — New structured audit log
  with persistence to fjall keyspace. Includes REST
  endpoints (`GET /audit/logs`, `GET /audit/retention`,
  `PATCH /audit/retention`) and DIDComm protocol
  support. Audit events emitted via tracing at the
  `audit` target and persisted for API retrieval.
- **Connection rate limiting** — Enclave proxy now
  enforces a configurable maximum concurrent connection
  limit (default 256) per proxy channel to prevent
  resource exhaustion.
- **Refactored to use vti-common** — Auth, ACL, store,
  error, and config modules now delegate to the shared
  `vti-common` crate, reducing duplication with
  `vtc-service`.
- **Code quality cleanup** — Eliminated unnecessary
  `KeyspaceHandle::clone()` calls in auth routes,
  combined redundant config lock acquisitions, removed
  duplicate `AuditLogQuery` struct in favor of SDK's
  `ListAuditLogsBody`, and optimized audit cleanup to
  use key-only iteration.

### vtc-service `0.1.2`

- **Refactored to use vti-common** — Auth, ACL, store,
  error, and config modules now delegate to the shared
  `vti-common` crate.

### vta-sdk `0.1.2`

- **Audit management protocol** — New
  `audit_management` module with types and client
  methods for listing audit logs
  (`list_audit_logs`), querying retention
  (`get_audit_retention`), and updating retention
  (`update_audit_retention`).

### vta-cli-common `0.1.2`

- **Audit commands** — New `cmd_list_audit_logs` (with
  colored table output), `cmd_get_retention`, and
  `cmd_update_retention` commands.
- **Simplified `cmd_list_audit_logs` API** — Accepts
  `&ListAuditLogsBody` directly instead of 8 individual
  parameters.

### pnm-cli `0.1.2`

- **`pnm audit list`** — List audit logs with filtering
  by time range, action, actor, outcome, and context.
- **`pnm audit retention get/set`** — View and update
  audit log retention period.

### Security Documentation

- **Security architecture** (`docs/security-architecture.md`)
  — Comprehensive security architecture document.
- **Threat model** (`docs/threat-model.md`) — Detailed
  threat model analysis.

---

## 2026-03-16

### vta-sdk `0.1.1`

- **Context provision bundle** — New
  `ContextProvisionBundle` type for encoding/decoding
  portable application onboarding bundles (context
  credentials, VTA config, and optional DID material).
- **Pluggable session storage (`SessionBackend` trait)**
  — `SessionStore` now uses a `SessionBackend` trait
  instead of compile-time feature flags. Consumers can
  provide their own storage implementation via
  `SessionStore::with_backend()`. Built-in backends
  (keyring, file, Azure) remain available as trait
  implementations.
- **DID log retrieval** — New `get_did_webvh_log()`
  client method and `GET_DID_WEBVH_LOG` protocol
  constant for retrieving stored DID logs.
- **Context deletion preview** — New
  `preview_delete_context()` and `delete_context()`
  client methods with cascading resource cleanup.
- **Serverless DID creation** —
  `CreateDidWebvhRequest` now supports an optional
  `url` field for serverless DID creation. Response
  includes `did_document` and `log_entry` for
  self-hosting.

### vta-service `0.1.2`

- **Serverless WebVH DID creation (`--did-url`)** —
  Create a DID document and log entry locally without
  a pre-registered WebVH server. Keys are derived and
  stored, and the DID document and log entry are
  returned for self-hosting.
- **Cascading context deletion** — Deleting a context
  removes all associated keys, WebVH DIDs (and logs),
  and cleans up ACL entries. A preview endpoint lets
  callers inspect what will be removed before
  committing.
- **DID log retrieval API** — New
  `GET /webvh/dids/{did}/log` endpoint (REST and
  DIDComm) to retrieve the stored DID log for a given
  WebVH DID.
- **Serverless DIDs now persist data** — Serverless
  DID creation stores the `WebvhDidRecord`, DID log,
  and updates the context DID field, matching
  server-managed behavior.
- **Upgraded to didwebvh-rs 0.3 `create_did()` API**
  — Replaced manual `DIDWebVHState` +
  `create_log_entry` + SCID/DID extraction with the
  high-level `CreateDIDConfig` builder and
  `create_did()`. DID documents now use `{DID}`
  placeholders.

### vta-cli-common `0.1.1`

- **`cmd_context_provision`** — Creates a context,
  generates admin credentials, and optionally creates
  a WebVH DID. Outputs a portable base64 bundle for
  application onboarding.
- **`cmd_context_reprovision`** — Regenerates a
  provision bundle for an existing context. Supports
  selecting an existing VTA-stored key interactively
  or via `--key`, or creating a new admin key.
  Includes full DID material (document, log entry,
  secrets).
- **`cmd_context_delete`** — Cascading delete with
  preview and interactive confirmation.
- **Serverless DID support** in
  `cmd_webvh_did_create` via `--did-url`.

### pnm-cli `0.1.1`

- **`pnm context provision`** — Single command for
  application onboarding with optional DID creation.
- **`pnm context reprovision`** — Regenerate provision
  bundles for existing contexts.
- **`pnm context delete`** — Cascading delete with
  preview and `--force` flag.
- **`pnm webvh create-did --did-url`** — Serverless
  DID creation.

### cnm-cli `0.1.1`

- **`cnm context delete`** — Cascading delete with
  preview and `--force` flag.

### vtc-service `0.1.1`

- **Upgraded to didwebvh-rs 0.3 `create_did()` API**
  — Same refactoring as vta-service for DID creation
  flows.

### Dependency Updates (all crates)

- `didwebvh-rs` 0.2 → 0.3
- `affinidi-tdk` 0.5 → 0.6
- `azure_security_keyvault_secrets` 0.11 → 0.12
- `azure_identity` 0.32 → 0.33
- All compatible transitive dependencies updated to
  latest versions
