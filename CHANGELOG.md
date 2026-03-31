# Changelog

## 0.3.0 — 2026-03-31

### Imported Secrets

- **Import external private keys** — New `POST /keys/import` endpoint
  and `pnm keys import` command allow importing externally-created
  private keys (Ed25519, X25519, P-256) into the VTA. Imported keys
  are stored encrypted at rest and participate in signing, secret
  export, backup/restore, and revocation alongside BIP-32-derived keys.
- **Ephemeral wrapping keys (REST)** — REST key import uses
  ECDH-ES + AES-256-GCM key wrapping via ephemeral X25519 keypairs
  (`GET /keys/import/wrapping-key`). Each wrapping key is single-use
  with a 60-second TTL. DIDComm transport sends keys directly inside
  the end-to-end encrypted envelope.
- **Encrypted storage layer** — Imported secrets are encrypted with
  AES-256-GCM using a KEK derived from the BIP-32 master seed via
  HKDF-SHA256 with a random 32-byte salt. Each ciphertext is bound
  to its `key_id:key_type` via authenticated associated data (AAD),
  preventing blob-swap attacks.
- **Secure deletion on revoke** — Revoking an imported key overwrites
  the encrypted blob with zeros and deletes it from the keyspace.
  The `KeyRecord` is retained for audit trail.
- **Seed rotation re-encryption** — When the BIP-32 seed is rotated,
  all imported secrets are automatically re-encrypted with the new
  seed-derived KEK.
- **Backup & restore** — Imported secrets are included in the
  encrypted backup payload (plaintext inside the Argon2id+AES-256-GCM
  envelope) and restored on import. The KEK salt is also backed up
  for deterministic KEK reconstruction.

### Data Model

- **`KeyOrigin` enum** — New `origin` field on `KeyRecord`:
  `derived` (default, BIP-32) or `imported` (external). Backward
  compatible via `#[serde(default)]`.
- **`ImportedSecretBackup`** — New type in `BackupPayload` for
  portable imported secret backup.
- **`imported_secret_count`** — Added to `ImportResult` for
  visibility during backup preview/import.

### Security

- **Zeroize** — All private key buffers are zeroized after use
  via the `zeroize` crate (import, signing, backup export/import,
  seed rotation re-encryption).
- **AAD binding** — AES-GCM encryption of imported secrets includes
  `key_id:key_type` as additional authenticated data, preventing
  ciphertext swapping between key entries.
- **Independent KEK salt** — A random 32-byte salt is generated
  per VTA instance and stored alongside the keyspace, ensuring
  two VTAs with the same seed produce different KEKs.
- **Admin-only import** — The import endpoint requires Admin role
  (stricter than key creation which allows Initiator).

### CLI

- **`pnm keys import`** — Import a private key from multibase
  string (`--private-key`) or file (`--private-key-file`).
  Supports `--key-type ed25519|x25519|p256`, `--label`, and
  `--context-id`. Prints a secure-deletion warning on success.

### Testing

- **6 new unit tests** — Imported secret encrypt/decrypt roundtrip,
  wrong-AAD rejection, secure deletion, seed rotation re-encryption,
  ephemeral wrapping key generation + unwrap, single-use enforcement.
- **Total: 234 tests** (up from 228).

### Breaking Changes

- **Operation signatures** — `get_key_secret()`, `sign_payload()`,
  `revoke_key()`, `rotate_seed()`, `export_backup()`, and
  `apply_import()` now accept an `imported_ks` parameter.
- **`AppState`** — Added `imported_ks: KeyspaceHandle` and
  `wrapping_cache: WrappingKeyCache` fields.
- **`VtaState` (DIDComm)** — Added `imported_ks: KeyspaceHandle`.
- **Workspace version bumped to 0.3.0** — All crates updated.

### Dependency Updates

- `hkdf` 0.12 (new — KEK derivation for imported secrets)

### VTA SDK Improvements for Service Integration

- **Lightweight DIDComm auth (`auth_light`)** — New
  `challenge_response_light()` and `refresh_token_light()`
  functions perform DIDComm challenge-response authentication
  without requiring ATM/TDK runtime initialization. Uses a
  hand-rolled JWE packer (`didcomm_light`) with
  ECDH-ES+A256KW key agreement and A256GCM content
  encryption. Available behind the `client` feature (not
  `session`).
- **`VtaClient::from_credential()`** — One-line constructor
  that decodes a base64 credential bundle, authenticates via
  lightweight auth, and returns a ready-to-use client with
  auto-refresh enabled.
- **Automatic token refresh** — `VtaClient` now stores
  credential material and automatically refreshes expired
  tokens before each API call. Tries the `/auth/refresh`
  endpoint first (cheap), falls back to full
  challenge-response if the refresh token is expired.
  Token expiry is checked with a 30-second buffer.
- **`fetch_context_secrets()`** — Convenience method that
  paginates through all active keys in a context and returns
  TDK `Secret` objects ready for DIDComm or signing. Pages
  in batches of 100 to handle large key sets.
- **`check_auth()`** — Verifies the current token is valid
  by calling `GET /health/details`. Returns `true`/`false`
  for readiness checks.
- **`token_expires_at()`** — Exposes token expiry for health
  monitoring in long-running services.
- **`set_token()` is now `&self`** — No longer requires
  `&mut self`, simplifying usage in shared contexts.

### Lightweight DIDComm Packer (`didcomm_light`)

- **DIDComm v2 anoncrypt** — Minimal JWE (General JSON)
  packer producing messages compatible with any DIDComm v2
  unpacker (including `affinidi-tdk`'s `ATM::unpack()`).
- **ECDH-ES+A256KW** key agreement with ephemeral X25519.
- **A256GCM** content encryption (simpler than A256CBC-HS512).
- **Concat KDF** (NIST SP 800-56A) for key derivation.
- **AES-256 Key Wrap** (RFC 3394) for CEK wrapping.
- **`did:key` → X25519** conversion (Edwards→Montgomery).
- **8 unit tests** — Key wrap roundtrip, KDF determinism,
  did:key parsing, Ed25519→X25519 conversion, JWE structure
  validation.

---

## 0.2.1 — 2026-03-30

### Bug Fixes

- **Health check deserialization** — Made `version` field optional
  in `vta-sdk::HealthResponse` so the unauthenticated `GET /health`
  endpoint (which returns only `{"status": "ok"}`) deserializes
  correctly. Previously `pnm health` and `cnm health` reported
  "error decoding response body".

### Improvements

- **Audit log levels** — Audit events now use `INFO` for successful
  outcomes and `ERROR` for failures (e.g. `denied:*`). Previously
  all audit events were emitted at `ERROR` level regardless of
  outcome.

## 0.2.0 — 2026-03-29

### Observability

- **Prometheus metrics endpoint** — `GET /metrics` serves
  request count and latency histograms in Prometheus text
  format. Requires authentication (any role including the
  new Monitor role).
- **Monitor role** — New lowest-privilege role for
  observability-only access. Can read `/metrics` and
  `/health` but nothing else. Create with
  `pnm acl create --role monitor`.

### Hardening

- **Admin credential delete-after-read** — The
  `/attestation/admin-credential` endpoint now deletes the
  credential from the store after first retrieval.
  Subsequent calls return 404.
- **Server-side backup password minimum** — The backup
  export API enforces a 12-character minimum password.
- **Super admin for backup/restart** — Backup export,
  import, and VTA restart now require super admin (admin
  with no context restrictions).
- **Enclave bootstrap error handling** — Replaced all
  `.expect()` calls in `vta-enclave/src/main.rs` with
  proper error handling and `tracing::error` before exit.
- **Clippy clean** — Fixed all actionable warnings:
  `Role::from_str` → `Role::parse`, `.clamp()`, needless
  borrows, collapsed ifs.

### Testing

- **31 REST API integration tests** — Full axum server
  with temp fjall store, programmatic JWT tokens, and
  pre-inserted sessions. Covers auth enforcement (6),
  role hierarchy (4), CRUD operations (5), backup (3),
  cache (1), audit (2), context scoping (1), key
  lifecycle (3), P-256 keys (1), seed list (1),
  wrong password (1), ACL lifecycle (1), context
  lifecycle (1), audit retention (1).
- **20 security-focused unit tests** — Auth role
  enforcement, ACL privilege escalation prevention,
  context access scoping, backup crypto validation.
- **Total: 226 tests** (up from 175 at start of release).

### Documentation

- **6 Mermaid diagrams** — Crate dependencies, REST vs
  DIDComm request flow, auth challenge-response sequence,
  BIP-32 derivation tree, TEE bootstrap sequence, enclave
  proxy architecture.
- **Consolidated docs** — Removed ~170 lines of
  duplicated content from README.md (feature flags, CLI
  reference). Cross-references to canonical sources.
- **Doc comments** on 35 public route handler functions.
- **Expanded CONTRIBUTING.md** — Development setup, test
  commands, PR checklist, coding guidelines.

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
