# Changelog

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
