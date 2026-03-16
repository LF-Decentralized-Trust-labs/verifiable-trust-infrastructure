# Changelog

## 0.1.1 — 2026-03-16

### New Features

- **Application context provisioning (`pnm context provision`)** — Single command that creates a context, generates admin credentials, and optionally creates a WebVH DID (server-managed or self-hosted). Outputs a portable base64-encoded bundle containing everything an application needs to connect, authenticate, and self-administer its context.

- **Context reprovisioning (`pnm context reprovision`)** — Regenerate a provision bundle for an existing context. Select an existing VTA-stored key interactively or specify one via `--key`, or create a new admin key. The bundle includes full DID material (document, log entry, and key secrets) matching the format produced by `provision`.

- **Serverless WebVH DID creation (`--did-url`)** — Create a DID document and log entry locally without a pre-registered WebVH server. When `--did-url` is provided instead of `--server`, keys are derived and stored but the DID document and log entry are returned for self-hosting. Available in both `pnm webvh create-did` and `pnm context provision`.

- **Cascading context deletion** — Deleting a context now removes all associated keys, WebVH DIDs (and logs), and cleans up ACL entries. A preview shows what will be removed before committing. The CLI prompts for confirmation unless `--force` is passed.

- **DID log retrieval API** — New `GET /webvh/dids/{did}/log` endpoint (REST and DIDComm) to retrieve the stored DID log for a given WebVH DID. Used by reprovisioning and external tools that need the original log entry.

- **Pluggable session storage (`SessionBackend` trait)** — `SessionStore` now uses a `SessionBackend` trait instead of compile-time feature flags. Consumers can provide their own storage implementation via `SessionStore::with_backend()`. Built-in backends (keyring, file, Azure) are available as trait implementations.

### Improvements

- **Upgraded to didwebvh-rs 0.3 `create_did()` API** — Replaced the manual `DIDWebVHState` + `create_log_entry` + SCID/DID extraction pattern with the high-level `CreateDIDConfig` builder and `create_did()` convenience function. DID documents now use `{DID}` placeholders instead of pre-computed strings.

- **Serverless DIDs now persist data** — Serverless DID creation stores the `WebvhDidRecord`, DID log, and updates the context DID field, matching server-managed behavior. This enables reprovisioning and log retrieval for self-hosted DIDs.

### Dependency Updates

- `didwebvh-rs` 0.2 → 0.3
- `affinidi-tdk` 0.5 → 0.6
- `azure_security_keyvault_secrets` 0.11 → 0.12
- `azure_identity` 0.32 → 0.33
- All compatible transitive dependencies updated to latest versions
