# Adding a New VTA Front-End

The VTA is designed as a **core library + thin front-ends** architecture.
The business logic (routes, operations, keys, auth, store) lives in the
`vta-service` library crate. Each deployment mode has its own binary crate
that handles platform-specific bootstrapping and calls `server::run()`.

## Current front-ends

| Crate | Binary | Purpose |
|-------|--------|---------|
| `vta-service` | `vta` | Local/dev/cloud — opens a local fjall store, no TEE |
| `vta-enclave` | `vta-enclave` | AWS Nitro Enclave — KMS bootstrap, vsock store, TEE attestation |

## Creating a new front-end

### 1. Create the crate

```
mkdir vta-myfrontend
```

**`vta-myfrontend/Cargo.toml`:**

```toml
[package]
name = "vta-myfrontend"
version.workspace = true
edition.workspace = true

[[bin]]
name = "vta-myfrontend"
path = "src/main.rs"

[features]
default = ["rest", "didcomm"]
rest = ["vta-service/rest"]
didcomm = ["vta-service/didcomm"]

[dependencies]
vta-service = { path = "../vta-service" }
tokio = { workspace = true }
tracing = { workspace = true }
```

Add it to the workspace in `Cargo.toml`:

```toml
[workspace]
members = [
  # ... existing crates ...
  "vta-myfrontend",
]
```

### 2. Write the main.rs

A minimal front-end is ~30 lines:

```rust
use std::sync::Arc;
use vta_service::config::AppConfig;
use vta_service::keys::seed_store::create_seed_store;
use vta_service::store::Store;

#[tokio::main]
async fn main() {
    let config = AppConfig::load(None).expect("failed to load config");
    vta_service::init_tracing(&config);

    let store = Store::open(&config.store).expect("failed to open store");
    let seed_store = Arc::from(
        create_seed_store(&config).expect("failed to create seed store"),
    );

    if let Err(e) = vta_service::server::run(
        config,
        store,
        seed_store,
        None, // storage_encryption_key
        None, // tee_context
    )
    .await
    {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}
```

### 3. What you can customize

The entry point `server::run()` accepts five parameters:

| Parameter | Type | Purpose |
|-----------|------|---------|
| `config` | `AppConfig` | Loaded from TOML + env var overrides |
| `store` | `Store` | `Store::Local(...)` for fjall, `Store::Vsock(...)` for vsock proxy |
| `seed_store` | `Arc<dyn SeedStore>` | Where the master seed lives (keyring, KMS, config, cloud secrets) |
| `storage_encryption_key` | `Option<[u8; 32]>` | AES-256-GCM key for at-rest encryption (None = unencrypted) |
| `tee_context` | `Option<TeeContext>` | TEE attestation provider + mnemonic guard (None = no TEE) |

Your front-end's job is to **construct these values** using whatever
platform-specific logic your environment needs, then call `server::run()`.

### 4. Common patterns

**Custom store backend:** Implement `VsockStore`-like adapter (or add a new
variant to the `Store` enum in `vti-common/src/store/mod.rs`). See
[Store Migration Path](store-migration.md) for the trait-based design.

**Custom seed storage:** Implement the `SeedStore` trait from
`vta-service/src/keys/seed_store/mod.rs`. Examples: `PlaintextSeedStore`,
`KeyringSeedStore`, `KmsTeeSeedStore`.

**Custom TEE provider:** Implement the `TeeProvider` trait from
`vta-service/src/tee/provider.rs`. Pass it wrapped in a `TeeContext` to
`server::run()`. The server uses it for attestation endpoints and JWT claims.

**Disable features:** Use `--no-default-features` and enable only what you
need. For example, a DIDComm-only deployment:

```toml
[dependencies]
vta-service = { path = "../vta-service", default-features = false, features = ["didcomm"] }
```

### 5. Examples

- **`vta-service/src/main.rs`** — Simplest front-end. Opens local store,
  creates seed store, calls `server::run()`. No TEE, no encryption.

- **`vta-enclave/src/main.rs`** — Full TEE front-end. VsockStore connection,
  KMS bootstrap, mnemonic guard, DID auto-generation, TEE provider init.
  ~170 lines of bootstrap code.
