# Contribution Guidelines

Thank you for contributing! Before you contribute, we ask some things of you:

- Please follow our Code of Conduct, the Contributor Covenant. You can find a copy [in this repository](CODE_OF_CONDUCT.md) or under https://www.contributor-covenant.org/
- All Contributors must agree to [a CLA](.github/CLA/INDIVIDUAL.md). When opening a PR, the system will guide you through the process. However, if you contribute on behalf of a legal entity, we ask of you to agree to [a different CLA](.github/CLA/ENTITY.md). In that case, please contact us.

## Development Setup

### Prerequisites

- **Rust 1.91.0+** (`rustup default stable`)
- **libdbus-1-dev** (Linux) or equivalent (for keyring feature)
- **Docker** (for enclave builds only)

### Build

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the local/dev VTA
cargo run --package vta-service

# Build for TEE (Linux only)
cargo build --package vta-enclave --features rest,didcomm,vsock-store
```

### Test

```bash
# Run all tests
cargo test

# Run tests for a single crate
cargo test --package vta-service --lib

# Run a specific test
cargo test --package vta-service --lib encrypt_decrypt

# Run with output
cargo test -- --nocapture
```

### Lint

```bash
cargo clippy
cargo fmt --check
```

## PR Checklist

Before submitting a pull request:

- [ ] `cargo check` passes for the entire workspace
- [ ] `cargo test` passes with no failures
- [ ] `cargo fmt --check` shows no formatting issues
- [ ] New public functions have `///` doc comments
- [ ] Security-sensitive changes include tests (auth, ACL, crypto)
- [ ] CHANGELOG.md updated for user-facing changes
- [ ] Commits are signed off (DCO: `git commit -s`)

## Coding Guidelines

- **Error handling**: Use `?` operator and `AppError` variants. Never `unwrap()` on user input or I/O in production code paths. `expect()` is acceptable only in `main()` for unrecoverable startup failures.
- **Auth**: All new REST endpoints must use an auth extractor (`AuthClaims`, `ManageAuth`, `AdminAuth`, `SuperAdminAuth`). DIDComm handlers must call `auth_from_message()`.
- **Audit**: Security-sensitive operations (key creation, ACL changes, backup, restart) must emit an audit log entry via `crate::audit::record()`.
- **Feature flags**: Gate platform-specific code behind features. Don't add unconditional dependencies on `tokio-vsock`, cloud SDKs, etc.
- **Secrets**: Never log seeds, mnemonics, private keys, or passwords. Use `Zeroize` on structs holding secrets.

## Workspace Structure

See [README.md](README.md) for the crate overview. Key design documents:

- [Architecture & API](docs/design.md)
- [Security Architecture](docs/security.md)
- [Cold-Start Guide](docs/cold-start-guide.md)
- [Integration Guide](docs/integration-guide.md)
- [DIDComm Protocol](docs/didcomm_protocol.md)
- [BIP-32 Paths](docs/bip32_paths.md)
- [Feature Flags](docs/feature-flags.md)
- [TEE Enclave Security](docs/design/tee-enclave-security.md)
- [Store Migration](docs/design/store-migration.md)
