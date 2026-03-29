# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust workspace for **Verifiable Trust Infrastructure (VTI)**. The Verifiable Trust Agent (VTA) manages keys and policies for a Verifiable Trust Community. Part of the [First Person Network](https://www.firstperson.network/white-paper) project.

## Workspace Structure

This repo is a multi-crate workspace:

- **vti-common** (`../vti-common/`) — Shared library: auth, ACL, store (local + vsock), error types, config
- **vta-sdk** (`../vta-sdk/`) — SDK for Verifiable Trust Agents (types, client, protocols)
- **vta-service** (this crate) — VTA library + local/dev binary (key management, audit logging, routes, operations)
- **vta-enclave** (`../vta-enclave/`) — VTA binary for Nitro Enclaves (TEE bootstrap, KMS, vsock-store)
- **vtc-service** (`../vtc-service/`) — VTC binary service (community management)
- **vta-cli-common** (`../vta-cli-common/`) — Shared CLI command implementations
- **pnm-cli** (`../pnm-cli/`) — Personal Network Manager CLI

### Architecture: Core + Front-ends

`vta-service` is both a **library** (business logic) and a **binary** (local/dev front-end):
- `src/lib.rs` — Exports all shared modules (routes, operations, keys, auth, store, tee types)
- `src/main.rs` — Local/dev/cloud binary (no TEE bootstrap)

`vta-enclave` is a separate **binary crate** for Nitro Enclave deployments:
- Depends on `vta-service` as a library
- Has its own `main.rs` with TEE-specific bootstrap (KMS, vsock-store, attestation)
- No feature flags for TEE — it's always TEE mode

Future front-ends (SGX, serverless, etc.) follow the same pattern: new binary crate depending on `vta-service` lib.

All crates share configuration via `workspace.package` in the root `Cargo.toml`.

## Build Commands

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the local/dev VTA
cargo run --package vta-service

# Build the enclave VTA (Linux only — vsock-store requires Linux)
cargo build --package vta-enclave --features rest,didcomm,vsock-store

# Run all tests
cargo test

# Run tests for a single crate
cargo test --package vta-service
cargo test --package vta-sdk

# Run a single test by name
cargo test test_name

# Lint
cargo clippy

# Format
cargo fmt
cargo fmt --check   # check only
```

## Rust Configuration

- **Edition**: 2024
- **Minimum Rust version**: 1.91.0
- **Resolver**: 3
- **License**: Apache-2.0
