# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust workspace for **Verifiable Trust Communities (VTC)**. A VTC manages a community of Verifiable Trust Agents. Unlike the VTA (which manages keys), the VTC handles community management, ACL, and DIDComm messaging. Part of the [First Person Network](https://www.firstperson.network/white-paper) project.

## Workspace Structure

This repo lives at `vtc-vta-rs/vtc-service/` within a multi-crate workspace:

- **vta-sdk** (`../vta-sdk/`) — Shared SDK: types, VTA HTTP client, session/auth logic, and protocol constants
- **vta-service** (`../vta-service/`) — VTA binary service (key management)
- **vtc-service** (this crate) — VTC binary service (community management, no key management)

Both service crates share configuration via `workspace.package` in the root `Cargo.toml`.

## Key Differences from VTA

- **No key management** — no `keys/mod.rs`, `keys/paths.rs`, or `/keys/*` routes
- **No contexts** — no `contexts/` module or `/contexts/*` routes
- **Only 2 keyspaces** — `sessions` and `acl` (no `keys`, `contexts`)
- **VTC_ env prefix** — all environment variables use `VTC_` instead of `VTA_`
- **JWT audience** — `"VTC"` instead of `"VTA"`
- **Default port** — 8200 (VTA uses 8100)
- **No BIP-32** — VTC receives key material from the VTA (no local key derivation)

## Build Commands

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the service
cargo run --package vtc-service

# Run all tests
cargo test

# Run tests for a single crate
cargo test --package vtc-service

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
