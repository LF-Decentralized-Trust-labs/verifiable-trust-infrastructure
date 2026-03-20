# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust workspace for **Verifiable Trust Communities (VTC) - Verifiable Trust Agent (VTA)**. A Trust Agent manages keys and policies for a Verifiable Trust Community. Part of the [First Person Network](https://www.firstperson.network/white-paper) project.

## Workspace Structure

This repo lives at `vtc-vta-rs/vta-service/` within a multi-crate workspace:

- **vti-common** (`../vti-common/`) — Shared library: auth, ACL, store, error types, config
- **vta-sdk** (`../vta-sdk/`) — SDK for Verifiable Trust Agents (types, client, protocols)
- **vta-service** (this crate) — VTA binary service (key management, audit logging)
- **vtc-service** (`../vtc-service/`) — VTC binary service (community management)
- **vta-cli-common** (`../vta-cli-common/`) — Shared CLI command implementations
- **pnm-cli** (`../pnm-cli/`) — Personal Network Manager CLI

All crates share configuration via `workspace.package` in the root `Cargo.toml`.

Key external dependency: `dtg-credentials` (Decentralized Trust Graph Credentials) — currently sourced from git (`https://github.com/FirstPersonNetwork/dtg-credentials-rs`), will move to crates.io when published.

## Build Commands

```bash
# Build entire workspace
cargo build

# Check compilation (faster, no codegen)
cargo check

# Run the service
cargo run --package vta-service

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
- **Minimum Rust version**: 1.90.0
- **Resolver**: 3
- **License**: Apache-2.0
