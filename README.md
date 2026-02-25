# Verifiable Trust Communities - Verified Trust Agent

[![Rust](https://img.shields.io/badge/rust-1.91.0%2B-blue.svg?maxAge=3600)](https://github.com/FirstPersonNetwork/vtc-vta-rs)

A Verifiable Trust Agent (VTA) is an always-on service that manages cryptographic
keys, DIDs, and access-control policies for a
[Verifiable Trust Community](https://www.firstperson.network/white-paper). This
repository contains the VTA service, a shared SDK, and the Community Network
Manager (CNM) CLI.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Feature Flags](#feature-flags)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Example: Creating a New Application Context](#example-creating-a-new-application-context)
- [CLI Reference](#cli-reference)
  - [VTA Service CLI](#vta-service-cli-vta)
  - [CNM CLI](#cnm-cli-cnm) (multi-community)
  - [PNM CLI](#pnm-cli-pnm) (single VTA)
  - [Shared VTA commands](#shared-vta-commands-both-cnm-and-pnm)
- [Additional Resources](#additional-resources)

## Overview

The repository is a Rust workspace with four crates:

| Crate           | Description                                                                                             |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| **vta-service** | Axum HTTP service -- the VTA itself. Manages keys, contexts, ACL, sessions, and DIDComm authentication. |
| **vta-sdk**     | Shared SDK: types, VTA HTTP client, session/auth logic, and protocol constants.                         |
| **cnm-cli**     | Community Network Manager CLI -- multi-community client for operating VTAs.                             |
| **pnm-cli**     | Personal Network Manager CLI -- simpler single-VTA client for personal use.                             |

## Architecture

The VTA is built on Axum with an embedded fjall key-value store for
persistence. Cryptographic keys derive from a single BIP-39 mnemonic via
BIP-32 Ed25519 derivation, and the master seed is stored in a pluggable
backend (OS keyring by default; see [Feature Flags](#feature-flags)). Authentication uses a DIDComm v2 challenge-response flow
that issues short-lived EdDSA JWTs.

| Layer          | Technology                                                                                                |
| -------------- | --------------------------------------------------------------------------------------------------------- |
| Web framework  | Axum 0.8                                                                                                  |
| Async runtime  | Tokio                                                                                                     |
| Storage        | fjall (embedded LSM key-value store)                                                                      |
| Cryptography   | ed25519-dalek, ed25519-dalek-bip32                                                                        |
| DID resolution | affinidi-did-resolver-cache-sdk                                                                           |
| DIDComm        | affinidi-tdk (didcomm, secrets_resolver)                                                                  |
| JWT            | jsonwebtoken (EdDSA / Ed25519)                                                                            |
| Seed storage   | OS keyring, AWS Secrets Manager, GCP Secret Manager, or config file (see [Feature Flags](#feature-flags)) |

See [docs/design.md](docs/design.md) for the full design document.

## Feature Flags

Feature flags control compile-time backend selection. The default build
uses the OS keyring for both `vta-service` (seed storage) and `cnm-cli`
(session storage).

### vta-service

| Feature       | Description                                                                                                                                                    | Default |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `setup`       | Interactive setup wizard (`vta setup`)                                                                                                                         | Yes     |
| `keyring`     | Store the master seed in the OS keyring (macOS Keychain, GNOME Keyring, Windows Credential Manager)                                                            | Yes     |
| `config-seed` | Store the seed as a hex string in `config.toml` (useful for containers / CI). **Warning:** the seed is stored on disk unprotected -- do not use in production. | No      |
| `aws-secrets` | Store the seed in AWS Secrets Manager                                                                                                                          | No      |
| `gcp-secrets` | Store the seed in GCP Secret Manager                                                                                                                           | No      |

### cnm-cli

| Feature          | Description                                                                                                                                                     | Default |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `keyring`        | Store sessions in the OS keyring                                                                                                                                | Yes     |
| `config-session` | Store sessions in `~/.config/cnm/sessions.json` (useful for containers / CI). **Warning:** sessions are stored on disk unprotected -- do not use in production. | No      |

### pnm-cli

| Feature          | Description                                                                                                                                                     | Default |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `keyring`        | Store sessions in the OS keyring                                                                                                                                | Yes     |
| `config-session` | Store sessions in `~/.config/pnm/sessions.json` (useful for containers / CI). **Warning:** sessions are stored on disk unprotected -- do not use in production. | No      |

### Build examples

```sh
# Default (OS keyring + setup wizard)
cargo build --package vta-service

# AWS Secrets Manager instead of keyring
cargo build --package vta-service --no-default-features --features "setup,aws-secrets"

# GCP Secret Manager instead of keyring
cargo build --package vta-service --no-default-features --features "setup,gcp-secrets"

# Both cloud backends (setup wizard lets you choose)
cargo build --package vta-service --no-default-features --features "setup,aws-secrets,gcp-secrets"

# Config-file seed (no keyring, no cloud -- seed stored in config.toml)
cargo build --package vta-service --no-default-features --features "setup,config-seed"

# Keyring + AWS (keyring is the fallback if no AWS secret name is configured)
cargo build --package vta-service --features "aws-secrets"
```

When a cloud backend is compiled in, the setup wizard prompts for the
relevant configuration (secret name, region, project ID). If both
`aws-secrets` and `gcp-secrets` are enabled, the wizard shows a selector
to choose between them or fall back to the OS keyring.

At runtime, the backend is selected by priority based on what is
configured in `config.toml` (or environment variables):

1. AWS Secrets Manager (`secrets.aws_secret_name` set)
2. GCP Secret Manager (`secrets.gcp_secret_name` set)
3. Config file seed (`secrets.seed` set)
4. OS keyring (default fallback)

## Prerequisites

- **Rust 1.91.0+** (edition 2024)
- **OS keyring support** (when using the default `keyring` feature) --
  the master seed is stored in your platform's credential manager:
  - macOS: Keychain
  - Linux: secret-service (e.g. GNOME Keyring)
  - Windows: Credential Manager

## Getting Started

### Build

```sh
cargo build --workspace
```

### Run the Setup Wizard

The setup wizard bootstraps a new VTA instance. It is behind the `setup`
feature flag:

```sh
cargo run --package vta-service --features setup -- setup
```

The wizard walks through these steps:

1. **Server configuration** -- host, port, log level, data directory.
2. **Seed context** -- creates the `vta` context (and `mediator` if DIDComm
   is enabled).
3. **Mnemonic** -- generate a new BIP-39 mnemonic or import an existing one.
   The derived seed is stored in the OS keyring.
4. **JWT signing key** -- a random Ed25519 key for signing access tokens.
5. **Mediator DID** -- creates a `did:webvh` with signing and key-agreement
   keys.
6. **VTA DID** -- creates a `did:webvh` with a DIDComm service endpoint
   pointing to the mediator.
7. **Admin credential** -- generates a `did:key` credential for the first
   administrator.
8. **ACL bootstrap** -- registers the admin in the access-control list.
9. **Persist** -- writes `config.toml` and flushes the store.

> **Save the mnemonic and admin credential.** The mnemonic is the root of all
> key material; the admin credential is required to authenticate the CLI.

### Start the VTA Service

```sh
cargo run --package vta-service
```

The service listens on the host and port configured during setup (default
`127.0.0.1:3000`). Verify it is running:

```sh
# Using the Community Network Manager (multi-community):
cargo run --package cnm-cli -- health

# Or using the Personal Network Manager (single VTA):
cargo run --package pnm-cli -- health --url http://localhost:3000
```

### Authenticate a CLI

Use the admin credential printed during setup:

```sh
# CNM -- multi-community, interactive setup
cargo run --package cnm-cli -- auth login <credential>

# PNM -- single VTA, non-interactive setup
cargo run --package pnm-cli -- setup --url http://localhost:3000 --credential <credential>
```

This imports the credential into the OS keyring, performs a DIDComm
challenge-response handshake, and caches the resulting tokens. Subsequent
commands authenticate automatically.

## Example: Creating a New Application Context

The `contexts bootstrap` command creates a context and generates credentials
for its first admin in a single step:

```sh
cargo run --package cnm-cli -- contexts bootstrap \
  --id myapp \
  --name "My Application" \
  --admin-label "MyApp Admin"
```

This outputs a credential string. Give it to the context administrator so they
can authenticate:

```sh
cargo run --package cnm-cli -- auth login <context-admin-credential>
```

Follow-up commands the context admin can now run:

```sh
# List all contexts visible to this credential
cargo run --package cnm-cli -- contexts list

# Create an Ed25519 signing key in the new context
cargo run --package cnm-cli -- keys create --key-type ed25519 --context-id myapp --label "Signing Key"

# List keys
cargo run --package cnm-cli -- keys list
```

## CLI Reference

### VTA Service CLI (`vta`)

The VTA binary provides both the server and offline management commands.
During development use `cargo run --package vta-service --` in place of `vta`.

| Command                                                                  | Description                                                          |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| _(no subcommand)_                                                        | Start the VTA HTTP service                                           |
| `setup`                                                                  | Interactive setup wizard (requires `setup` feature)                  |
| `status`                                                                 | Show VTA status: config, contexts, keys, ACL, sessions               |
| `export-admin`                                                           | Export admin DID and credential                                      |
| `create-did-key --context ID [--admin] [--label LABEL]`                  | Create a did:key in a context (offline)                              |
| `create-did-webvh --context ID [--label LABEL]`                          | Create a did:webvh interactively (offline, requires `setup` feature) |
| `import-did --did DID [--role ROLE] [--label LABEL] [--context CTX ...]` | Import an external DID and create an ACL entry (offline)             |
| `acl list [--context ID] [--role ROLE]`                                  | List ACL entries (offline)                                           |
| `acl get <did>`                                                          | Show details of an ACL entry (offline)                               |
| `acl update <did> [--role ROLE] [--label LABEL] [--contexts ctx1,ctx2]`  | Update an ACL entry (offline)                                        |
| `acl delete <did> [--yes]`                                               | Delete an ACL entry (offline)                                        |

### CNM CLI (`cnm`)

The CNM binary is the multi-community client for operating VTAs over the network.
During development use `cargo run --package cnm-cli --` in place of `cnm`.
See the [cnm-cli README](cnm-cli/README.md) for full documentation.

#### CNM-specific commands

| Command                   | Description                                |
| ------------------------- | ------------------------------------------ |
| `setup`                   | Interactive first-time setup wizard        |
| `community list`          | List configured communities                |
| `community use <slug>`    | Set default community                      |
| `community add`           | Add a new community interactively          |
| `community remove <slug>` | Remove a community                         |
| `community status`        | Show active community info and auth status |
| `community ping`          | Send a DIDComm trust-ping to the VTA       |

### PNM CLI (`pnm`)

The PNM binary is a simpler single-VTA client for personal use. It has the same
VTA management commands (keys, contexts, ACL, credentials) but no community or
personal-VTA concepts. During development use `cargo run --package pnm-cli --`
in place of `pnm`. See the [pnm-cli README](pnm-cli/README.md) for full
documentation.

#### PNM-specific commands

| Command                                  | Description                                    |
| ---------------------------------------- | ---------------------------------------------- |
| `setup --url URL [--credential CRED]`    | Configure VTA URL and optionally authenticate  |

### Shared VTA commands (both `cnm` and `pnm`)

Both CLIs share the following commands for VTA management:

#### Health & Authentication

| Command                   | Description                          |
| ------------------------- | ------------------------------------ |
| `health`                  | Check VTA service health and version |
| `auth login <credential>` | Import credential and authenticate   |
| `auth logout`             | Clear stored credentials and tokens  |
| `auth status`             | Show current authentication status   |

#### Configuration

| Command                                                                                 | Description                    |
| --------------------------------------------------------------------------------------- | ------------------------------ |
| `config get`                                                                            | Show current VTA configuration |
| `config update [--community-name ...] [--community-description ...] [--public-url ...]` | Update configuration fields    |

#### Keys

| Command                                                                    | Description               |
| -------------------------------------------------------------------------- | ------------------------- |
| `keys list [--status active\|revoked] [--limit N] [--offset N]`            | List keys                 |
| `keys create --key-type ed25519\|x25519 [--context-id ID] [--label LABEL]` | Create a key              |
| `keys get <key_id>`                                                        | Get a key by ID           |
| `keys revoke <key_id>`                                                     | Revoke (invalidate) a key |
| `keys rename <key_id> <new_key_id>`                                        | Rename a key              |

#### Contexts

| Command                                                             | Description                                              |
| ------------------------------------------------------------------- | -------------------------------------------------------- |
| `contexts list`                                                     | List application contexts                                |
| `contexts get <id>`                                                 | Get a context by ID                                      |
| `contexts create --id ID --name NAME [--description DESC]`          | Create a context                                         |
| `contexts update <id> [--name ...] [--did ...] [--description ...]` | Update a context                                         |
| `contexts delete <id>`                                              | Delete a context                                         |
| `contexts bootstrap --id ID --name NAME [--admin-label LABEL]`      | Create a context and generate its first admin credential |

#### ACL

| Command                                                                   | Description             |
| ------------------------------------------------------------------------- | ----------------------- |
| `acl list [--context ID]`                                                 | List ACL entries        |
| `acl get <did>`                                                           | Get an ACL entry by DID |
| `acl create --did DID --role ROLE [--label LABEL] [--contexts ctx1,ctx2]` | Create an ACL entry     |
| `acl update <did> [--role ROLE] [--label LABEL] [--contexts ctx1,ctx2]`   | Update an ACL entry     |
| `acl delete <did>`                                                        | Delete an ACL entry     |

#### Auth Credentials

| Command                                                                     | Description                                     |
| --------------------------------------------------------------------------- | ----------------------------------------------- |
| `auth-credential create --role ROLE [--label LABEL] [--contexts ctx1,ctx2]` | Generate a did:key credential with an ACL entry |

## Additional Resources

- [First Person Project White Paper](https://www.firstperson.network/white-paper)
- [Design Document](docs/design.md)
- [BIP-32 Path Specification](docs/bip32_paths.md)
