# Personal Network Manager (PNM) CLI

The PNM CLI is a single-VTA client for managing a personal
[Verifiable Trust Agent (VTA)](../README.md). Unlike the
[CNM CLI](../cnm-cli/README.md) which supports multiple communities and a
personal VTA, PNM focuses on managing one VTA instance with a simpler
non-interactive setup flow.

## Table of Contents

- [Feature Flags](#feature-flags)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [CLI Reference](#cli-reference)
- [Additional Resources](#additional-resources)

## Feature Flags

| Feature          | Description                                                                                                                                                                                    | Default |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `keyring`        | Store sessions in the OS keyring (macOS Keychain, GNOME Keyring, Windows Credential Manager)                                                                                                   | Yes     |
| `config-session` | Store sessions in `~/.config/pnm/sessions.json`. Useful for containers and CI where no keyring is available. **Warning:** sessions are stored on disk unprotected -- do not use in production. | No      |

At least one of `keyring` or `config-session` must be enabled. When `keyring`
is enabled it takes priority over `config-session`.

### Build examples

```sh
# Default build (keyring)
cargo build --package pnm-cli --release

# Keyring-free build for containers / CI
cargo build --package pnm-cli --release --no-default-features --features config-session
```

## Installation

### From source

Requires **Rust 1.91.0+**.

```sh
cargo build --package pnm-cli --release
```

The binary is at `target/release/pnm`.

### During development

All examples below use `pnm` directly. When developing from the workspace,
substitute `cargo run --package pnm-cli --` for `pnm`.

## Quick Start

### 1. Set up the VTA connection

```sh
pnm setup --url http://localhost:3000 --credential <credential>
```

This saves the URL to `~/.config/pnm/config.toml` and authenticates using the
provided credential. You can also set up without a credential and log in later:

```sh
pnm setup --url http://localhost:3000
pnm auth login <credential>
```

### 2. Verify connectivity

```sh
pnm health
```

### 3. Start using the CLI

```sh
# List application contexts
pnm contexts list

# Create a signing key
pnm keys create --key-type ed25519 --context-id myapp --label "Signing Key"

# List keys
pnm keys list
```

## Authentication

PNM uses **DID-based challenge-response authentication** with short-lived JWT
tokens:

1. **Import a credential** -- a base64-encoded bundle containing your client
   DID, private key, and the VTA DID.
2. **Challenge-response** -- the CLI requests a nonce from the VTA, signs a
   DIDComm v2 message, and receives a JWT.
3. **Token caching** -- tokens are cached in the OS keyring and refreshed
   automatically when they expire.

```sh
# Import credential and authenticate
pnm auth login <credential>

# Check auth status
pnm auth status

# Clear credentials
pnm auth logout
```

After initial login, all subsequent commands authenticate transparently.

### Credential storage

With the default `keyring` feature, sessions are stored in the platform's
credential manager:

| Platform | Backend                             |
| -------- | ----------------------------------- |
| macOS    | Keychain                            |
| Linux    | secret-service (e.g. GNOME Keyring) |
| Windows  | Credential Manager                  |

When built with `--features config-session` (and without `keyring`), sessions
are stored in `~/.config/pnm/sessions.json` instead. See
[Feature Flags](#feature-flags) for details.

## Configuration

### Config file

`~/.config/pnm/config.toml`

```toml
url = "http://localhost:3000"
```

### Environment variables

| Variable   | Description                          |
| ---------- | ------------------------------------ |
| `VTA_URL`  | Override the VTA base URL            |
| `RUST_LOG` | Set log level (e.g. `debug`, `info`) |

## CLI Reference

### Global flags

| Flag            | Description                              |
| --------------- | ---------------------------------------- |
| `--url <URL>`   | Override VTA base URL (or set `VTA_URL`) |
| `-v, --verbose` | Enable debug logging                     |

### Setup

| Command                               | Description                                   |
| ------------------------------------- | --------------------------------------------- |
| `setup --url URL [--credential CRED]` | Configure VTA URL and optionally authenticate |

### Authentication

| Command                   | Description                         |
| ------------------------- | ----------------------------------- |
| `auth login <credential>` | Import credential and authenticate  |
| `auth logout`             | Clear stored credentials and tokens |
| `auth status`             | Show current authentication status  |

### Health

| Command  | Description                                            |
| -------- | ------------------------------------------------------ |
| `health` | Check VTA service health and version                   |

### Configuration

| Command                   | Description                                       |
| ------------------------- | ------------------------------------------------- |
| `config get`              | Show current VTA configuration                    |
| `config update [options]` | Update VTA metadata (DID, name, description, URL) |

### Keys

| Command                                                                    | Description     |
| -------------------------------------------------------------------------- | --------------- |
| `keys list [--status active\|revoked] [--limit N] [--offset N]`            | List keys       |
| `keys create --key-type ed25519\|x25519 [--context-id ID] [--label LABEL]` | Create a key    |
| `keys get <key_id>`                                                        | Get a key by ID |
| `keys revoke <key_id>`                                                     | Revoke a key               |
| `keys rename <key_id> <new_key_id>`                                        | Rename a key               |
| `keys secrets [key_ids...] [--context ID]`                                 | Export secret key material |
| `keys seeds`                                                               | List seed generations      |
| `keys rotate-seed [--mnemonic PHRASE]`                                     | Rotate to a new seed       |

### Contexts

| Command                                                             | Description                             |
| ------------------------------------------------------------------- | --------------------------------------- |
| `contexts list`                                                     | List application contexts               |
| `contexts get <id>`                                                 | Get a context by ID                     |
| `contexts create --id ID --name NAME [--description DESC]`          | Create a context                        |
| `contexts update <id> [--name ...] [--did ...] [--description ...]` | Update a context                        |
| `contexts delete <id>`                                              | Delete a context                        |
| `contexts bootstrap --id ID --name NAME [--admin-label LABEL]`      | Create context + first admin credential |

### ACL

| Command                                                                   | Description             |
| ------------------------------------------------------------------------- | ----------------------- |
| `acl list [--context ID]`                                                 | List ACL entries        |
| `acl get <did>`                                                           | Get an ACL entry by DID |
| `acl create --did DID --role ROLE [--label LABEL] [--contexts ctx1,ctx2]` | Create an ACL entry     |
| `acl update <did> [--role ROLE] [--label LABEL] [--contexts ctx1,ctx2]`   | Update an ACL entry     |
| `acl delete <did>`                                                        | Delete an ACL entry     |

Roles: `admin`, `initiator`, `application`. An admin with no contexts listed
has unrestricted access across all contexts.

### Auth Credentials

| Command                                                                     | Description                                  |
| --------------------------------------------------------------------------- | -------------------------------------------- |
| `auth-credential create --role ROLE [--label LABEL] [--contexts ctx1,ctx2]` | Generate a did:key credential with ACL entry |

## Additional Resources

- [VTA Service & Architecture](../README.md)
- [CNM CLI (multi-community)](../cnm-cli/README.md)
- [First Person Network White Paper](https://www.firstperson.network/white-paper)
- [Design Document](../docs/design.md)
- [BIP-32 Path Specification](../docs/bip32_paths.md)
