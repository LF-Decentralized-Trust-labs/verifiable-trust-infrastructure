# Cold-Start Guide: Single Trust Network from Scratch

This guide walks through bootstrapping a complete Verifiable Trust Network
from nothing -- a VTA, WebVH hosting, and a DIDComm mediator -- with every
service instantiated from scratch. No existing services are assumed.

## Prerequisites

- **Rust 1.91.0+** (`rustup update stable`)
- **OS keyring support** (macOS Keychain, GNOME Keyring, or Windows Credential Manager)
- **Redis** (for the mediator's message store)
- **git** and **curl**

### Repository Locations

This guide references three codebases:

| Repository | Purpose | Local Path (example) |
|-----------|---------|---------------------|
| `verifiable-trust-infrastructure` | VTA service, PNM/CNM CLIs | `~/devel/fpp/verifiable-trust-infrastructure` |
| `affinidi-tdk-rs` | DIDComm mediator | `~/devel/affinidi/affinidi-tdk-rs` |
| `affinidi-webvh-service` | WebVH DID hosting server | `~/devel/affinidi/affinidi-webvh-service` |

## Architecture Overview

The VTA is the **root of the entire system**. It holds the master BIP-39 seed
from which all cryptographic keys are derived, creates contexts for each
service, and provisions credentials. Everything flows outward from the VTA.

```
                    ┌───────────────────────┐
                    │         VTA           │
                    │   (master key store)  │
                    │      :8100            │
                    └───┬───────────┬───────┘
                        │           │
              creates   │           │  creates
             context +  │           │  context +
               keys     │           │    keys
                        ▼           ▼
               ┌──────────┐   ┌──────────────┐
               │  WebVH   │   │   Mediator   │
               │  Hosting │   │   (DIDComm)  │
               │  :8000   │   │   :7037      │
               └──────────┘   └──────────────┘
                    ▲               ▲
                    │               │
              hosts did.jsonl   routes DIDComm
              for all DIDs      messages
                    │               │
               ┌────┴───────────────┴────┐
               │       PNM CLI           │
               │  (operator management)  │
               └─────────────────────────┘
```

### Circular Dependency Problem

A naive approach hits a circular dependency:

- VTA needs WebVH to host its DID, and a mediator for DIDComm
- Mediator needs VTA for its keys and DID
- WebVH needs to host DID documents that don't exist yet

The VTA setup wizard **breaks this cycle** by running completely offline. It
generates all keys, creates all DID documents, and exports secrets bundles --
before any service is running. Both the WebVH server and mediator support
offline DID import (`load-did` / `--import-bundle`) so they can bootstrap
with pre-generated artifacts before the VTA is reachable.

### DID Naming Conventions

Before running the setup wizard, decide on a naming convention for your DIDs.
Each `did:webvh` identifier maps to a path on the WebVH hosting server (e.g.,
`did:webvh:example.com:vta` is served at `example.com/vta/did.jsonl`). Choose
names that are short, descriptive, and won't collide with the server's own
routes.

**Reserved names (affinidi-webvh-service).** The following names are reserved
and **cannot** be used as the first path segment of a DID:

| Reserved name | Reason |
|---------------|--------|
| `.well-known` | Root/server DID -- only an admin can create this DID |
| `api` | Management API routes |
| `auth` | Authentication routes |
| `dids` | DID introspection routes |
| `stats` | Statistics routes |
| `acl` | ACL management routes |
| `health` | Health check routes |

**Path segment rules.** Each segment of a custom DID path must:

- Be **2--63 characters** long (total path max 255 characters)
- Contain only **lowercase letters, digits, and hyphens** (`[a-z0-9-]`)
- **Start and end** with an alphanumeric character (not a hyphen)
- Not contain empty segments (no double slashes)

**Examples:**

| DID path | Valid? | Notes |
|----------|--------|-------|
| `vta` | Yes | Simple, descriptive |
| `mediator` | Yes | |
| `my-app` | Yes | Hyphens allowed mid-segment |
| `org/dept/service` | Yes | Multi-segment paths work |
| `api` | **No** | Reserved name |
| `API` | **No** | Uppercase not allowed |
| `health/vta` | **No** | First segment is reserved |
| `v` | **No** | Too short (min 2 chars) |
| `-bad` | **No** | Cannot start with hyphen |

> **Tip:** The `.well-known` path is special -- it represents the root DID for
> the WebVH server itself. Only admins can create it, and it's typically used
> for the WebVH server's own identity, not application DIDs.

### Bootstrap Order

| Phase | What | Runs Against | Produces |
|-------|------|-------------|----------|
| 1 | Build all repos | — | Binaries |
| 2 | VTA setup wizard + WebVH keys (offline) | No services | Seed, keys, `did.jsonl` files, secrets bundles, admin credential, `config.toml` |
| 3 | WebVH daemon (import-secrets + load-did) | — | DID hosting for all services |
| 4 | Redis | — | Message store for mediator |
| 5 | Mediator (import-bundle) | Redis, WebVH | DIDComm message routing |
| 6 | VTA service (online) | WebVH, Mediator | REST API + DIDComm endpoints |
| 7 | PNM CLI | VTA | Operator management |

---

## Phase 1: Build All Repositories

### 1.1 Build the VTI workspace

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo build --workspace
```

Verify the VTA and PNM binaries:

```bash
cargo run --package vta-service -- --help
cargo run --package pnm-cli -- --help
```

### 1.2 Build the mediator

```bash
cd ~/devel/affinidi/affinidi-tdk-rs
cargo build --package affinidi-messaging-mediator --features setup,vta-keyring
```

This builds two binaries:
- `mediator` -- the main mediator service
- `mediator-setup-vta` -- the VTA integration wizard

**Feature flags** control which VTA credential storage backends are available
at runtime. The `setup` flag is required for the wizard binary; the others
determine where the mediator stores its VTA credential:

| Feature | Purpose | When to use |
|---------|---------|-------------|
| `setup` | Builds `mediator-setup-vta` wizard | Always needed for first-time setup |
| `vta-keyring` | OS keyring credential storage (`keyring://`) | Local dev on macOS / Linux desktop |
| `vta-aws-secrets` | AWS Secrets Manager credential storage (`aws_secrets://`) | Production / cloud deployments |
| *(none)* | Config-file credential storage (`string://`) | Always available -- dev/CI only |

> **Tip:** If you plan to choose "OS Keyring" during the mediator setup
> wizard (Phase 5.2), you **must** include `vta-keyring` in the build.
> Without it the keyring option will fail at runtime. For a quick local
> setup, `string://` (embed in config) works without any extra flags.

### 1.3 Build the WebVH server

The WebVH service has two deployment modes:

| Mode | Binary | Description |
|------|--------|-------------|
| **Daemon** | `webvh-daemon` | All-in-one: server + control + witness in a single process on one port. Best for cold-start and development. |
| **Distributed** | `webvh-server` + `webvh-control` + `webvh-witness` | Each service runs as a separate binary. Requires a VTA context per service. Best for production multi-node deployments. |

For cold-start, use **daemon mode** (simplest):

```bash
cd ~/devel/affinidi/affinidi-webvh-service
cargo build --package webvh-daemon --release
```

Or build the standalone server for distributed mode:

```bash
cargo build --package affinidi-webvh-server --release
```

Both binaries support `load-did` and `bootstrap-did` commands for offline
DID import -- no static file server workaround needed.

---

## Phase 2: Run the VTA Setup Wizard (Offline)

The setup wizard runs with **no services needed**. It generates all keys,
creates DID documents, and exports everything the other services need.

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service --features setup -- setup
```

### 2.1 Server Configuration

```
Config file path [config.toml]: config.toml
VTA name: My Trust Network
Enable REST API? Y
Enable DIDComm messaging? Y
Public URL for this VTA: http://localhost:8100
Server host [0.0.0.0]: 0.0.0.0
Server port [8100]: 8100
Log level [info]: info
Log format: text
Data directory [data/vta]: data/vta
```

### 2.2 BIP-39 Mnemonic

```
BIP-39 mnemonic:
  > Generate new 24-word mnemonic
    Import existing mnemonic
```

Choose **Generate new 24-word mnemonic**:

```
╔═══════════════════════════════════════════════════════════╗
║  SAVE THIS MNEMONIC — it is the root of all key material ║
╚═══════════════════════════════════════════════════════════╝
```

> **Write this down and store it securely.** This single mnemonic is the root
> of every key in the entire trust network.

### 2.3 Seed Storage

Choose **OS keyring** for local development. The seed is stored in your
platform's credential manager (macOS Keychain, GNOME Keyring, etc.).

### 2.4 DIDComm Messaging -- Create the Mediator Context

This step creates a `mediator` context inside the VTA, derives signing and
key-agreement keys, and produces a `did:webvh` DID for the mediator.

```
DIDComm messaging:
    Use an existing mediator DID
  > Create a new mediator DID (did:webvh)
    Do not use DIDComm messaging
```

Choose **Create a new mediator DID (did:webvh)**.

```
Mediator URL: http://localhost:7037
```

The wizard asks where to host the mediator's DID document:

```
  Enter the URL where the mediator DID document will be hosted.

mediator DID URL [http://localhost:8000/]: http://localhost:8000/dids/mediator
  DID:  did:webvh:{SCID}:localhost%3A8000:dids:mediator
  URL:  http://localhost:8000/dids/mediator/did.jsonl
Is this correct? [Y/n]: Y
```

Choose **Simple** mode, portable **yes**, pre-rotation keys **1**.

```
Created DID: did:webvh:QmMed...:localhost%3A8000:dids:mediator
Save DID log to file [mediator-did.jsonl]: mediator-did.jsonl
  DID log saved to: mediator-did.jsonl
```

**IMPORTANT -- Export the secrets bundle:**

```
Export DID secrets bundle? [y/N]: y

╔══════════════════════════════════════════════════════════╗
║  WARNING: The secrets bundle contains private keys.      ║
║  Store it securely and do not share it publicly.         ║
╚══════════════════════════════════════════════════════════╝

eyJkaWQiOiJkaWQ6d2VidmgiLCJz...    ← SAVE THIS (mediator secrets bundle)
```

> **You MUST export and save the secrets bundle.** The mediator needs it in
> Phase 5 to start without a running VTA. If you skip this, you cannot do a
> cold-start -- the mediator would need the VTA running to fetch its keys.

### 2.5 VTA DID

The wizard creates the VTA's own DID. It embeds the mediator DID from step
2.4 as a DIDComm service endpoint in the VTA's DID document.

```
VTA DID:
  > Create a new did:webvh DID

VTA DID URL [http://localhost:8000/]: http://localhost:8000/dids/vta
  DID:  did:webvh:{SCID}:localhost%3A8000:dids:vta
  URL:  http://localhost:8000/dids/vta/did.jsonl
Is this correct? [Y/n]: Y
```

Choose **Simple** mode, portable **yes**, pre-rotation keys **1**.

```
Created DID: did:webvh:QmVta...:localhost%3A8000:dids:vta
Save DID log to file [VTA-did.jsonl]: VTA-did.jsonl
  DID log saved to: VTA-did.jsonl
```

### 2.6 Admin Credential

```
Admin DID:
  > Generate a new did:key (Ed25519)
```

Choose **Generate a new did:key**. The admin DID is a `did:key` -- it's
self-certifying and needs no WebVH hosting or resolution infrastructure.

```
Generated admin DID: did:key:z6Mkr...

╔══════════════════════════════════════════════════════════╗
║  IMPORTANT: Save the credential string below.            ║
╚══════════════════════════════════════════════════════════╝

  eyJ0eXAiOiJKV1QiLCJhbGciOi...    ← SAVE THIS (admin credential)

I have saved the admin credential [y/N]: y
```

### 2.7 Setup Complete

```
Setup complete!
  Config saved to: config.toml
```

### 2.8 Generate WebVH Server Keys (Post-Wizard)

The WebVH daemon requires its own signing and key-agreement keys to start.
The VTA's offline CLI can generate these without any running services:

```bash
cargo run --package vta-service --features setup -- \
    create-did-webvh --context webvh --label "WebVH Server"
```

This will:
- Create a `webvh` context (auto-created since it doesn't exist yet)
- Prompt for the DID URL (use the same WebVH server URL):

```
WebVH Server DID URL [http://localhost:8000/]: http://localhost:8000
  DID:  did:webvh:{SCID}:localhost%3A8000
  URL:  http://localhost:8000/.well-known/did.jsonl
Is this correct? [Y/n]: Y
```

- Choose **No service endpoints** (the WebVH server doesn't need DIDComm)
- Portable: **yes**, pre-rotation keys: **1**
- Save the DID log file when prompted:

```
Save DID log to file [WebVH Server-did.jsonl]: webvh-did.jsonl
```

- **Export the secrets bundle:**

```
Export DID secrets bundle? [y/N]: y

eyJkaWQiOiJkaWQ6d2VidmgiLCJz...    ← SAVE THIS (WebVH server secrets bundle)
```

### What you now have

| Artifact | File | Needed By |
|----------|------|-----------|
| VTA config | `config.toml` | VTA service (Phase 6) |
| VTA data store | `data/vta/` | VTA service (Phase 6) |
| Mediator DID log | `mediator-did.jsonl` | WebVH server (Phase 3) |
| VTA DID log | `VTA-did.jsonl` | WebVH server (Phase 3) |
| WebVH DID log | `webvh-did.jsonl` | WebVH server (Phase 3) |
| Mediator secrets bundle | (base64 string you saved) | Mediator import (Phase 5) |
| WebVH secrets bundle | (base64 string you saved) | WebVH daemon (Phase 3) |
| Admin credential | (base64 string you saved) | PNM CLI (Phase 7) |

---

## Phase 3: Start the WebVH Server

The WebVH daemon hosts `did.jsonl` files so that `did:webvh` DIDs are
resolvable via HTTP. It supports importing pre-generated DID documents
offline via `load-did`, and requires secrets imported via `import-secrets`
before it can start.

We use **daemon mode** (all-in-one binary). For distributed mode with
separate `webvh-server` + `webvh-control` binaries, see
[Enabling Full WebVH Functionality](#enabling-full-webvh-functionality).

### 3.1 Create a minimal daemon config

```bash
cd ~/devel/affinidi/affinidi-webvh-service

cat > config.toml << 'EOF'
public_url = "http://localhost:8000"

[server]
host = "0.0.0.0"
port = 8000

[log]
level = "info"

[store]
data_dir = "data/daemon/store"

[witness_store]
data_dir = "data/daemon/witness"

[secrets]
keyring_service = "webvh-daemon"

[enable]
server = true
witness = false
watcher = false
control = false
EOF
```

> **Note:** During cold-start we enable only the server component (DID
> hosting). The control plane, witness, and watcher can be enabled later
> once the VTA is running and a context has been provisioned.

### 3.2 Import secrets (required)

The daemon requires signing, key-agreement, and JWT keys to start. Use the
WebVH secrets bundle exported in Phase 2.8:

```bash
./target/release/webvh-daemon import-secrets \
    --vta-bundle <webvh-secrets-bundle-from-phase-2.8>
```

```
  VTA bundle decoded for DID: did:webvh:...:localhost%3A8000
  Found 2 secret(s)
  Generated JWT signing key.

  Secrets imported successfully!
```

The JWT signing key is auto-generated. Secrets are stored in the OS keyring
under the service name configured in `[secrets]`.

### 3.3 Load the DID documents from the VTA setup wizard

```bash
# Load the mediator DID
./target/release/webvh-daemon load-did \
    --path dids/mediator \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/mediator-did.jsonl

# Load the VTA DID
./target/release/webvh-daemon load-did \
    --path dids/vta \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/VTA-did.jsonl

# Load the WebVH server's own DID at the root
./target/release/webvh-daemon load-did \
    --path .well-known \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/webvh-did.jsonl
```

Each `load-did` reads the file, validates the JSONL structure, and stores it
in the daemon's embedded fjall store. DIDs are immediately resolvable once
the daemon starts.

### 3.4 Start the daemon

```bash
./target/release/webvh-daemon
```

### 3.5 Verify DID resolution

```bash
# Verify the mediator DID
curl -s http://localhost:8000/dids/mediator/did.jsonl | head -c 200
echo

# Verify the VTA DID
curl -s http://localhost:8000/dids/vta/did.jsonl | head -c 200
echo

# Verify the WebVH server's own DID
curl -s http://localhost:8000/.well-known/did.jsonl | head -c 200
echo
```

Each should return JSONL starting with `{"didDocument":{"id":"did:webvh:...`.

### DID Path Mapping

The `--path` argument to `load-did` determines the URL where the DID is
served. It must match the URL entered during the VTA setup wizard:

| Setup wizard URL | `load-did --path` | Served at |
|-----------------|-------------------|-----------|
| `http://localhost:8000/dids/vta` | `dids/vta` | `http://localhost:8000/dids/vta/did.jsonl` |
| `http://localhost:8000/dids/mediator` | `dids/mediator` | `http://localhost:8000/dids/mediator/did.jsonl` |
| `http://localhost:8000` | `.well-known` | `http://localhost:8000/.well-known/did.jsonl` |

---

## Phase 4: Start Redis

The mediator uses Redis for message storage, forwarding queues, and session
management.

```bash
# macOS (Homebrew)
brew install redis
brew services start redis

# Linux
sudo apt install redis-server
sudo systemctl start redis

# Docker
docker run -d --name redis -p 6379:6379 redis:7

# Verify
redis-cli ping
# → PONG
```

---

## Phase 5: Configure and Start the Mediator

The mediator has a dedicated `--import-bundle` mode designed for cold-start.
It imports the VTA secrets bundle offline, caches the keys locally, and
starts without needing the VTA to be running. When the VTA later becomes
available, the mediator will fetch fresh secrets automatically.

### 5.1 Copy the mediator config template

```bash
cd ~/devel/affinidi/affinidi-tdk-rs/crates/messaging/affinidi-messaging-mediator

# The default config is at conf/mediator.toml
# Review it — key settings to note:
#   mediator_did       = will be updated by setup
#   [server]
#   listen_address     = "0.0.0.0:7037"
#   [database]
#   database_url       = "redis://127.0.0.1/"
#   [security]
#   mediator_secrets   = will be updated by setup
```

### 5.2 Import the VTA secrets bundle

```bash
cargo run --bin mediator-setup-vta --features setup -- --import-bundle
```

The wizard prompts for:

```
Mediator VTA Bundle Import
=========================

  Import a VTA secrets bundle for cold-start without a running VTA.

  VTA secrets bundle (base64url): ****    ← paste the secrets bundle from Phase 2.4
  * Decoded bundle for DID: did:webvh:QmMed...:localhost%3A8000:dids:mediator
    2 secrets

  VTA credential (base64url): ****        ← paste the admin credential from Phase 2.6

  Storage backend:
    > Embed in config file (string://) - simple, suitable for dev/CI
      AWS Secrets Manager (aws_secrets://) - production     [requires vta-aws-secrets feature]
      OS Keyring (keyring://) - local dev with OS keychain  [requires vta-keyring feature]

  * Secrets bundle cached (2 secrets)

  DID Document (optional)
  If you have the mediator's did.jsonl file, provide it so the mediator
  can resolve its own DID locally (without needing the webvh-server).

  Path to did.jsonl (or empty to skip): mediator-did.jsonl
  * Copied DID document to conf/mediator_did.jsonl

  VTA context ID [mediator]: mediator

Import complete!

  The mediator will use cached secrets when the VTA is unreachable.
  When the VTA becomes available, fresh secrets will be fetched automatically.

Start the mediator with:
  cargo run --bin mediator
```

This updates `conf/mediator.toml` with:
- `mediator_did = "vta://mediator"` (resolved from cached secrets)
- `[security] mediator_secrets = "vta://mediator"` (resolved from cached secrets)
- `[vta] credential = "string://eyJ..."` (or keyring/AWS)
- `[vta] context = "mediator"`
- `[server] did_web_self_hosted = "file://conf/mediator_did.jsonl"` (local resolution)

### 5.3 Update the admin DID

Edit `conf/mediator.toml` and set the admin DID to the VTA's admin DID
from Phase 2.6:

```toml
[server]
admin_did = "did://did:key:z6Mkr..."   # ← the admin DID from Phase 2.6
```

### 5.4 Start the mediator

```bash
cargo run --bin mediator
```

Expected output:

```
INFO  Mediator starting on 0.0.0.0:7037
INFO  VTA: using cached secrets (VTA unreachable)
INFO  DIDComm messaging ready
```

The "VTA unreachable" message is expected at this point -- the VTA isn't
running yet. The mediator operates with its cached secrets.

### 5.5 Verify

```bash
# Health check (if REST API is accessible)
curl -s http://localhost:7037/mediator/v1/health
```

---

## Phase 6: Start the VTA Service

With WebVH hosting the DID documents and the mediator running, start the VTA:

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service
```

Expected output:

```
INFO vta_service: VTA starting...
INFO vta_service: REST API listening on 0.0.0.0:8100
INFO vta_service: DIDComm messaging enabled
INFO vta_service: Connected to mediator
```

### Verify

```bash
curl -s http://localhost:8100/health | python3 -m json.tool
```

```json
{
    "status": "ok"
}
```

At this point the mediator will detect the VTA is now reachable and switch
from cached secrets to live VTA integration.

---

## Phase 7: Connect PNM (Personal Network Manager)

PNM is the operator CLI for managing a VTA. Connect it using the admin
credential saved from Phase 2.6.

### 7.1 Setup

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package pnm-cli -- setup
```

```
What would you like to do?
  > Connect to an existing VTA — I have an admin credential bundle

Paste the base64-encoded admin credential you received from
your VTA administrator or from the VTA's bootstrap output.

Admin credential: eyJ0eXAiOiJKV1Qi...    ← paste admin credential from Phase 2.6

Name for this VTA [vta]: my-trust-network
```

PNM decodes the credential (which contains the VTA DID and URL), resolves
the VTA DID via WebVH, authenticates via DIDComm challenge-response, and
caches the session in the OS keyring.

Alternatively, pass the credential directly:

```bash
cargo run --package pnm-cli -- setup --credential eyJ0eXAiOiJKV1Qi...
```

### 7.2 Verify connectivity

```bash
# Health check
cargo run --package pnm-cli -- health

# List contexts — should show 'vta', 'mediator', and 'webvh'
cargo run --package pnm-cli -- contexts list

# List keys — should show the signing and KA keys from setup
cargo run --package pnm-cli -- keys list
```

Expected contexts:

```
┌ Contexts (3) ─────────────────────────────────────────────────┐
│ ID          Name                          Base Path           │
│ vta         Verifiable Trust Agent        m/26'/2'/0'         │
│ mediator    DIDComm Messaging Mediator    m/26'/2'/1'         │
│ webvh       WebVH Server                  m/26'/2'/2'         │
└───────────────────────────────────────────────────────────────┘
```

---

## Phase 8: Create Application Contexts

With the full network running, create contexts for applications:

### Bootstrap a context with admin credentials

```bash
cargo run --package pnm-cli -- contexts bootstrap \
    --id myapp \
    --name "My Application" \
    --admin-label "MyApp Admin"
```

Output:

```
Context created:
  ID:        myapp
  Name:      My Application
  Base Path: m/26'/2'/2'

Admin credential created:
  DID:  did:key:z6Mkq...
  Role: admin

Credential (one-time secret — save this now):
eyJ0eXAiOiJKV1Qi...
```

### Provision a full bundle (context + DID + keys)

For applications that need their own DID:

```bash
cargo run --package pnm-cli -- contexts provision \
    --id myapp \
    --name "My Application" \
    --did-url "http://localhost:8000/dids/myapp" \
    --mediator-service
```

This creates a context, admin credentials, and a `did:webvh` DID in one
step. The output is a base64-encoded **provision bundle** containing
everything the application needs to connect.

> **Note:** For `--did-url` mode (serverless), the VTA generates the log
> entry but doesn't publish it to the WebVH server. You must load it
> manually. The `did.jsonl` content is included in the provision bundle.

```bash
# Extract the did.jsonl from the provision bundle and load it into the WebVH server
webvh-daemon load-did --path dids/myapp --did-log myapp-did.jsonl
```

### Create keys in a context

```bash
# Create an Ed25519 signing key
cargo run --package pnm-cli -- keys create \
    --key-type ed25519 \
    --context-id myapp \
    --label "Signing Key"

# List all keys
cargo run --package pnm-cli -- keys list
```

---

## REST-Only Mode (No Mediator, No DIDComm)

For the simplest possible cold start without DIDComm:

```bash
# Phase 1: Build VTI + WebVH
cd ~/devel/fpp/verifiable-trust-infrastructure && cargo build --workspace
cd ~/devel/affinidi/affinidi-webvh-service && cargo build -p webvh-daemon --release

# Phase 2: Setup — choose "Do not use DIDComm messaging"
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service --features setup -- setup

# Phase 2b: Generate WebVH server keys
cargo run --package vta-service --features setup -- \
    create-did-webvh --context webvh --label "WebVH Server"
# → Save webvh secrets bundle, outputs webvh-did.jsonl

# Phase 3: WebVH — import secrets, load VTA DID, start
cd ~/devel/affinidi/affinidi-webvh-service
# Create config.toml (see Phase 3.1), then:
./target/release/webvh-daemon import-secrets --vta-bundle <webvh-secrets-bundle>
./target/release/webvh-daemon load-did --path dids/vta \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/VTA-did.jsonl
./target/release/webvh-daemon load-did --path .well-known \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/webvh-did.jsonl
./target/release/webvh-daemon &

# Phase 4: Start VTA (no mediator or Redis needed)
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service

# Phase 5: Connect PNM
cargo run --package pnm-cli -- setup --credential <admin-credential>
```

In REST-only mode:
- No mediator context is created
- No Redis is needed
- Authentication uses HTTP challenge-response instead of DIDComm
- The VTA DID still needs to be hosted on the WebVH server

---

## Enabling Full WebVH Functionality

After the cold-start, the WebVH daemon/server is running with only the
server component (DID hosting). To enable the full feature set -- control
plane, witness, DIDComm sync, and VTA integration -- provision contexts
and reconfigure.

### 1. Provision a VTA context for the WebVH service

```bash
# For daemon mode (single context):
cargo run --package pnm-cli -- contexts provision \
    --id webvh \
    --name "WebVH Service" \
    --did-url "http://localhost:8000" \
    --mediator-service

# For distributed mode (one context per service):
cargo run --package pnm-cli -- contexts provision \
    --id webvh-control \
    --name "WebVH Control Plane" \
    --did-url "http://localhost:8532" \
    --mediator-service

cargo run --package pnm-cli -- contexts provision \
    --id webvh-server \
    --name "WebVH Server" \
    --did-url "http://localhost:8000" \
    --mediator-service
```

### 2. Configure VTA integration

**Daemon mode:** Run the setup wizard or update `config.toml` with the
VTA credential from the provision bundle:

```bash
# Import secrets from the provision bundle
./target/release/webvh-daemon import-secrets --vta-bundle <secrets-from-bundle>

# Bootstrap the server's own DID (now with proper keys)
./target/release/webvh-daemon bootstrap-did

# Enable all services
# Update config.toml:
#   [enable]
#   server = true
#   witness = true
#   control = true
```

**Distributed mode:** Run the setup wizard for each service:

```bash
./target/release/webvh-server setup
# Provide the webvh-server provision bundle

./target/release/webvh-control setup
# Provide the webvh-control provision bundle
```

### 3. Register the WebVH server in the VTA

```bash
cargo run --package pnm-cli -- webvh add-server \
    --id prod \
    --did "did:webvh:...:localhost%3A8000" \
    --label "Production WebVH"
```

Now the VTA can create new DIDs directly on the WebVH server:

```bash
cargo run --package pnm-cli -- webvh create-did \
    --context myapp \
    --server prod \
    --label "MyApp DID"
```

---

## Troubleshooting

### "DID not resolvable" errors

The DID resolver can't fetch `did.jsonl` from the WebVH server.

```bash
# Check the WebVH server is running
curl -v http://localhost:8000/dids/vta/did.jsonl

# List DIDs loaded in the WebVH server
./target/release/webvh-daemon list-dids   # or webvh-server list-dids

# Verify the DID was loaded at the correct path
./target/release/webvh-daemon dump-did --path dids/vta
```

The `--path` used in `load-did` must match the URL path from the VTA setup
wizard. For `did:webvh:{SCID}:localhost%3A8000:dids:vta`, use
`--path dids/vta`.

### "Keyring not available" errors

Common in headless/SSH sessions where the OS keyring isn't accessible.

```bash
# Use config-seed instead of keyring for the VTA
cargo run --package vta-service --no-default-features \
    --features setup,config-seed,rest -- setup
# Choose "Config file (hex in TOML)" for seed storage

# For the mediator, use "Embed in config file (string://)" storage
```

### Mediator: "VTA unreachable" at startup

This is expected during cold-start before the VTA is running. The mediator
uses cached secrets from the `--import-bundle` step. Once the VTA starts
(Phase 6), the mediator will reconnect automatically.

If the message persists after the VTA is running:
```bash
# Check VTA is accessible
curl -s http://localhost:8100/health

# Check mediator config for correct VTA credential
grep credential conf/mediator.toml

# Check VTA DID is resolvable (mediator needs this for DIDComm)
curl -s http://localhost:8000/dids/vta/did.jsonl | head -1
```

### Mediator: Redis connection failures

```bash
# Check Redis is running
redis-cli ping
# → PONG

# Check mediator config
grep database_url conf/mediator.toml
# Should be: database_url = "redis://127.0.0.1/"
```

### PNM can't authenticate

```bash
# Verify VTA health
curl -s http://localhost:8100/health

# Verify VTA DID is resolvable (PNM resolves it during setup)
curl -s http://localhost:8000/dids/vta/did.jsonl | head -1

# Verify mediator is running (PNM authenticates via DIDComm)
curl -s http://localhost:7037/mediator/v1/health

# Try with debug logging
RUST_LOG=debug cargo run --package pnm-cli -- setup --credential <credential>
```

### VTA won't start

```bash
# Check config
cat config.toml

# Check data directory
ls -la data/vta/

# Check mediator DID is resolvable
curl -s http://localhost:8000/dids/mediator/did.jsonl | head -1

# Run with debug logging
VTA_LOG_LEVEL=debug cargo run --package vta-service
```

---

## Quick Reference: Complete Cold-Start Sequence

```bash
# ── Phase 1: Build all repos ──
cd ~/devel/fpp/verifiable-trust-infrastructure && cargo build --workspace
cd ~/devel/affinidi/affinidi-webvh-service && cargo build -p webvh-daemon --release
cd ~/devel/affinidi/affinidi-tdk-rs && cargo build -p affinidi-messaging-mediator --features setup,vta-keyring

# ── Phase 2: VTA setup wizard (offline — no services needed) ──
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service --features setup -- setup
# → Save: mnemonic, mediator secrets bundle, admin credential
# → Outputs: mediator-did.jsonl, VTA-did.jsonl, config.toml, data/vta/

# ── Phase 2.8: Generate WebVH server keys (offline) ──
cargo run --package vta-service --features setup -- \
    create-did-webvh --context webvh --label "WebVH Server"
# → Save: webvh secrets bundle
# → Outputs: webvh-did.jsonl

# ── Phase 3: WebVH server (daemon mode) ──
cd ~/devel/affinidi/affinidi-webvh-service
# Create config.toml (see Phase 3.1 above), then:
./target/release/webvh-daemon import-secrets --vta-bundle <webvh-secrets-bundle>
./target/release/webvh-daemon load-did --path dids/mediator \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/mediator-did.jsonl
./target/release/webvh-daemon load-did --path dids/vta \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/VTA-did.jsonl
./target/release/webvh-daemon load-did --path .well-known \
    --did-log ~/devel/fpp/verifiable-trust-infrastructure/webvh-did.jsonl
./target/release/webvh-daemon &

# ── Phase 4: Redis ──
redis-server --daemonize yes    # or: docker run -d -p 6379:6379 redis:7

# ── Phase 5: Mediator (import-bundle for cold-start) ──
cd ~/devel/affinidi/affinidi-tdk-rs/crates/messaging/affinidi-messaging-mediator
cargo run --bin mediator-setup-vta --features setup -- --import-bundle
# → Paste secrets bundle + admin credential, provide mediator-did.jsonl
# → Edit conf/mediator.toml: set admin_did
cargo run --bin mediator &

# ── Phase 6: VTA service ──
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service &

# ── Phase 7: Connect PNM ──
cargo run --package pnm-cli -- setup --credential <admin-credential>
cargo run --package pnm-cli -- health
cargo run --package pnm-cli -- contexts list

# ── Phase 8: Create application contexts ──
cargo run --package pnm-cli -- contexts bootstrap \
    --id myapp --name "My Application" --admin-label "Admin"
```

---

## What the Setup Wizard Creates Internally

For reference, here is what the wizard creates in the VTA's fjall store
during Phase 2:

| Keyspace | Records Created | Purpose |
|----------|----------------|---------|
| `contexts` | `vta`, `mediator`, `webvh` | Application contexts with BIP-32 base paths |
| `keys` | Signing + KA keys per context | Ed25519 and X25519 key records |
| `keys` | `path_counter:*` | BIP-32 derivation counters |
| `keys` | Seed generation 0 | Active seed record |
| `webvh` | DID records | did:webvh metadata and log entries |
| `acl` | Admin entry | Initial admin with full access |

All keys derive from the single BIP-39 mnemonic via BIP-32 paths:

```
m/26'/2'/0'   → vta context (VTA's own signing + KA keys)
m/26'/2'/1'   → mediator context (mediator signing + KA keys)
m/26'/2'/2'   → webvh context (WebVH server signing + KA keys)
m/26'/2'/3'   → first application context (created in Phase 8)
...
```

## Service Ports Summary

| Service | Default Port | Protocol |
|---------|-------------|----------|
| WebVH daemon | 8534 (or 8000 in guide) | HTTP (DID hosting + control + witness) |
| WebVH server (standalone) | 8530 | HTTP (DID hosting only) |
| WebVH control (standalone) | 8532 | HTTP (DID lifecycle management) |
| Mediator | 7037 | HTTP + WebSocket (DIDComm) |
| VTA | 8100 | HTTP (REST + DIDComm) |
| Redis | 6379 | Redis protocol |

## WebVH Server CLI Quick Reference

Both `webvh-daemon` and `webvh-server` share these commands:

```bash
# Load a pre-generated DID from a did.jsonl file (offline, no VTA needed)
webvh-daemon load-did --path <url-path> --did-log <file.jsonl>

# Bootstrap a new DID using imported secrets (requires import-secrets first)
webvh-daemon bootstrap-did [--path <url-path>]

# Import signing/KA keys from a VTA secrets bundle
webvh-daemon import-secrets --vta-bundle <base64>

# List all hosted DIDs
webvh-daemon list-dids

# Dump a DID's log entry
webvh-daemon dump-did --path <url-path>

# Remove a DID
webvh-daemon remove-did --path <url-path>
```
