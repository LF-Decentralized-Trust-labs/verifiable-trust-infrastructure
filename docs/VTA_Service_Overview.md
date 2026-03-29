# VTA Service Overview — v0.2.0

Presentation content for updating VTA_Service_Overview.pptx.

---

## Slide 1: Title

**Verifiable Trust Agent (VTA) v0.2.0**

Key management, DID operations, and access control for Verifiable Trust Communities.

Part of the [First Person Network](https://www.firstperson.network/white-paper).

---

## Slide 2: What is the VTA?

A **cryptographic key management agent** that:

- Manages BIP-32 derived keys (Ed25519, X25519, P-256)
- Controls access via DID-based authentication
- Communicates over REST API and DIDComm v2
- Runs locally, in the cloud, or inside AWS Nitro Enclaves (TEE)
- Supports backup, restore, and migration between environments

---

## Slide 3: Architecture Overview

```
┌─────────────────────────────────────────────┐
│                  Workspace                   │
│                                             │
│  vti-common ──► vta-sdk ──► vta-service     │
│      │              │           │ (lib)      │
│      │              │           ▼            │
│      │              │      vta-enclave       │
│      │              │       (TEE binary)     │
│      │              ▼                        │
│      │         vta-cli-common                │
│      │           │       │                   │
│      │           ▼       ▼                   │
│      │        pnm-cli  cnm-cli              │
│      ▼                                       │
│  vtc-service                                 │
└─────────────────────────────────────────────┘
```

**9 crates** — clean layered dependencies, no circular deps.

---

## Slide 4: Dual Transport Architecture

```
  REST Client                   DIDComm Client
      │                              │
      │ HTTP + JWT                   │ Mediator + JWE
      ▼                              ▼
  REST Routes                  DIDComm Router
  + Auth Extractors            + MessagePolicy
      │                              │
      └──────────┬───────────────────┘
                 ▼
        Shared Operations Layer
                 │
                 ▼
           fjall Store
```

- **REST**: Axum 0.8, JWT authentication, role-based extractors
- **DIDComm**: affinidi-messaging-didcomm-service, typed router, middleware
- Both converge on the **same operations** — consistent behavior guaranteed

---

## Slide 5: Security Model

**5-tier role hierarchy:**

| Role | Access |
|------|--------|
| Super Admin | Everything — backup, restore, restart, config |
| Admin | Key management, ACL, contexts, audit |
| Initiator | ACL management, application onboarding |
| Application | API access within allowed contexts |
| Monitor | Metrics and health only |

**Context scoping**: Admins can be restricted to specific application contexts.

---

## Slide 6: Authentication Flow

```
Client                              VTA
  │                                  │
  │  POST /auth/challenge {did}      │
  │─────────────────────────────────►│
  │                                  │ Generate challenge + session
  │  {session_id, challenge}         │
  │◄─────────────────────────────────│
  │                                  │
  │  Sign challenge with DID key     │
  │  POST /auth/ (DIDComm message)   │
  │─────────────────────────────────►│
  │                                  │ Verify signature + challenge
  │  {access_token, refresh_token}   │
  │◄─────────────────────────────────│
```

- DIDComm v2 challenge-response
- Short-lived EdDSA JWTs (Ed25519)
- Session state machine prevents replay

---

## Slide 7: Key Management

**BIP-32 hierarchical deterministic keys:**

```
m (BIP-39 seed)
└── 26' (VTI purpose)
    ├── 2' (Ed25519)
    │   ├── 0' (Context 0)
    │   │   ├── 0' (Key 0)
    │   │   └── 1' (Key 1)
    │   └── 1' (Context 1)
    │       └── 0' (Key 0)
    └── 256' (P-256 domain)
        └── N' (Context)
            └── K' (Key)
```

- **Single seed** → all keys derived deterministically
- **Ed25519** (signing), **X25519** (key agreement), **P-256** (secp256r1)
- **Signing oracle**: `POST /keys/{key_id}/sign`

---

## Slide 8: TEE Enclave Support (AWS Nitro)

```
┌─────── Nitro Enclave ───────┐    ┌─── Parent EC2 ───┐
│                              │    │                   │
│  VTA Service                 │    │  Enclave Proxy    │
│  (encrypted storage)    ◄────┼────┤  (7 vsock channels)
│                              │    │                   │
│  KMS Bootstrap               │    │  fjall Store      │
│  (seed + JWT encryption)     │    │  DID Resolver     │
│                              │    │                   │
└──────────────────────────────┘    └───────────────────┘
                                           │
                                    ┌──────┴──────┐
                                    │  Mediator   │
                                    │  AWS KMS    │
                                    │  IMDS       │
                                    └─────────────┘
```

- **KMS-encrypted secrets**: Seed + JWT key encrypted at rest with Nitro attestation
- **PCR enforcement**: KMS key policy locks to enclave image hash (PCR0) + signing cert (PCR8)
- **Encrypted storage**: AES-256-GCM, key derived from seed via HKDF
- **Auto-DID generation**: did:webvh identity created on first boot

---

## Slide 9: Backup & Restore

**Encrypted backup system:**

1. Export: `pnm backup export` → `.vtabak` file
2. Encryption: **Argon2id** (64 MiB, 3 iter) → **AES-256-GCM**
3. Contains: seed, keys, ACL, contexts, WebVH DIDs, config, optional audit
4. Import: `pnm backup import` → preview → confirm → **soft restart**
5. TEE: auto re-encrypts secrets with local KMS on import

**Requires super admin. Password minimum 12 characters.**

---

## Slide 10: Operational Features

- **Soft restart**: `POST /vta/restart` or `pnm vta restart` — no process restart needed
- **Prometheus metrics**: `GET /metrics` — request count, latency histograms
- **Structured audit logs**: All security operations logged with actor, action, outcome
- **Audit retention**: Configurable retention period with automatic cleanup
- **Health checks**: `/health` (unauthenticated) + `/health/details` (authenticated)

---

## Slide 11: CLI Tools

**PNM CLI** (Personal Network Manager):

```
pnm setup                    Configure VTA connection
pnm health                   Service health + DIDComm trust-ping
pnm keys create/list/revoke  Key management
pnm contexts provision       Application onboarding
pnm acl create/update        Access control
pnm backup export/import     Encrypted backup/restore
pnm vta restart              Soft restart
pnm webvh create-did         DID creation (did:webvh)
```

**CNM CLI** (Community Network Manager): Multi-community management.

---

## Slide 12: DIDComm Protocol

**8 protocol families, 50+ message types:**

| Family | Operations |
|--------|-----------|
| Key Management | create, get, list, rename, revoke, sign |
| Seed Management | list, rotate |
| Context Management | create, get, list, update, delete |
| ACL Management | create, get, list, update, delete |
| Backup Management | export, import |
| VTA Management | get-config, update-config, restart |
| Credential Management | generate |
| Attestation | get-status, request-attestation |

All messages: encrypted + authenticated + signed (MessagePolicy middleware).

---

## Slide 13: Quality & Testing

**226 tests across the workspace:**

| Category | Count |
|----------|-------|
| API integration (real axum server) | 31 |
| Security enforcement (roles, ACL, crypto) | 20 |
| Key derivation (BIP-32) | 16 |
| KMS bootstrap (TEE) | 8 |
| Backup crypto (Argon2id + AES-GCM) | 7 |
| Client SDK | 22 |
| Configuration | 18 |
| Session management | 9 |
| Other (store, DID, credentials) | 95 |

**Clippy clean. Doc comments on all public handlers.**

---

## Slide 14: Technology Stack

| Layer | Choice |
|-------|--------|
| Language | Rust 1.91+ (edition 2024) |
| Web framework | Axum 0.8 |
| Async runtime | Tokio |
| Storage | fjall (embedded LSM-tree) |
| Cryptography | ed25519-dalek, p256, aes-gcm, argon2 |
| DID resolution | affinidi-did-resolver-cache-sdk |
| DIDComm | affinidi-tdk + affinidi-messaging-didcomm-service |
| JWT | jsonwebtoken (EdDSA) |
| Metrics | metrics + metrics-exporter-prometheus |
| TEE | AWS Nitro Enclaves + KMS |

---

## Slide 15: What's New in v0.2.0

- TEE Enclave support (AWS Nitro)
- DIDComm service migration (typed router)
- P-256 key support + signing oracle
- Backup & restore with Argon2id encryption
- Soft restart infrastructure
- Prometheus metrics with Monitor role
- 226 tests (51 new integration + security)
- 6 Mermaid architecture diagrams
- Consolidated documentation
