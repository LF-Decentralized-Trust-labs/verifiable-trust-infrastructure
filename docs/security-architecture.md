# VTA Security Architecture

## Overview

The VTA implements a defense-in-depth security model with eight layers of protection when deployed in TEE mode.

## Security Layers

### Layer 1: Hardware Isolation (Nitro Enclave)
- Enclave runs in isolated memory — parent EC2 cannot read enclave RAM
- No direct network access — all I/O through vsock channels
- `/dev/nsm` provides hardware-backed attestation and entropy
- Hypervisor enforces isolation (not software-based)

### Layer 2: KMS-Backed Secrets
- Master seed generated inside enclave using NSM-backed random
- Encrypted with AWS KMS before leaving enclave memory
- KMS key policy requires PCR0 (image hash) + PCR8 (signing cert)
- Only the exact enclave image + signing cert can decrypt secrets
- JWT signing key also KMS-encrypted with fingerprint verification

### Layer 3: Encrypted Storage
- All fjall keyspace values encrypted with AES-256-GCM
- Storage key derived from master seed via HKDF-SHA256
- Deterministic derivation — same seed produces same key across restarts
- Keys stored in plaintext for prefix scans; values always encrypted
- Each value: `[12-byte random nonce][ciphertext][16-byte auth tag]`

### Layer 4: Configuration Locking
- When KMS bootstrap is active, environment variable overrides are blocked
- Only `VTA_LOG_LEVEL` and `VTA_LOG_FORMAT` remain configurable
- Prevents parent-side attacker from injecting `VTA_DID`, `VTA_AUTH_JWT_SIGNING_KEY`, etc.
- Config baked into EIF at build time — immutable after signing

### Layer 5: Identity & Access Control
- DID-based authentication via challenge-response (Ed25519 signatures)
- Role hierarchy: super-admin > admin > initiator > application
- Context scoping restricts access to assigned application contexts
- DID method whitelist blocks unsafe `did:web` in TEE mode
- Session state machine prevents challenge replay

### Layer 6: VTA Seal
- After initial admin bootstrap, VTA is "sealed"
- All offline CLI commands (key management, ACL changes) disabled
- Management only via authenticated REST/DIDComm
- Unsealing requires challenge-response proof of admin key ownership
- In TEE mode, seal marker is AES-256-GCM encrypted in storage

### Layer 7: Network Controls
- Three vsock channels with strict purpose separation:
  - Inbound REST (port 5100): client requests to VTA
  - Outbound mediator (port 5200): DIDComm messaging with TLS
  - Outbound HTTPS (port 5300): allowlisted destinations only
- HTTPS CONNECT proxy validates every request against allowlist
- Non-CONNECT requests rejected with 405 Method Not Allowed
- Connection limits prevent resource exhaustion
- Request body size limits protect enclave memory

### Layer 8: Audit & Observability
- Structured audit events at target "audit" — never suppressed by log level
- All security operations logged: auth, ACL changes, key operations, exports
- Health endpoint split: minimal (public) vs. detailed (authenticated)
- Graceful shutdown with store persistence guarantees

## Key Lifecycle

```
1. First Boot (inside enclave):
   ┌─────────────────────────────────────────┐
   │ Generate 256-bit entropy (/dev/nsm)     │
   │ → BIP-39 mnemonic (24 words)            │
   │ → BIP-32 master seed (512 bits)         │
   │ → KMS Encrypt(seed) → seed.enc          │
   │ → Generate JWT key (256 bits)            │
   │ → KMS Encrypt(jwt) → jwt.enc            │
   │ → HKDF(seed, salt) → storage key        │
   │ → Start mnemonic export window           │
   └─────────────────────────────────────────┘

2. Key Derivation (BIP-32 hierarchy):
   m/26'/2'/N'/K'
   │       │  │
   │       │  └── Key counter (sequential)
   │       └───── Context index (sequential)
   └────────────── FPN reserved prefix

3. Subsequent Boot:
   ┌─────────────────────────────────────────┐
   │ Read seed.enc + jwt.enc from EBS        │
   │ → KMS Decrypt(seed.enc) → seed          │
   │ → KMS Decrypt(jwt.enc) → jwt key        │
   │ → Verify JWT fingerprint (SHA-256)       │
   │ → HKDF(seed, salt) → same storage key   │
   │ → Open encrypted fjall store             │
   │ → Resume operations                      │
   └─────────────────────────────────────────┘

4. Key Rotation:
   ┌─────────────────────────────────────────┐
   │ Generate new seed (or import mnemonic)   │
   │ → Mark old seed generation as "retired"  │
   │ → New keys derived from new seed         │
   │ → Old keys remain readable (old seed)    │
   └─────────────────────────────────────────┘
```

## Authentication Flow

```
Client                          VTA (in enclave)
  │                                  │
  │  POST /auth/challenge {did}      │
  │ ─────────────────────────────►   │
  │                                  │ ← Check DID whitelist
  │                                  │ ← Check DID in ACL
  │                                  │ ← Generate 32-byte nonce
  │                                  │ ← Store nonce (replay detection)
  │                                  │ ← Generate attestation report
  │  {sessionId, challenge,          │
  │   tee_attestation}               │
  │ ◄─────────────────────────────   │
  │                                  │
  │  (client verifies attestation)   │
  │  (client signs challenge)        │
  │                                  │
  │  POST /auth/ (DIDComm packed)    │
  │ ─────────────────────────────►   │
  │                                  │ ← Unpack DIDComm (verify sig)
  │                                  │ ← Validate session state
  │                                  │ ← Verify challenge match
  │                                  │ ← Check challenge TTL
  │                                  │ ← Issue JWT (EdDSA signed)
  │  {accessToken, refreshToken}     │
  │ ◄─────────────────────────────   │
  │                                  │
  │  GET /keys (Bearer token)        │
  │ ─────────────────────────────►   │
  │                                  │ ← Validate JWT signature
  │                                  │ ← Check expiry, role, contexts
  │  {keys: [...]}                   │
  │ ◄─────────────────────────────   │
```

## Deployment Security Checklist

- [ ] TEE mode set to `required` (not `optional` or `simulated`)
- [ ] KMS key policy pinned to PCR0 + PCR8
- [ ] EIF signed with offline P-384 key
- [ ] IAM role limited to `kms:Encrypt` + `kms:Decrypt`
- [ ] KMS admin requires MFA for policy changes
- [ ] DID method whitelist: `["did:key", "did:webvh"]`
- [ ] Reverse proxy with TLS, rate limiting, CORS policy
- [ ] Mnemonic exported and stored securely offline
- [ ] VTA sealed after admin bootstrap
- [ ] Audit logs shipped to SIEM
- [ ] CloudTrail alerts on KMS policy changes
- [ ] Health endpoint accessible only to monitoring systems
