# VTA Threat Model

This document describes the threat model for the Verifiable Trust Agent (VTA) when deployed in TEE mode (AWS Nitro Enclaves).

## Trust Boundaries

```
┌──────────────────────────────────┐
│        Untrusted Zone            │
│  (Internet, external clients)    │
└──────────────┬───────────────────┘
               │ HTTPS (TLS)
┌──────────────┴───────────────────┐
│     Semi-Trusted Zone            │
│  (Parent EC2 instance)           │
│  - enclave-proxy                 │
│  - EBS volumes (ciphertext only) │
│  - IAM role (limited)            │
└──────────────┬───────────────────┘
               │ vsock (no network)
┌──────────────┴───────────────────┐
│       Trusted Zone               │
│  (Nitro Enclave)                 │
│  - VTA service                   │
│  - Plaintext secrets (memory)    │
│  - Encrypted storage (fjall)     │
│  - /dev/nsm (attestation)        │
└──────────────────────────────────┘
```

## Adversary Model

### A1: Network Attacker
**Capabilities:** Intercept/modify network traffic between clients and the VTA.
**Mitigations:**
- TLS termination on parent proxy (inbound)
- DIDComm authenticated encryption (end-to-end)
- HTTPS CONNECT proxy with allowlist (outbound)

### A2: Compromised Parent Instance
**Capabilities:** Root access to the EC2 host. Can read EBS, modify proxy, inject env vars.
**Mitigations:**
- Nitro Enclave memory isolation (hypervisor-enforced)
- KMS key policy with PCR pinning (PCR0 + PCR8)
- Environment variable locking when KMS bootstrap active
- Storage encrypted with AES-256-GCM (key only in enclave memory)
- Attestation reports prove enclave identity to clients
- DID method whitelist blocks `did:web` through untrusted resolver

### A3: Supply Chain Attacker
**Capabilities:** Modify the enclave image or signing certificate.
**Mitigations:**
- PCR0 (image hash) pinned in KMS key policy
- PCR8 (signing cert hash) pinned in KMS key policy
- EIF signing with P-384 key (stored offline)
- KMS Decrypt fails if PCRs don't match → secrets inaccessible

### A4: Insider with Admin Access
**Capabilities:** Valid admin DID credentials. Can manage keys, ACL, config.
**Mitigations:**
- Role-based access control (admin, initiator, application)
- Context scoping limits admin to assigned contexts
- Structured audit logging (target: "audit") for all admin operations
- VTA seal prevents offline CLI manipulation after deployment
- Mnemonic export is time-limited and one-time only

### A5: Denial of Service
**Capabilities:** Flood endpoints with requests.
**Mitigations:**
- Request body size limits (1MB default)
- Connection limits on proxy (semaphore-based)
- Store operation timeouts (30s)
- Rate limiting on auth endpoints (recommended via reverse proxy)

## Attack Trees

### AT1: Steal Master Seed
```
Steal master seed
├── Read enclave memory → BLOCKED (Nitro hypervisor)
├── Decrypt seed.enc from EBS
│   ├── Obtain KMS Decrypt access
│   │   ├── Modify KMS key policy → requires admin MFA
│   │   └── Spoof PCR values → BLOCKED (hardware-measured)
│   └── Brute-force AES-256 → computationally infeasible
├── Export mnemonic via API
│   ├── Obtain super-admin JWT
│   │   ├── Steal JWT signing key → only in enclave memory
│   │   └── Brute-force Ed25519 → computationally infeasible
│   └── Bypass time window → entropy zeroed after window
└── Intercept during KMS Decrypt
    ├── MITM vsock proxy → TLS to KMS (webpki-roots)
    └── Read KMS response → TLS encrypted (TODO: Recipient param)
```

### AT2: Impersonate VTA
```
Impersonate VTA
├── Forge attestation report → requires /dev/nsm (enclave-only)
├── Replace enclave image
│   └── KMS Decrypt fails (PCR0 mismatch) → no secrets
├── Run VTA outside enclave
│   └── tee.mode = "required" → refuses to start
└── Inject config via env vars
    └── KMS lock blocks all security-relevant env overrides
```

### AT3: Privilege Escalation
```
Escalate privileges
├── Modify ACL via CLI → BLOCKED by VTA seal
├── Tamper with fjall store directly
│   └── AES-256-GCM encrypted → requires storage key
├── Forge JWT token
│   └── Ed25519 signing key only in enclave memory
├── Replay auth challenge
│   └── Nonce stored in session KS, state machine prevents replay
└── Create admin via API
    └── Requires existing admin/initiator JWT with Manage role
```

## Residual Risks

| Risk | Severity | Status | Notes |
|------|----------|--------|-------|
| KMS Recipient parameter not implemented | Medium | TODO | Parent could theoretically intercept KMS Decrypt response; mitigated by TLS + key policy |
| No per-IP rate limiting in VTA | Low | Mitigated | Deploy behind reverse proxy with rate limiting |
| Health endpoint information disclosure | Low | Fixed | Split into minimal (public) and detailed (auth required) |
| DID resolver through parent | Low | Mitigated | Whitelist blocks `did:web`; `did:key` and `did:webvh` are self-certifying |

## Cryptographic Inventory

| Algorithm | Purpose | Key Size | Standard |
|-----------|---------|----------|----------|
| Ed25519 | Signing, authentication | 256-bit | RFC 8032 |
| X25519 | Key agreement (DIDComm) | 256-bit | RFC 7748 |
| AES-256-GCM | Storage encryption | 256-bit | NIST SP 800-38D |
| HKDF-SHA256 | Storage key derivation | 256-bit | RFC 5869 |
| BIP-39 | Mnemonic seed generation | 256-bit entropy | BIP-39 |
| BIP-32 | Hierarchical key derivation | Ed25519 | BIP-32/SLIP-0010 |
| SHA-256 | JWT fingerprint, nonce hashing | 256-bit | FIPS 180-4 |
| ECDSA P-384 | EIF signing (Nitro) | 384-bit | FIPS 186-4 |
| COSE_Sign1 | Attestation reports (Nitro) | ES384 | RFC 8152 |
