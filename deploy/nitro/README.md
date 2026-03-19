# VTA on AWS Nitro Enclaves — Deployment Guide

Deploy the Verifiable Trust Agent (VTA) inside an AWS Nitro Enclave with
hardware-backed TEE attestation, KMS-based secret bootstrap, encrypted
storage, and signed enclave images.

## Security Model

```
┌─────────────────────────────────────────────────────────────────────┐
│  What stops a compromised EC2 host from stealing secrets?           │
│                                                                     │
│  Layer 1: PCR0 (image hash)                                         │
│    → Different enclave image = different hash = KMS rejects         │
│                                                                     │
│  Layer 2: PCR8 (EIF signing certificate)                            │
│    → Unsigned or wrongly-signed image = KMS rejects                 │
│    → Signing key lives in CI/CD, never on EC2                       │
│                                                                     │
│  Layer 3: PCR3 (IAM role)                                           │
│    → Can't use a different role to bypass the policy                │
│                                                                     │
│  Layer 4: Ephemeral RSA key                                         │
│    → KMS response encrypted to enclave's key                        │
│    → Network MITM can't read the response                           │
│                                                                     │
│  Layer 5: IAM separation                                            │
│    → EC2 role: kms:Decrypt + kms:Encrypt only                       │
│    → Admin role (separate account): kms:PutKeyPolicy + MFA          │
│                                                                     │
│  Layer 6: Hardware memory isolation                                  │
│    → Nitro hypervisor prevents parent from reading enclave memory   │
│                                                                     │
│  Layer 7: Encrypted external storage                                │
│    → All fjall data AES-256-GCM encrypted inside TEE                │
│    → Parent EBS only has ciphertext                                 │
│                                                                     │
│  Layer 8: CloudTrail audit                                          │
│    → All KMS policy changes logged and alertable                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Nitro Enclave (no network access, isolated memory)                 │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  VTA Service                                                 │   │
│  │                                                              │   │
│  │  Boot: ephemeral RSA key → NSM attestation → KMS Decrypt    │   │
│  │        → seed + JWT key in TEE memory only                   │   │
│  │                                                              │   │
│  │  Runtime: REST :8100 + DIDComm (via vsock proxies)          │   │
│  │           All storage AES-256-GCM encrypted                  │   │
│  │           /dev/nsm for attestation reports                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  vsock proxies: inbound(:5100) mediator(:5200) HTTPS(:5300)        │
└────────────┬──────────────┬──────────────┬──────────────────────────┘
             │ vsock        │ vsock        │ vsock
┌────────────▼──────────────▼──────────────▼──────────────────────────┐
│  Parent EC2 Instance                                                │
│  parent-proxy.sh: REST ↔ vsock, mediator ↔ vsock, HTTPS ↔ vsock   │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### EC2 Instance

| Requirement | Details |
|------------|---------|
| Instance type | Nitro Enclave capable: `m5.xlarge`, `c5.xlarge`, `r5.xlarge` or larger |
| AMI | Amazon Linux 2023 or Ubuntu 22.04+ |
| Enclave support | Enabled at launch: `--enclave-options Enabled=true` |
| IAM role | Minimal: `kms:Decrypt`, `kms:Encrypt` only (see Step 3) |

### Software on the Parent Instance

```bash
# Amazon Linux 2023
sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat

# Ubuntu
sudo apt install -y aws-nitro-enclaves-cli docker.io socat

# Enable services
sudo systemctl enable --now nitro-enclaves-allocator docker

# Add your user to the docker and ne groups (required before building images)
sudo usermod -aG docker,ne $USER

# IMPORTANT: Log out and back in (or run `newgrp docker`) for group changes
# to take effect. Docker commands will fail with "permission denied" until
# your session picks up the new group membership.
```

### Configure Enclave Resources

Edit `/etc/nitro_enclaves/allocator.yaml`:

```yaml
memory_mib: 1024
cpu_count: 2
```

```bash
sudo systemctl restart nitro-enclaves-allocator
```

## Step 1: Generate EIF Signing Key

**Run this on your build machine or CI/CD pipeline — NOT on the EC2 instance.**

The signing key ensures only images built by your pipeline can decrypt secrets.
PCR8 (the certificate hash) is included in the KMS key policy.

```bash
chmod +x deploy/nitro/generate-signing-key.sh
./deploy/nitro/generate-signing-key.sh ./signing

# Output:
#   ./signing/signing-key.pem     — Private key (KEEP SECRET)
#   ./signing/signing-cert.pem    — Certificate (include in builds)
#   ./signing/pcr8.txt            — PCR8 hash for KMS policy
```

Store the private key securely:
- **CI/CD pipeline secret** (GitHub Actions secret, GitLab CI variable, etc.)
- **AWS Secrets Manager** in a separate account
- **Hardware security module** for maximum security
- **Never** on the EC2 instance that runs the enclave

## Step 2: Choose a Build Profile

The VTA supports different feature flag combinations for different security
postures. Choose the profile that matches your deployment:

### Profile A: Hardened (DIDComm only — recommended for production TEE)

All secret-handling operations go through DIDComm (E2E encrypted). REST is
limited to attestation, health, and auth bootstrap (unauthenticated/read-only).
This is the smallest attack surface.

```bash
docker build -f Dockerfile.nitro \
    --build-arg FEATURES="didcomm,tee" \
    -t vta-nitro .
```

| Available on REST | Available on DIDComm |
|---|---|
| `GET /health` | Key management (create, list, get, revoke, secrets) |
| `GET,POST /attestation/report` | ACL management (CRUD) |
| `GET /attestation/status` | Config management |
| `POST /auth/challenge` | Credential generation |
| `POST /auth/` | Context management |
| `POST /auth/refresh` | Seed rotation |
| | WebVH DID operations |

### Profile B: Full API (REST + DIDComm — for development or network-controlled environments)

All operations available on both REST and DIDComm. Use when the REST API is
behind a load balancer, VPN, or other network-level access control.

```bash
docker build -f Dockerfile.nitro \
    --build-arg FEATURES="rest,didcomm,tee" \
    -t vta-nitro .
```

### Profile C: REST only (no DIDComm — for simple deployments without a mediator)

```bash
docker build -f Dockerfile.nitro \
    --build-arg FEATURES="rest,tee" \
    -t vta-nitro .
```

### Customizing Feature Flags

The `FEATURES` build arg maps directly to Cargo feature flags. Available features:

| Feature | Purpose | TEE deployment |
|---------|---------|----------------|
| `rest` | REST API endpoints | Optional (Profile B/C) |
| `didcomm` | DIDComm v2 messaging | Recommended (Profile A/B) |
| `tee` | TEE attestation + KMS bootstrap + encrypted storage | **Required** |
| `keyring` | OS keyring seed storage | **Do not use** (no keyring in enclaves) |
| `config-seed` | Load seed from config file | **Do not use** (KMS bootstrap provides the seed) |
| `aws-secrets` | AWS Secrets Manager seed storage | **Do not use** (KMS bootstrap provides the seed) |
| `webvh` | did:webvh DID management | Optional |
| `setup` | Interactive setup wizard (requires TTY) | **Do not use** (no TTY in enclaves) |

**In TEE mode with KMS bootstrap**, the `tee` feature handles all secret management:
- The seed is generated inside the TEE on first boot and encrypted to KMS
- The JWT signing key is generated inside the TEE and encrypted to KMS
- On subsequent boots, both are decrypted from KMS with attestation verification
- No other seed storage backend (`config-seed`, `keyring`, `aws-secrets`) is needed

## Step 3: Build and Sign the Enclave Image

```bash
# Build the Docker image (using your chosen profile from Step 2)
docker build -f Dockerfile.nitro -t vta-nitro .

# Build AND SIGN the Enclave Image File
nitro-cli build-enclave \
    --docker-uri vta-nitro \
    --output-file vta.eif \
    --signing-certificate ./signing/signing-cert.pem \
    --private-key ./signing/signing-key.pem
```

Save the output — you need **PCR0** for the KMS policy:

```
Enclave Image successfully created.
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "abc123def456...",    ← Enclave image hash
    "PCR1": "...",                ← Kernel + boot ramfs
    "PCR2": "...",                ← Application
    "PCR8": "789abc012..."        ← Signing certificate (matches pcr8.txt)
  }
}
```

Verify PCR8 matches your signing key:
```bash
cat ./signing/pcr8.txt
# Should match the PCR8 from build output
```

## Step 4: Set Up IAM Roles and KMS Key Policy

This step creates the IAM roles and a KMS key that **only releases secrets to
your exact enclave image, signed by your certificate, running on your IAM role**.

### 4a: Create the EC2 Instance Role

The EC2 instance running the enclave needs a minimal IAM role. Create it in the
AWS Console or via CLI:

```bash
# Create the role with EC2 trust policy
aws iam create-role \
    --role-name vta-enclave-role \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }'

# Create an instance profile and attach the role
aws iam create-instance-profile --instance-profile-name vta-enclave-profile
aws iam add-role-to-instance-profile \
    --instance-profile-name vta-enclave-profile \
    --role-name vta-enclave-role
```

The KMS permissions for this role are set by the KMS key policy in Step 4c —
you do NOT need to attach a KMS policy to the role itself. KMS key policies
are authoritative when they grant access to a principal.

If your EC2 instance is already running, attach the profile:
```bash
aws ec2 associate-iam-instance-profile \
    --instance-id i-0123456789abcdef0 \
    --iam-instance-profile Name=vta-enclave-profile
```

### 4b: IAM Permissions for the KMS Setup User

The person (or CI/CD role) running `setup-kms-policy.sh` needs these
permissions. This is your **admin user**, separate from the EC2 instance role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowKMSKeyManagement",
            "Effect": "Allow",
            "Action": [
                "kms:CreateKey",
                "kms:CreateAlias",
                "kms:PutKeyPolicy",
                "kms:DescribeKey",
                "kms:ListAliases",
                "kms:TagResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowCheckCallerIdentity",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*"
        }
    ]
}
```

Attach this policy to your IAM user or role:
```bash
# Create the policy
aws iam create-policy \
    --policy-name vta-kms-admin \
    --policy-document file://deploy/nitro/iam-kms-admin-policy.json

# Attach to your IAM user
aws iam attach-user-policy \
    --user-name your-admin-user \
    --policy-arn arn:aws:iam::123456789012:policy/vta-kms-admin

# Or attach to a role (for CI/CD)
aws iam attach-role-policy \
    --role-name your-ci-role \
    --policy-arn arn:aws:iam::123456789012:policy/vta-kms-admin
```

### 4c: Create the KMS Key with Attestation Policy

```bash
chmod +x deploy/nitro/setup-kms-policy.sh

./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "abc123def456..." \
    --pcr8 "789abc012..." \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --region us-east-1
```

This creates a KMS key with three policy statements:

| Statement | Principal | Actions | Condition |
|-----------|-----------|---------|-----------|
| Key administration | Your IAM user/role | Full management | None (admin only) |
| Encrypt | EC2 instance role | `kms:Encrypt` | None (for first-boot seed storage) |
| **Attestation decrypt** | EC2 instance role | `kms:Decrypt`, `kms:GenerateDataKey` | **PCR0 + PCR8 must match** |

The script outputs the KMS key ARN. Now update the VTA config and rebuild the
enclave image.

### 4d: Update Config with KMS Key ARN

Edit the reference config file with the KMS key ARN from Step 4c:

```bash
# Edit the config
nano deploy/nitro/config.toml
```

Replace `REPLACE_WITH_KMS_KEY_ARN` with your actual KMS key ARN:

```toml
[tee.kms]
region = "us-east-1"
key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
seed_ciphertext_path = "/mnt/vta-data/secrets/seed.enc"
jwt_ciphertext_path = "/mnt/vta-data/secrets/jwt.enc"
allow_first_boot = true     # Set to false after the first successful boot
```

If you have a DIDComm mediator, also uncomment and configure the `[messaging]`
section:

```toml
[messaging]
mediator_url = "ws://127.0.0.1:4443"
mediator_did = "did:web:mediator.example.com"
```

### 4e: Rebuild the Enclave Image with Updated Config

The config is baked into the EIF, so any config change requires a rebuild.
This also generates a new PCR0 (image hash) which must be updated in the
KMS key policy.

**Use the same `docker build` command from your chosen profile in Step 2.**
If you chose Profile B (Full API), the rebuild cycle is:

```bash
# 1. Rebuild the Docker image with the SAME profile as Step 2
#    Profile A (Hardened):       --build-arg FEATURES="didcomm,tee"
#    Profile B (Full API):       --build-arg FEATURES="rest,didcomm,tee"
#    Profile C (REST only):      --build-arg FEATURES="rest,tee"
#    Or omit --build-arg to use the Dockerfile default (rest,didcomm,tee)
docker build -f Dockerfile.nitro -t vta-nitro .

# 2. Rebuild and sign the EIF
nitro-cli build-enclave \
    --docker-uri vta-nitro \
    --output-file vta.eif \
    --signing-certificate ./signing/signing-cert.pem \
    --private-key ./signing/signing-key.pem

# 3. Note the new PCR0 from the output
#    PCR0: "new_hash_here..."

# 4. Update the KMS key policy with the new PCR0
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "NEW_PCR0_HASH" \
    --pcr8 "$(cat ./signing/pcr8.txt)" \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

**Every config or code change follows this cycle:** edit → docker build
(same profile) → nitro build-enclave → update KMS policy with new PCR0.
This is by design — the PCR0 pin ensures nobody can tamper with the config
after build.

### After first successful boot: disable allow_first_boot

Once the VTA has generated its secrets on first boot, set `allow_first_boot = false`
to prevent an attacker from deleting ciphertext files to trigger a new identity:

```bash
# Edit config
nano deploy/nitro/config.toml
# Change: allow_first_boot = false

# Rebuild with the SAME profile as Step 2 (example: default profile)
docker build -f Dockerfile.nitro -t vta-nitro .

# Sign the EIF
nitro-cli build-enclave --docker-uri vta-nitro --output-file vta.eif \
    --signing-certificate ./signing/signing-cert.pem \
    --private-key ./signing/signing-key.pem

# Update KMS policy with new PCR0
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "LATEST_PCR0" \
    --pcr8 "$(cat ./signing/pcr8.txt)" \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

## Step 5: Deploy and Run the Enclave

```bash
# If building on a separate machine, copy EIF to the EC2 instance
scp vta.eif ec2-user@<instance-ip>:~/

# SSH to instance and start the enclave
nitro-cli run-enclave \
    --eif-path ~/vta.eif \
    --cpu-count 2 \
    --memory 1024 \
    --enclave-cid 16

# Verify
nitro-cli describe-enclaves
```

## Step 6: Start the Parent Proxy

The parent proxy bridges all networking between the enclave and the outside
world. This includes DID resolution (`did:web`, `did:webvh`) — the enclave has
no direct network access, so all HTTPS traffic is routed through a vsock proxy
with an allowlist of permitted hosts.

```bash
# Basic: mediator only + default DID resolvers
./deploy/nitro/parent-proxy.sh mediator.example.com

# With WebVH server and custom DID resolution endpoints
./deploy/nitro/parent-proxy.sh mediator.example.com 16 \
    webvh-server.example.com:443 \
    did-resolver.example.com:443

# Or via environment variable
ALLOWLIST_HOSTS="webvh-server.example.com:443,custom-resolver.example.com:443" \
    ./deploy/nitro/parent-proxy.sh mediator.example.com
```

This starts three proxy channels:
1. **Inbound REST**: `TCP:8443 → vsock:5100 → Enclave VTA`
2. **Outbound DIDComm**: `Enclave → vsock:5200 → TLS → mediator`
3. **Outbound HTTPS**: `Enclave → vsock:5300 → allowlisted hosts`

The HTTPS proxy (`vsock-proxy`) allowlists these hosts by default:
- DIDComm mediator hostname
- `dev.uniresolver.io` (Universal Resolver)
- `resolver.identity.foundation` (DIF resolver)
- `kdsintf.amd.com` (AMD attestation)
- `kms.<region>.amazonaws.com` (AWS KMS)

Add your WebVH servers and any custom DID resolution endpoints as extra
arguments or via `ALLOWLIST_HOSTS`.

Inside the enclave, the entrypoint sets `HTTPS_PROXY=http://127.0.0.1:4444`
so all HTTP clients (`reqwest`, used by the DID resolver and WebVH client)
automatically route through the proxy. No code changes needed — `did:web`,
`did:webvh`, and any HTTPS-based DID method will resolve correctly as long
as the host is in the allowlist.

## Step 7: First Boot — Seed Generation

On first boot, the VTA:
1. Detects TEE mode (required) + KMS config
2. Finds no existing ciphertext files → **first boot**
3. Generates BIP-39 entropy inside the TEE using NSM hardware random
4. Derives seed from entropy
5. Encrypts seed + JWT key with KMS → stores ciphertext on external EBS
6. Derives AES-256 storage key from seed
7. Creates default context, VTA identity DID, admin ACL
8. Starts serving

**The mnemonic is never displayed.** To export it for backup:

```bash
# Terminate the enclave
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# Restart with a 5-minute export window
VTA_MNEMONIC_EXPORT_WINDOW=300 nitro-cli run-enclave \
    --eif-path vta.eif --cpu-count 2 --memory 1024 --enclave-cid 16

# Authenticate as super admin and export within 5 minutes:
TOKEN=$(curl -s -X POST http://localhost:8443/auth/challenge -H 'Content-Type: application/json' \
    -d '{"did":"did:key:z6Mk..."}' | jq -r '.data.challenge')
# ... complete auth flow to get JWT ...

# Check export window status
curl -s http://localhost:8443/attestation/mnemonic \
    -H "Authorization: Bearer $JWT" | jq

# Export (one-time, entropy zeroed after)
curl -s -X POST http://localhost:8443/attestation/mnemonic \
    -H "Authorization: Bearer $JWT" | jq '.mnemonic'
```

After 5 minutes (or one successful export), the entropy is permanently zeroed.
The VTA continues running — only the mnemonic words are gone.

## Step 8: Subsequent Boots

On subsequent boots, the VTA:
1. Finds existing ciphertext files on external storage
2. Generates ephemeral RSA keypair
3. Gets NSM attestation document (RSA public key embedded)
4. Calls KMS Decrypt with attestation → KMS verifies PCR0 + PCR8
5. Decrypts seed + JWT key inside TEE memory
6. Opens encrypted fjall store (same seed → same storage key)
7. Resumes normal operation

No mnemonic export is possible on subsequent boots (no entropy exists).

## Step 9: Verify

```bash
# Health check
curl http://localhost:8443/health
# → {"status":"ok","version":"0.1.2","tee_status":{"tee_type":"nitro","detected":true}}

# TEE attestation
curl http://localhost:8443/attestation/status

# Fresh attestation report
curl -X POST http://localhost:8443/attestation/report \
    -H 'Content-Type: application/json' \
    -d '{"nonce":"deadbeef0123456789abcdef01234567"}'
```

## Disaster Recovery

| Scenario | Recovery |
|----------|----------|
| Enclave restart | Automatic — KMS Decrypt retrieves seed from ciphertext |
| EBS volume lost | Use mnemonic backup with `vta tee recover --mnemonic "..."` |
| KMS key deleted | Use mnemonic to regenerate seed with a new KMS key |
| PCR0 mismatch after rebuild | Update KMS policy with `setup-kms-policy.sh --pcr0 <new>` |
| Signing key lost | Generate new key, rebuild + re-sign EIF, update PCR8 in KMS policy |

## IAM Role Configuration

### EC2 Instance Role (Minimal)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt"
            ],
            "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
        }
    ]
}
```

**This role intentionally does NOT include:**
- `kms:PutKeyPolicy` — cannot modify the KMS key policy
- `kms:CreateGrant` — cannot delegate access
- `kms:ScheduleKeyDeletion` — cannot destroy the key
- `iam:*` — cannot modify its own permissions

### Admin Role (Separate, MFA-Protected)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "kms:*",
            "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"}
            }
        }
    ]
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build VTA Enclave

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -f Dockerfile.nitro -t vta-nitro .

      - name: Write signing key
        run: |
          echo "${{ secrets.EIF_SIGNING_KEY }}" > /tmp/signing-key.pem
          echo "${{ secrets.EIF_SIGNING_CERT }}" > /tmp/signing-cert.pem

      - name: Build and sign EIF
        run: |
          nitro-cli build-enclave \
              --docker-uri vta-nitro \
              --output-file vta.eif \
              --signing-certificate /tmp/signing-cert.pem \
              --private-key /tmp/signing-key.pem | tee build-output.json

      - name: Extract PCR0 and update KMS policy
        env:
          AWS_REGION: us-east-1
          KMS_KEY_ARN: ${{ secrets.KMS_KEY_ARN }}
          EC2_ROLE_ARN: ${{ secrets.EC2_ROLE_ARN }}
        run: |
          PCR0=$(jq -r '.Measurements.PCR0' build-output.json)
          PCR8=$(cat signing/pcr8.txt)
          ./deploy/nitro/setup-kms-policy.sh \
              --pcr0 "$PCR0" --pcr8 "$PCR8" \
              --role "$EC2_ROLE_ARN" --key-arn "$KMS_KEY_ARN"

      - name: Upload EIF
        run: aws s3 cp vta.eif s3://my-bucket/vta/vta.eif

      - name: Cleanup signing key
        if: always()
        run: rm -f /tmp/signing-key.pem /tmp/signing-cert.pem
```

## Port Reference

| Vsock Port | Direction | Purpose |
|-----------|-----------|---------|
| 5100 | Parent → Enclave | Inbound REST API |
| 5200 | Enclave → Parent | Outbound DIDComm (mediator WebSocket) |
| 5300 | Enclave → Parent | Outbound HTTPS (DID resolution) |

## Files

| File | Where | Purpose |
|------|-------|---------|
| `Dockerfile.nitro` | Build host | Multi-stage build → Docker image |
| `generate-signing-key.sh` | Build host / CI | Generate EC P-384 signing key + certificate |
| `setup-kms-policy.sh` | Admin workstation | Create/update KMS key with PCR-pinned policy |
| `iam-kms-admin-policy.json` | Admin workstation | IAM policy for the user running setup-kms-policy.sh |
| `enclave-entrypoint.sh` | Enclave | Set up lo, vsock proxies, start VTA |
| `parent-proxy.sh` | Parent EC2 | Bridge vsock ↔ TCP/TLS for all channels |
| `config.toml` | Reference | Example config with KMS + DIDComm |
