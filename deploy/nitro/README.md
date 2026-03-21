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
│  vsock proxies: inbound(:5100) mediator(:5200) HTTPS(:5300) IMDS(:5400) │
└────────────┬──────────────┬──────────────┬──────────────────────────┘
             │ vsock        │ vsock        │ vsock
┌────────────▼──────────────▼──────────────▼──────────────────────────┐
│  Parent EC2 Instance                                                │
│  parent-proxy.sh: REST ↔ vsock, mediator ↔ vsock, HTTPS ↔ vsock   │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

For an interactive end-to-end deployment, use the deployment script:

```bash
./deploy/nitro/deploy-vta.sh
```

This walks through all the steps below — prerequisite checks, build profile
selection, signing key generation, IAM and KMS setup, Docker/EIF builds,
enclave launch, and parent proxy startup.

For CI/CD, use non-interactive mode with environment variables:

```bash
VTA_PROFILE=hardened \
VTA_REGION=us-east-1 \
VTA_ROLE_NAME=vta-enclave-role \
VTA_MEDIATOR_DID="did:web:mediator.example.com" \
./deploy/nitro/deploy-vta.sh --non-interactive
```

The rest of this guide documents each step in detail.

## Prerequisites

### EC2 Instance

| Requirement | Details |
|------------|---------|
| Instance type | Nitro Enclave capable: `m5.xlarge`, `c5.xlarge`, `r5.xlarge` or larger |
| AMI | Amazon Linux 2023 or Ubuntu 22.04+ |
| Enclave support | Enabled at launch: `--enclave-options Enabled=true` |
| IMDS hop limit | Must be **2** (see below) |
| IAM role | Minimal: `kms:Decrypt`, `kms:Encrypt` only (see Step 3) |

### IMDS Hop Limit

The AWS SDK inside the enclave fetches IAM credentials from the Instance
Metadata Service (IMDS) via a vsock proxy on the parent. IMDSv2 counts
this proxy as an extra network hop. The default hop limit is 1, which
causes the token response to be dropped before reaching the enclave.

Set the hop limit to 2 on the EC2 instance:

```bash
aws ec2 modify-instance-metadata-options \
    --instance-id <your-instance-id> \
    --http-put-response-hop-limit 2
```

Or set it at launch time:

```bash
aws ec2 run-instances ... \
    --metadata-options "HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=2"
```

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
memory_mib: 512
cpu_count: 1
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

**You do NOT need to edit `[services]` in `config.toml` when switching profiles.**
The `FEATURES` build arg controls which services are compiled into the binary.
The `[services]` section in config is a runtime toggle that can only *disable*
a compiled-in service, never *enable* one that wasn't compiled. For example,
building with `FEATURES="didcomm,tee"` (Profile A) means REST code is not in
the binary at all — `services.rest = true` in config has no effect. You can
use `services.didcomm = false` to disable DIDComm at runtime without rebuilding.

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

#### Granting build role admin access

In CI/CD pipelines, the build role needs to update the KMS key policy to rotate
PCR0 after each rebuild. Use `--build-admin` to grant a second principal KMS
admin permissions (policy management only — no encrypt/decrypt access):

```bash
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "abc123def456..." \
    --pcr8 "789abc012..." \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --build-admin "arn:aws:iam::123456789012:role/vta-build-role" \
    --region us-east-1
```

The build role can then update PCR0 in subsequent runs without the original
creator's credentials:

```bash
# CI/CD pipeline runs as vta-build-role:
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "NEW_PCR0_HASH" \
    --pcr8 "$(cat ./signing/pcr8.txt)" \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --build-admin "arn:aws:iam::123456789012:role/vta-build-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

To remove build role admin access later, re-run the script without
`--build-admin` — the policy is fully replaced each time:

```bash
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "abc123def456..." \
    --pcr8 "789abc012..." \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

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

**First boot is auto-detected.** On first deployment, the ciphertext files
don't exist yet, so the VTA generates new secrets inside the TEE and encrypts
them to KMS. On subsequent boots it finds the ciphertexts and decrypts them.
No config changes or redeployment needed between first and subsequent boots.

## Step 5: Copy Artifacts to the EC2 Instance

If building on a separate machine, copy the EIF and finalized config:

```bash
scp vta.eif ec2-user@<instance-ip>:~/
scp deploy/nitro/config.toml ec2-user@<instance-ip>:~/config.toml
```

If building directly on the EC2 instance, the files are already in place.

## Step 6: Start the Parent Proxy (before the enclave)

> **Important:** The parent proxy must be running **before** the enclave
> starts. On boot, the enclave immediately tries to reach KMS and IMDS
> through vsock. If the parent proxy isn't listening, these connections
> fail and the VTA crashes.

The parent proxy bridges all networking between the enclave and the outside
world. This includes DID resolution (`did:web`, `did:webvh`) — the enclave has
no direct network access, so all HTTPS traffic is routed through a vsock proxy
with an allowlist of permitted hosts.

The proxy is a Rust binary that auto-reads the mediator DID and KMS region
from `config.toml` and auto-detects the enclave CID.

**Important:** The proxy needs the **finalized** `config.toml` — the same
version baked into the EIF (with the real KMS ARN, mediator DID, etc.).
A repo checkout on the EC2 instance may have stale values (e.g., `PLACEHOLDER`
for the KMS ARN). There are two ways to provide the config:

**Option A: Copy the finalized config from the build machine** (recommended)

```bash
# On the build/CI machine, after building the EIF:
scp deploy/nitro/config.toml ec2-user@<instance-ip>:~/config.toml

# On the EC2 instance, run the proxy with the copied config:
./deploy/nitro/enclave-proxy/target/release/enclave-proxy -c ~/config.toml
```

**Option B: Pass settings via environment variables** (no config file needed)

```bash
AWS_REGION=us-east-1 \
MEDIATOR_HOST=mediator.example.com \
    ./deploy/nitro/enclave-proxy/target/release/enclave-proxy
```

Build and run the proxy on the EC2 instance:

```bash
# Build the proxy (first time only — on the parent EC2 instance)
cd deploy/nitro/enclave-proxy
cargo build --release
cd ../../..

# Run with the finalized config
./deploy/nitro/enclave-proxy/target/release/enclave-proxy -c ~/config.toml

# With additional allowlisted hosts (WebVH servers, etc.)
./deploy/nitro/enclave-proxy/target/release/enclave-proxy -c ~/config.toml webvh-server.example.com:443

# Custom DID resolver URL (e.g., local Affinidi DID resolver)
RESOLVER_URL=http://localhost:8200 ./deploy/nitro/enclave-proxy/target/release/enclave-proxy -c ~/config.toml
```

The proxy starts three channels:

| Channel | Flow | Purpose |
|---------|------|---------|
| Inbound REST | `TCP:8443 → vsock:5100 → Enclave :8100` | External clients access VTA API |
| Outbound DIDComm | `Enclave → vsock:5200 → TLS → mediator` | VTA DIDComm messaging |
| Outbound HTTPS | `Enclave → vsock:5300 → allowlisted hosts` | DID resolution, KMS, WebVH |
| Outbound IMDS | `Enclave → vsock:5400 → 169.254.169.254:80` | AWS IAM credentials |

The HTTPS channel implements an **HTTP CONNECT proxy** with an allowlist.
Inside the enclave, `HTTPS_PROXY=http://127.0.0.1:4444` routes all HTTPS
traffic through it. DID resolution (`did:web`, `did:webvh`), KMS calls, and
WebVH server access all flow through this proxy.

The allowlist is built automatically from:
- KMS endpoint (`kms.<region>.amazonaws.com`)
- Mediator host (from config.toml)
- DID resolver host (from `--resolver-url`)
- Extra hosts (from CLI args or `ALLOWLIST_HOSTS` env var)

### DID Resolution

**Recommended for production:** Run an Affinidi DID resolver instance on the
parent EC2 instance. This avoids maintaining an allowlist of individual DID
hosting endpoints and provides caching:

```bash
# Run a local DID resolver on the parent (separate terminal)
docker run -d --name did-resolver -p 8200:8080 affinidi/did-resolver

# Point the proxy to the local resolver
RESOLVER_URL=http://localhost:8200 ./deploy/nitro/enclave-proxy/target/release/enclave-proxy
```

The VTA's `affinidi-did-resolver-cache-sdk` connects through the vsock
proxy to reach the resolver. Inside the enclave, `HTTPS_PROXY` is set
automatically by the entrypoint.

### DID Resolution Security

The DID resolver runs on the parent EC2 instance (outside the TEE). An
attacker with parent access could potentially return fake DID documents.
The actual risk depends on the DID method:

| DID Method | Safe through parent resolver? | Why |
|---|---|---|
| `did:key` | **Yes** | No resolution needed — public key is embedded in the DID |
| `did:webvh` | **Yes** | Cryptographic audit trail — the resolver validates the signed log chain. Faking a document requires forging the entire history signed by the original keys. |
| `did:web` | **No** | No signatures on the document — relies solely on HTTPS transport trust. An attacker controlling the resolver can return fake documents. |

**For production TEE deployments:** use `did:key` and `did:webvh` exclusively.
Avoid `did:web` for any security-critical identity (admin DIDs, ACL entries,
DIDComm peers). If you must resolve `did:web` DIDs, route them through the
HTTPS CONNECT proxy (which terminates TLS inside the enclave) rather than
through the parent-side resolver.

> **Fallback:** The shell script `parent-proxy.sh` is still available if you
> prefer not to build the Rust proxy. It requires `socat` and `vsock-proxy`.

## Step 7: Start the Enclave

With the parent proxy running, start the enclave. Use `--enclave-cid 16`
to match the proxy's default CID:

```bash
nitro-cli run-enclave \
    --eif-path ~/vta.eif \
    --cpu-count 1 \
    --memory 512 \
    --enclave-cid 16 \
    --debug-mode

# Verify it's running
nitro-cli describe-enclaves

# Watch the console output (debug mode required)
nitro-cli console \
    --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

> **Tip:** Use `--debug-mode --attach-console` to stream console output
> directly to your terminal. See the [Troubleshooting](#troubleshooting)
> section for more details.

## Step 8: First boot (auto-detected)

First boot is detected automatically — no config changes needed. The VTA
checks if ciphertext files exist on the external storage path:

- **Files missing** → first boot: generate new secrets
- **Files present** → subsequent boot: decrypt from KMS

On first boot, the VTA:
1. Detects TEE mode (required) + KMS config
2. Finds no existing ciphertext files → **first boot**
3. Generates BIP-39 entropy inside the TEE using NSM hardware random
4. Derives seed from entropy
5. Encrypts seed + JWT key with KMS → stores ciphertext on external EBS
6. Derives AES-256 storage key from seed
7. If `vta_did_template` is configured: auto-generates the VTA's did:webvh
   identity and writes `did.jsonl` to disk (see below)
8. Starts serving

### Automatic DID identity generation

To avoid a manual DID creation / config update / EIF rebuild cycle, set
`vta_did_template` in `config.toml` before baking the EIF:

```toml
[tee.kms]
vta_did_template = "did:webvh:{SCID}:example.com:vta"
did_log_path = "/mnt/vta-data/secrets/did.jsonl"
```

On first boot, the VTA:
1. Derives signing and key-agreement keys from the bootstrapped seed
2. Creates a did:webvh DID using the template (replacing `{SCID}` with the real value)
3. Persists the DID in the encrypted store (restored automatically on subsequent boots)
4. Writes the initial `did.jsonl` log entry to `did_log_path`

After the enclave starts, copy `did.jsonl` from the parent EC2 instance and
upload it to your WebVH server:

```bash
# On the parent EC2 instance:
cat /mnt/vta-data/secrets/did.jsonl

# Upload to your WebVH server at the matching path:
# e.g., https://example.com/vta/did.jsonl
curl -X POST https://webvh-server.example.com/api/publish \
    -H 'Content-Type: application/json' \
    -d @/mnt/vta-data/secrets/did.jsonl
```

**No EIF rebuild is needed.** The template is stable across boots — the actual
DID (with real SCID) is generated once on first boot and persisted in the
encrypted store. Subsequent boots restore it directly.

The template format follows the did:webvh spec. Examples:

| Template | Resulting URL |
|----------|--------------|
| `did:webvh:{SCID}:example.com:vta` | `https://example.com/vta` |
| `did:webvh:{SCID}:example.com:org:agents:vta-1` | `https://example.com/org/agents/vta-1` |
| `did:webvh:{SCID}:example.com%3A8080:vta` | `https://example.com:8080/vta` |

> **Note on ciphertext deletion:** If an attacker deletes the ciphertext files,
> the next boot will generate a new identity. This is a denial-of-service (the old
> identity and data are lost), not a privilege escalation — the attacker still
> can't authenticate to the new VTA without admin credentials. Back up the
> ciphertext files and monitor for unexpected identity changes.

**The mnemonic is never displayed.** To export it for backup:

```bash
# Terminate the enclave
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# Restart with a 5-minute export window
VTA_MNEMONIC_EXPORT_WINDOW=300 nitro-cli run-enclave \
    --eif-path vta.eif --cpu-count 1 --memory 512 --enclave-cid 16

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

## Step 9: Subsequent Boots

On subsequent boots, the VTA:
1. Finds existing ciphertext files on external storage
2. Generates ephemeral RSA keypair
3. Gets NSM attestation document (RSA public key embedded)
4. Calls KMS Decrypt with attestation → KMS verifies PCR0 + PCR8
5. Decrypts seed + JWT key inside TEE memory
6. Opens encrypted fjall store (same seed → same storage key)
7. Resumes normal operation

No mnemonic export is possible on subsequent boots (no entropy exists).

## Step 10: Verify

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

## Troubleshooting

### Viewing enclave console output

Nitro Enclaves have no SSH access and no network. The only way to see what's
happening inside is through the console, which requires **debug mode**.

```bash
# Start the enclave in debug mode with console attached to your terminal.
# You'll see kernel boot messages, entrypoint output, and any errors.
nitro-cli run-enclave \
    --eif-path vta.eif \
    --cpu-count 1 \
    --memory 512 \
    --debug-mode \
    --attach-console
```

If you prefer to run the enclave in the background and read the console
separately:

```bash
# Start in debug mode (background)
nitro-cli run-enclave \
    --eif-path vta.eif \
    --cpu-count 1 \
    --memory 512 \
    --debug-mode

# Read the console output (streams until Ctrl+C or enclave stops)
nitro-cli console \
    --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

> **Note:** `--debug-mode` must be specified at launch time. You cannot
> attach a console to an enclave that was started without it. Debug mode
> does not weaken security — it only enables the console output channel.

### Common startup errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Error loading shared library ...` | Missing runtime library in the Alpine image | Add the library to the `apk add` list in `Dockerfile.nitro` and rebuild |
| `Error relocating ... symbol not found` | glibc binary uses a function Alpine/musl doesn't provide | Check if the symbol needs a compat stub (see `libresolv_compat.so` in `Dockerfile.nitro`) |
| Enclave exits immediately (hang-up event) | Process inside crashed — use `--attach-console` to see why | Start with `--debug-mode --attach-console` and read the error output |
| `KMS Decrypt failed [ACCESS_DENIED]` | PCR0 mismatch — the EIF was rebuilt but KMS policy wasn't updated | Re-run `setup-kms-policy.sh` with the new PCR0 from the build output |
| `failed to load IMDS session token` | IMDS hop limit too low or HTTP_PROXY interfering | Set IMDS hop limit to 2: `aws ec2 modify-instance-metadata-options --instance-id <id> --http-put-response-hop-limit 2` |
| `KMS Decrypt failed [NETWORK]` | Can't reach KMS — parent proxy not running or allowlist wrong | Start the enclave-proxy on the parent and verify the KMS endpoint is allowlisted |
| `KMS Decrypt failed [KEY_NOT_FOUND]` | Wrong KMS key ARN in config.toml | Verify `[tee.kms] key_arn` matches the key created by `setup-kms-policy.sh` |
| `failed to open /dev/nsm` | Not running inside a Nitro Enclave | The VTA binary must run inside an enclave, not directly on the EC2 host |
| `TEE mode is 'required' but no TEE hardware detected` | TEE mode set to required but `/dev/nsm` not found | Ensure you're running inside a Nitro Enclave, or set `tee.mode = "optional"` for testing |
| Health endpoint returns but no `tee_status` | TEE subsystem didn't initialize | Check console logs for TEE init errors; verify the `tee` feature was included in the build |

### Checking enclave status

```bash
# List running enclaves
nitro-cli describe-enclaves

# Check if the VTA is responding (via the parent proxy)
curl http://localhost:8443/health

# Terminate a running enclave
nitro-cli terminate-enclave \
    --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

### Checking parent proxy logs

The enclave-proxy logs to stderr. If started in the foreground, logs appear
in your terminal. If started via `deploy-vta.sh`, logs are written to
`.deploy-nitro/proxy.log`:

```bash
# View proxy logs
tail -f .deploy-nitro/proxy.log

# Check if the proxy is running
cat .deploy-nitro/proxy.pid | xargs ps -p
```

### Rebuilding after changes

Any change to `config.toml`, the VTA source code, or the Dockerfile requires
the full rebuild cycle because PCR0 changes:

```bash
# 1. Rebuild Docker image
docker build -f Dockerfile.nitro --build-arg FEATURES="rest,didcomm,tee" -t vta-nitro .

# 2. Rebuild and sign EIF — note the new PCR0
nitro-cli build-enclave --docker-uri vta-nitro --output-file vta.eif \
    --signing-certificate signing-cert.pem --private-key signing-key.pem

# 3. Update KMS policy with new PCR0
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "NEW_PCR0" --pcr8 "$(cat signing/pcr8.txt)" \
    --role "arn:aws:iam::ACCOUNT:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"

# 4. Terminate old enclave and start new one
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli run-enclave --eif-path vta.eif --cpu-count 1 --memory 512 --debug-mode
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
| 5300 | Enclave → Parent | Outbound HTTPS (DID resolution, KMS) |
| 5400 | Enclave → Parent | Outbound IMDS (AWS IAM credentials) |

## Files

| File | Where | Purpose |
|------|-------|---------|
| `Dockerfile.nitro` | Build host | Multi-stage build → Docker image |
| `deploy-vta.sh` | Build host / EC2 | End-to-end interactive deployment script |
| `generate-signing-key.sh` | Build host / CI | Generate EC P-384 signing key + certificate |
| `setup-kms-policy.sh` | Admin workstation | Create/update KMS key with PCR-pinned policy |
| `iam-kms-admin-policy.json` | Admin workstation | IAM policy for the user running setup-kms-policy.sh |
| `enclave-entrypoint.sh` | Enclave | Set up lo, vsock proxies, start VTA |
| `enclave-proxy/` | Parent EC2 | Rust proxy binary — bridges vsock ↔ TCP/TLS, HTTPS CONNECT proxy |
| `parent-proxy.sh` | Parent EC2 | Shell script fallback (requires socat + vsock-proxy) |
| `config.toml` | Reference | Example config with KMS + DIDComm |
