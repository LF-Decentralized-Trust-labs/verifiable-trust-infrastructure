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
sudo usermod -aG docker,ne $USER
# Log out and back in
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

## Step 2: Build and Sign the Enclave Image

```bash
# Build the Docker image
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

## Step 3: Set Up KMS Key Policy

This creates a KMS key that **only releases secrets to your exact enclave image,
signed by your certificate, running on your IAM role**.

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

The script outputs the KMS key ARN — add it to your VTA config:

```toml
[tee.kms]
region = "us-east-1"
key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

### After rebuilding the enclave image

PCR0 changes with every Docker image change. Update the KMS policy:

```bash
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "NEW_PCR0_HASH" \
    --pcr8 "789abc012..." \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

PCR8 only changes if you regenerate the signing key.

## Step 4: Deploy and Run the Enclave

```bash
# Copy EIF to EC2 instance
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

## Step 5: Start the Parent Proxy

```bash
./deploy/nitro/parent-proxy.sh mediator.example.com
```

This starts three proxy channels:
1. **Inbound REST**: `TCP:8443 → vsock:5100 → Enclave VTA`
2. **Outbound DIDComm**: `Enclave → vsock:5200 → TLS → mediator`
3. **Outbound HTTPS**: `Enclave → vsock:5300 → allowlisted hosts`

## Step 6: First Boot — Seed Generation

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

## Step 7: Subsequent Boots

On subsequent boots, the VTA:
1. Finds existing ciphertext files on external storage
2. Generates ephemeral RSA keypair
3. Gets NSM attestation document (RSA public key embedded)
4. Calls KMS Decrypt with attestation → KMS verifies PCR0 + PCR8
5. Decrypts seed + JWT key inside TEE memory
6. Opens encrypted fjall store (same seed → same storage key)
7. Resumes normal operation

No mnemonic export is possible on subsequent boots (no entropy exists).

## Step 8: Verify

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
| `enclave-entrypoint.sh` | Enclave | Set up lo, vsock proxies, start VTA |
| `parent-proxy.sh` | Parent EC2 | Bridge vsock ↔ TCP/TLS for all channels |
| `config.toml` | Reference | Example config with KMS + DIDComm |
