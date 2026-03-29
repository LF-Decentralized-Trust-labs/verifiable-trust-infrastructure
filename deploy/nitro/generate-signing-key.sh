#!/bin/bash
# =============================================================================
# Generate EIF Signing Key for Nitro Enclave Images
# =============================================================================
#
# This script generates an EC P-384 private key and self-signed certificate
# used to sign Nitro Enclave Image Files (EIFs).
#
# The signing key should be stored OUTSIDE the EC2 instance — keep it in
# your CI/CD pipeline, a hardware security module, or a separate AWS account.
# Only the certificate (public key) needs to be available at build time.
#
# PCR8 in the attestation document is computed using the TPM PCR extend
# operation: PCR8 = SHA-384(zeros_48 || SHA-384(certificate_DER)).
# Include PCR8 in your KMS key policy to ensure only images signed by
# this key can decrypt secrets.
#
# Usage:
#   ./generate-signing-key.sh [output-dir]
#
# Output:
#   <output-dir>/signing-key.pem     — Private key (KEEP SECRET)
#   <output-dir>/signing-cert.pem    — Certificate (include in builds)
#   <output-dir>/pcr8.txt            — PCR8 hash for KMS key policy
# =============================================================================

set -euo pipefail

OUTPUT_DIR="${1:-./signing}"

mkdir -p "$OUTPUT_DIR"

KEY_PATH="$OUTPUT_DIR/signing-key.pem"
CERT_PATH="$OUTPUT_DIR/signing-cert.pem"
PCR8_PATH="$OUTPUT_DIR/pcr8.txt"

if [ -f "$KEY_PATH" ]; then
    echo "ERROR: $KEY_PATH already exists. Remove it first or specify a different directory."
    exit 1
fi

echo "Generating EIF signing key..."

# Generate EC P-384 private key
openssl ecparam -name secp384r1 -genkey -noout -out "$KEY_PATH"

# Generate self-signed certificate (10 year validity)
openssl req -new -x509 -key "$KEY_PATH" -sha384 \
    -days 3650 \
    -subj "/CN=VTA Enclave Signing Key/O=Verifiable Trust Infrastructure" \
    -out "$CERT_PATH"

# Compute PCR8 using nitro-cli (authoritative, matches build-enclave exactly).
# Falls back to manual computation if nitro-cli is not installed (e.g., on a
# developer laptop where you're only generating the key, not building the EIF).
if command -v nitro-cli &>/dev/null; then
    PCR8=$(nitro-cli pcr --signing-certificate "$CERT_PATH" | python3 -c "import sys,json; print(json.load(sys.stdin)['PCR8'])")
else
    echo "  NOTE: nitro-cli not found — computing PCR8 manually."
    echo "  Verify with: nitro-cli pcr --signing-certificate $CERT_PATH"
    # PCR8 = SHA-384(zeros_48 || SHA-384(certificate_DER))
    PCR8=$(python3 -c "
import hashlib, subprocess
der = subprocess.check_output(['openssl', 'x509', '-in', '$CERT_PATH', '-outform', 'DER'])
cert_hash = hashlib.sha384(der).digest()
pcr8 = hashlib.sha384(b'\x00' * 48 + cert_hash).hexdigest()
print(pcr8)
")
fi
echo "$PCR8" > "$PCR8_PATH"

echo ""
echo "=== EIF Signing Key Generated ==="
echo ""
echo "  Private key:   $KEY_PATH"
echo "  Certificate:   $CERT_PATH"
echo "  PCR8 hash:     $PCR8"
echo ""
echo "IMPORTANT:"
echo "  1. Store the private key SECURELY — never put it on the EC2 instance"
echo "     Keep it in your CI/CD pipeline or a hardware security module"
echo ""
echo "  2. Add PCR8 to your KMS key policy:"
echo "     \"kms:RecipientAttestation:PCR8\": \"$PCR8\""
echo ""
echo "  3. Sign enclave images with:"
echo "     nitro-cli build-enclave --docker-uri vta-nitro --output-file vta.eif \\"
echo "         --signing-certificate $CERT_PATH --private-key $KEY_PATH"
echo ""
