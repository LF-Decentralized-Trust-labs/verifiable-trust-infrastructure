#!/bin/bash
# =============================================================================
# Set Up KMS Key Policy for VTA Nitro Enclave
# =============================================================================
#
# Creates a KMS key (or updates an existing one) with an attestation-based
# policy that restricts decryption to enclaves matching specific PCR values.
#
# Prerequisites:
#   - AWS CLI configured with permissions for kms:CreateKey, kms:PutKeyPolicy
#   - PCR0 from: nitro-cli build-enclave (enclave image hash)
#   - PCR8 from: generate-signing-key.sh (signing certificate hash)
#   - IAM role ARN for the EC2 instance running the enclave
#
# Usage:
#   ./setup-kms-policy.sh --pcr0 <hash> --pcr8 <hash> --role <iam-role-arn> [options]
#
# Options:
#   --pcr0 <hash>           Enclave image hash (required)
#   --old-pcr0 <hash>       Previous PCR0 for rolling upgrades. When set, both the
#                           new and old PCR0 are allowed in the KMS policy. This lets
#                           a new enclave image decrypt secrets encrypted by the old
#                           image. Remove --old-pcr0 after verifying the upgrade.
#   --pcr8 <hash>           Signing certificate hash (optional but recommended)
#   --role <arn>            EC2 instance IAM role ARN (required)
#   --key-arn <arn>         Existing KMS key ARN (creates new key if omitted)
#   --region <region>       AWS region (default: us-east-1)
#   --build-admin <arn>     Grant KMS admin to this role/user (e.g., CI/CD build role).
#                           This principal can update the key policy (e.g., to rotate
#                           PCR0 after a rebuild) without the original creator's
#                           credentials. Does NOT grant encrypt/decrypt access.
#                           To remove later, re-run without --build-admin.
#
# Examples:
#   # Create new KMS key:
#   ./setup-kms-policy.sh \
#       --pcr0 "abc123..." \
#       --pcr8 "def456..." \
#       --role "arn:aws:iam::123456789012:role/vta-enclave-role"
#
#   # Grant build role admin access (for CI/CD PCR0 rotation):
#   ./setup-kms-policy.sh \
#       --pcr0 "abc123..." \
#       --pcr8 "def456..." \
#       --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
#       --build-admin "arn:aws:iam::123456789012:role/vta-build-role"
#
#   # Update existing KMS key (also removes build-admin if previously set):
#   ./setup-kms-policy.sh \
#       --pcr0 "abc123..." \
#       --pcr8 "def456..." \
#       --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
#       --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
# =============================================================================

set -euo pipefail

# Parse arguments
PCR0=""
OLD_PCR0=""
PCR8=""
ROLE_ARN=""
KEY_ARN=""
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
BUILD_ADMIN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --pcr0) PCR0="$2"; shift 2;;
        --old-pcr0) OLD_PCR0="$2"; shift 2;;
        --pcr8) PCR8="$2"; shift 2;;
        --role) ROLE_ARN="$2"; shift 2;;
        --key-arn) KEY_ARN="$2"; shift 2;;
        --region) REGION="$2"; shift 2;;
        --build-admin) BUILD_ADMIN="$2"; shift 2;;
        --help|-h)
            sed -n '2,/^# =====/p' "$0" | head -n -1 | sed 's/^# \?//'
            exit 0;;
        *) echo "Unknown argument: $1"; exit 1;;
    esac
done

# Validate required args
if [ -z "$PCR0" ] || [ -z "$ROLE_ARN" ]; then
    echo "Usage: $0 --pcr0 <hash> --role <iam-role-arn> [--old-pcr0 <hash>] [--pcr8 <hash>] [--key-arn <existing>] [--region <region>] [--build-admin <arn>]"
    exit 1
fi

# Get AWS account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text)

echo ""
echo "=== VTA KMS Key Policy Setup ==="
echo ""
echo "  Account:    $ACCOUNT_ID"
echo "  Region:     $REGION"
echo "  Role ARN:   $ROLE_ARN"
echo "  PCR0:       ${PCR0:0:32}..."
[ -n "$OLD_PCR0" ] && echo "  Old PCR0:   ${OLD_PCR0:0:32}... (rolling upgrade)"
[ -n "$PCR8" ] && echo "  PCR8:       ${PCR8:0:32}..."
[ -n "$BUILD_ADMIN" ] && echo "  Build admin: $BUILD_ADMIN"
echo ""

# Build the PCR0 value — single string or array for rolling upgrades
if [ -n "$OLD_PCR0" ]; then
    PCR0_VALUE="[\"$PCR0\", \"$OLD_PCR0\"]"
else
    PCR0_VALUE="\"$PCR0\""
fi

# Build the attestation condition block
if [ -n "$PCR8" ]; then
    ATTESTATION_CONDITIONS=$(cat <<COND
                    "kms:RecipientAttestation:PCR0": $PCR0_VALUE,
                    "kms:RecipientAttestation:PCR8": "$PCR8"
COND
)
else
    ATTESTATION_CONDITIONS=$(cat <<COND
                    "kms:RecipientAttestation:PCR0": $PCR0_VALUE
COND
)
fi

# Build the admin principal — either just the caller, or caller + build role
if [ -n "$BUILD_ADMIN" ]; then
    ADMIN_PRINCIPAL=$(cat <<PRINC
                "AWS": ["$CALLER_ARN", "$BUILD_ADMIN"]
PRINC
)
else
    ADMIN_PRINCIPAL=$(cat <<PRINC
                "AWS": "$CALLER_ARN"
PRINC
)
fi

# Build key policy
POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowKeyAdministration",
            "Effect": "Allow",
            "Principal": {
$ADMIN_PRINCIPAL
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowEnclaveAttestationOperations",
            "Effect": "Allow",
            "Principal": {
                "AWS": "$ROLE_ARN"
            },
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
$ATTESTATION_CONDITIONS
                }
            }
        }
    ]
}
EOF
)

if [ -z "$KEY_ARN" ]; then
    # Create new KMS key
    echo "Creating new KMS key..."
    KEY_ARN=$(aws kms create-key \
        --region "$REGION" \
        --description "VTA Nitro Enclave secrets (PCR0-pinned)" \
        --policy "$POLICY" \
        --query KeyMetadata.Arn \
        --output text)

    # Create alias for convenience
    KEY_ID=$(echo "$KEY_ARN" | awk -F/ '{print $NF}')
    aws kms create-alias \
        --region "$REGION" \
        --alias-name "alias/vta-enclave-secrets" \
        --target-key-id "$KEY_ID" 2>/dev/null || true

    echo "Created KMS key: $KEY_ARN"
    echo "Alias: alias/vta-enclave-secrets"
else
    # Update existing key policy
    echo "Updating KMS key policy..."
    KEY_ID=$(echo "$KEY_ARN" | awk -F/ '{print $NF}')
    aws kms put-key-policy \
        --region "$REGION" \
        --key-id "$KEY_ID" \
        --policy-name default \
        --policy "$POLICY"

    echo "Updated KMS key: $KEY_ARN"
fi

echo ""
echo "=== Policy Summary ==="
echo ""
echo "  Key ARN:        $KEY_ARN"
echo "  GenerateDataKey: $ROLE_ARN (only with attestation matching PCR0"
[ -n "$PCR8" ] && echo "                   + PCR8) — for first-boot seed storage"
[ -z "$PCR8" ] && echo "                   ) — for first-boot seed storage"
echo "  Decrypt:        $ROLE_ARN (only with attestation matching PCR0"
[ -n "$PCR8" ] && echo "                   + PCR8)"
[ -z "$PCR8" ] && echo "                   )"
echo "  Administration: $CALLER_ARN"
[ -n "$BUILD_ADMIN" ] && echo "                   $BUILD_ADMIN (build admin)"
echo ""
echo "Add this to your VTA config.toml:"
echo ""
echo "  [tee.kms]"
echo "  region = \"$REGION\""
echo "  key_arn = \"$KEY_ARN\""
echo ""
echo "IMPORTANT: After rebuilding the enclave image, update PCR0:"
echo "  $0 --pcr0 <new-hash> --role $ROLE_ARN --key-arn $KEY_ARN"
[ -n "$PCR8" ] && echo "  (PCR8 only changes if you regenerate the signing key)"
echo ""
echo "Rolling upgrades (new image decrypts old secrets):"
echo "  $0 --pcr0 <new-hash> --old-pcr0 <current-hash> --role $ROLE_ARN --key-arn $KEY_ARN"
echo "  After verifying the upgrade, re-run without --old-pcr0 to remove the old PCR0."
if [ -n "$BUILD_ADMIN" ]; then
    echo ""
    echo "To remove build admin access later:"
    echo "  $0 --pcr0 <hash> --role $ROLE_ARN --key-arn $KEY_ARN"
    echo "  (omit --build-admin to remove it from the policy)"
fi
echo ""
