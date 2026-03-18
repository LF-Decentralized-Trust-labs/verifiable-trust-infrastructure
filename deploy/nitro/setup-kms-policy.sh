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
#   ./setup-kms-policy.sh --pcr0 <hash> --pcr8 <hash> --role <iam-role-arn> [--key-arn <existing>] [--region <region>]
#
# Examples:
#   # Create new KMS key:
#   ./setup-kms-policy.sh \
#       --pcr0 "abc123..." \
#       --pcr8 "def456..." \
#       --role "arn:aws:iam::123456789012:role/vta-enclave-role"
#
#   # Update existing KMS key:
#   ./setup-kms-policy.sh \
#       --pcr0 "abc123..." \
#       --pcr8 "def456..." \
#       --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
#       --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
# =============================================================================

set -euo pipefail

# Parse arguments
PCR0=""
PCR8=""
ROLE_ARN=""
KEY_ARN=""
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --pcr0) PCR0="$2"; shift 2;;
        --pcr8) PCR8="$2"; shift 2;;
        --role) ROLE_ARN="$2"; shift 2;;
        --key-arn) KEY_ARN="$2"; shift 2;;
        --region) REGION="$2"; shift 2;;
        *) echo "Unknown argument: $1"; exit 1;;
    esac
done

# Validate required args
if [ -z "$PCR0" ] || [ -z "$ROLE_ARN" ]; then
    echo "Usage: $0 --pcr0 <hash> --role <iam-role-arn> [--pcr8 <hash>] [--key-arn <existing>] [--region <region>]"
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
[ -n "$PCR8" ] && echo "  PCR8:       ${PCR8:0:32}..."
echo ""

# Build the attestation condition block
ATTESTATION_CONDITIONS=$(cat <<COND
                    "kms:RecipientAttestation:PCR0": "$PCR0"
COND
)

if [ -n "$PCR8" ]; then
    ATTESTATION_CONDITIONS=$(cat <<COND
                    "kms:RecipientAttestation:PCR0": "$PCR0",
                    "kms:RecipientAttestation:PCR8": "$PCR8"
COND
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
                "AWS": "$CALLER_ARN"
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
            "Sid": "AllowEnclaveEncryptDecrypt",
            "Effect": "Allow",
            "Principal": {
                "AWS": "$ROLE_ARN"
            },
            "Action": [
                "kms:Encrypt"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowEnclaveAttestationDecrypt",
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
echo "  Encrypt:        $ROLE_ARN (unconditional — for first-boot seed storage)"
echo "  Decrypt:        $ROLE_ARN (only with attestation matching PCR0"
[ -n "$PCR8" ] && echo "                   + PCR8)"
[ -z "$PCR8" ] && echo "                   )"
echo "  Administration: $CALLER_ARN"
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
