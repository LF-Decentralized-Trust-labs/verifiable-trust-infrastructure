#!/bin/bash
# =============================================================================
# VTA Nitro Enclave — End-to-End Deployment Script
# =============================================================================
#
# Interactive script that walks through the complete deployment of a VTA
# inside an AWS Nitro Enclave. Covers:
#
#   1. Prerequisite checks
#   2. Build profile selection
#   3. EIF signing key generation (or reuse existing)
#   4. Configuration (KMS region, mediator, etc.)
#   5. Docker image build
#   6. IAM role creation
#   7. KMS key creation with attestation policy
#   8. Config update + rebuild with KMS ARN
#   9. Enclave launch
#  10. Parent proxy start
#
# Usage:
#   ./deploy-vta.sh                    # Interactive — prompts for all inputs
#   ./deploy-vta.sh --non-interactive  # Uses env vars (for CI/CD)
#
# Environment variables (for non-interactive mode):
#   VTA_PROFILE         Build profile: hardened, full, rest-only (default: full)
#   VTA_REGION          AWS region (default: us-east-1)
#   VTA_ROLE_NAME       IAM role name (default: vta-enclave-role)
#   VTA_SIGNING_DIR     Signing key directory (default: ./signing)
#   VTA_MEDIATOR_DID    DIDComm mediator DID (optional)
#   VTA_ENCLAVE_CPU     Enclave CPU count (default: 1)
#   VTA_ENCLAVE_MEM     Enclave memory MiB (default: 512)
#   VTA_KEY_ARN         Existing KMS key ARN (skip creation if set)
#   VTA_BUILD_ADMIN     ARN of build role to grant KMS admin (optional)
#   VTA_SKIP_IAM        Set to "true" to skip IAM role creation
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors and helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "\n${BOLD}=== Step $1: $2 ===${NC}\n"; }

ask() {
    local prompt="$1" default="$2" var="$3"
    if [ "$INTERACTIVE" = true ]; then
        read -r -p "$(echo -e "${BOLD}${prompt}${NC} [${default}]: ")" input
        eval "$var=\"${input:-$default}\""
    else
        eval "$var=\"$default\""
    fi
}

ask_yn() {
    local prompt="$1" default="$2"
    if [ "$INTERACTIVE" = true ]; then
        read -r -p "$(echo -e "${BOLD}${prompt}${NC} [${default}]: ")" input
        input="${input:-$default}"
    else
        input="$default"
    fi
    [[ "$input" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
INTERACTIVE=true
for arg in "$@"; do
    case "$arg" in
        --non-interactive) INTERACTIVE=false ;;
        --help|-h)
            echo "Usage: $0 [--non-interactive]"
            echo ""
            echo "Interactive mode (default): prompts for all inputs."
            echo "Non-interactive mode: reads from environment variables."
            echo ""
            echo "See script header for environment variable reference."
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_TEMPLATE="$SCRIPT_DIR/config.toml"

# Working directory for this deployment
DEPLOY_DIR="${VTA_DEPLOY_DIR:-$REPO_ROOT/.deploy-nitro}"

# =============================================================================
# Step 0: Prerequisites
# =============================================================================
step 0 "Checking prerequisites"

MISSING=()

check_cmd() {
    if command -v "$1" &>/dev/null; then
        ok "$1 found: $(command -v "$1")"
    else
        err "$1 not found"
        MISSING+=("$1")
    fi
}

check_cmd docker
check_cmd aws
check_cmd openssl
check_cmd jq

# nitro-cli is only needed on the EC2 instance, not on a build machine
if command -v nitro-cli &>/dev/null; then
    ok "nitro-cli found"
    HAS_NITRO_CLI=true
else
    warn "nitro-cli not found — EIF build and enclave launch will be skipped"
    warn "This is expected if you're building on a developer machine"
    HAS_NITRO_CLI=false
fi

if [ ${#MISSING[@]} -gt 0 ]; then
    err "Missing required tools: ${MISSING[*]}"
    err "Install them and re-run this script."
    exit 1
fi

# Check AWS credentials
if aws sts get-caller-identity &>/dev/null; then
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text)
    ok "AWS credentials valid — account $ACCOUNT_ID"
    ok "Caller: $CALLER_ARN"
else
    err "AWS credentials not configured. Run 'aws configure' or set AWS_* env vars."
    exit 1
fi

# Check Docker is running
if docker info &>/dev/null; then
    ok "Docker daemon is running"
else
    err "Docker daemon is not running. Start it and re-run."
    exit 1
fi

# =============================================================================
# Step 1: Build Profile
# =============================================================================
step 1 "Build profile selection"

echo "Available profiles:"
echo ""
echo "  A) Hardened (DIDComm only) — smallest attack surface"
echo "     REST limited to health, attestation, auth. All key/ACL ops via DIDComm."
echo "     Features: didcomm,vsock-store"
echo ""
echo "  B) Full API (REST + DIDComm) — all operations on both transports"
echo "     For network-controlled environments (VPN, load balancer)."
echo "     Features: rest,didcomm,vsock-store"
echo ""
echo "  C) REST only — no DIDComm mediator needed"
echo "     Features: rest,vsock-store"
echo ""

DEFAULT_PROFILE="${VTA_PROFILE:-full}"

if [ "$INTERACTIVE" = true ]; then
    read -r -p "$(echo -e "${BOLD}Select profile (A/B/C)${NC} [B]: ")" PROFILE_CHOICE
    PROFILE_CHOICE="${PROFILE_CHOICE:-B}"
else
    case "$DEFAULT_PROFILE" in
        hardened) PROFILE_CHOICE="A" ;;
        rest-only) PROFILE_CHOICE="C" ;;
        *) PROFILE_CHOICE="B" ;;
    esac
fi

case "${PROFILE_CHOICE^^}" in
    A)
        FEATURES="didcomm,vsock-store"
        PROFILE_NAME="Hardened (DIDComm only)"
        NEEDS_MEDIATOR=true
        ;;
    C)
        FEATURES="rest,vsock-store"
        PROFILE_NAME="REST only"
        NEEDS_MEDIATOR=false
        ;;
    *)
        FEATURES="rest,didcomm,vsock-store"
        PROFILE_NAME="Full API (REST + DIDComm)"
        NEEDS_MEDIATOR=true
        ;;
esac

ok "Profile: $PROFILE_NAME"
ok "Features: $FEATURES"

# =============================================================================
# Step 2: Configuration inputs
# =============================================================================
step 2 "Configuration"

ask "AWS region" "${VTA_REGION:-us-east-1}" REGION
ask "IAM role name for EC2 instance" "${VTA_ROLE_NAME:-vta-enclave-role}" ROLE_NAME
ask "Enclave CPU count" "${VTA_ENCLAVE_CPU:-1}" ENCLAVE_CPU
ask "Enclave memory (MiB)" "${VTA_ENCLAVE_MEM:-512}" ENCLAVE_MEM

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

# Mediator configuration
MEDIATOR_DID="${VTA_MEDIATOR_DID:-}"
MEDIATOR_URL=""

if [ "$NEEDS_MEDIATOR" = true ]; then
    echo ""
    info "This profile uses DIDComm — a mediator is required."
    ask "DIDComm mediator DID (e.g., did:web:mediator.example.com)" "${MEDIATOR_DID}" MEDIATOR_DID
    if [ -n "$MEDIATOR_DID" ]; then
        # Inside the enclave, the mediator URL is always the local vsock proxy
        MEDIATOR_URL="ws://127.0.0.1:4443"
        ok "Mediator DID: $MEDIATOR_DID"
        ok "Mediator URL (inside enclave): $MEDIATOR_URL"
    else
        warn "No mediator DID provided — DIDComm will be disabled at runtime"
    fi
fi

# Build admin role (for CI/CD KMS policy management)
BUILD_ADMIN="${VTA_BUILD_ADMIN:-}"
if [ "$INTERACTIVE" = true ]; then
    echo ""
    info "Optional: grant a build role KMS admin access for CI/CD PCR0 rotation."
    info "This allows the build role to update the KMS key policy after rebuilds."
    info "Leave blank to skip (only the current caller will have admin access)."
    ask "Build admin role ARN (optional)" "$BUILD_ADMIN" BUILD_ADMIN
fi
[ -n "$BUILD_ADMIN" ] && ok "Build admin: $BUILD_ADMIN"

# Signing key
ask "Signing key directory" "${VTA_SIGNING_DIR:-./signing}" SIGNING_DIR

# =============================================================================
# Step 3: EIF Signing Key
# =============================================================================
step 3 "EIF signing key"

if [ -f "$SIGNING_DIR/signing-key.pem" ] && [ -f "$SIGNING_DIR/signing-cert.pem" ]; then
    ok "Existing signing key found in $SIGNING_DIR"
    if [ -f "$SIGNING_DIR/pcr8.txt" ]; then
        PCR8=$(cat "$SIGNING_DIR/pcr8.txt")
        ok "PCR8: ${PCR8:0:32}..."
    else
        warn "pcr8.txt not found — will recompute"
        # Recompute PCR8
        if command -v nitro-cli &>/dev/null; then
            PCR8=$(nitro-cli pcr --signing-certificate "$SIGNING_DIR/signing-cert.pem" \
                | python3 -c "import sys,json; print(json.load(sys.stdin)['PCR8'])")
        else
            PCR8=$(python3 -c "
import hashlib, subprocess
der = subprocess.check_output(['openssl', 'x509', '-in', '$SIGNING_DIR/signing-cert.pem', '-outform', 'DER'])
cert_hash = hashlib.sha384(der).digest()
pcr8 = hashlib.sha384(b'\x00' * 48 + cert_hash).hexdigest()
print(pcr8)
")
        fi
        echo "$PCR8" > "$SIGNING_DIR/pcr8.txt"
        ok "PCR8 computed: ${PCR8:0:32}..."
    fi
else
    info "Generating new EIF signing key..."
    bash "$SCRIPT_DIR/generate-signing-key.sh" "$SIGNING_DIR"
    PCR8=$(cat "$SIGNING_DIR/pcr8.txt")
    ok "Signing key generated"
fi

# =============================================================================
# Step 4: IAM Role
# =============================================================================
step 4 "IAM role setup"

SKIP_IAM="${VTA_SKIP_IAM:-false}"

if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
    ok "IAM role '$ROLE_NAME' already exists"
    ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)
    ok "Role ARN: $ROLE_ARN"
elif [ "$SKIP_IAM" = "true" ]; then
    warn "Skipping IAM role creation (VTA_SKIP_IAM=true)"
else
    if ask_yn "Create IAM role '$ROLE_NAME'?" "Y"; then
        info "Creating IAM role..."
        ROLE_ARN=$(aws iam create-role \
            --role-name "$ROLE_NAME" \
            --assume-role-policy-document '{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }' \
            --query 'Role.Arn' --output text)
        ok "Created role: $ROLE_ARN"

        # Create instance profile
        PROFILE_NAME_IAM="${ROLE_NAME}-profile"
        if ! aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME_IAM" &>/dev/null; then
            aws iam create-instance-profile --instance-profile-name "$PROFILE_NAME_IAM" >/dev/null
            aws iam add-role-to-instance-profile \
                --instance-profile-name "$PROFILE_NAME_IAM" \
                --role-name "$ROLE_NAME" >/dev/null
            ok "Created instance profile: $PROFILE_NAME_IAM"
        else
            ok "Instance profile '$PROFILE_NAME_IAM' already exists"
        fi
    else
        warn "Skipping IAM role creation — you must create it manually"
    fi
fi

# =============================================================================
# Step 5: Generate config.toml
# =============================================================================
step 5 "Generate config.toml"

mkdir -p "$DEPLOY_DIR"
CONFIG_PATH="$DEPLOY_DIR/config.toml"

info "Writing config to $CONFIG_PATH"

cat > "$CONFIG_PATH" <<TOML
# =============================================================================
# VTA Configuration — AWS Nitro Enclave
# =============================================================================
# Generated by deploy-vta.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Profile: $PROFILE_NAME (features: $FEATURES)
# =============================================================================

# Service toggles — runtime overrides for compiled-in features.
# These can only DISABLE a service that was compiled in, never enable one
# that wasn't. See the deployment guide for details.
[services]
rest = true
didcomm = true

[server]
host = "127.0.0.1"
port = 8100

[log]
level = "info"
format = "json"

[store]
data_dir = "/var/lib/vta/data"

[tee]
mode = "required"
embed_in_did = true
attestation_cache_ttl = 300
storage_key_salt = "vta-tee-storage-v1"

# KMS bootstrap — placeholder ARN, will be updated after KMS key creation
[tee.kms]
region = "$REGION"
key_arn = "PLACEHOLDER"
seed_ciphertext_path = "/mnt/vta-data/secrets/seed.enc"
jwt_ciphertext_path = "/mnt/vta-data/secrets/jwt.enc"

[auth]
access_token_expiry = 900
refresh_token_expiry = 86400
challenge_ttl = 300
session_cleanup_interval = 600

[secrets]
# Seed is provided by KMS bootstrap — do NOT set it here
TOML

# Add messaging section if mediator is configured
if [ -n "$MEDIATOR_DID" ]; then
    cat >> "$CONFIG_PATH" <<TOML

[messaging]
mediator_url = "$MEDIATOR_URL"
mediator_did = "$MEDIATOR_DID"
TOML
fi

ok "Config written"

# =============================================================================
# Step 6: Initial Docker build (to get PCR0 for KMS policy)
# =============================================================================
step 6 "Build Docker image"

info "Building Docker image with features: $FEATURES"
info "This may take several minutes on first build..."

# Copy config into place for the Docker build
cp "$CONFIG_PATH" "$SCRIPT_DIR/config.toml"

docker build -f "$REPO_ROOT/Dockerfile.nitro" \
    --build-arg FEATURES="$FEATURES" \
    -t vta-nitro \
    "$REPO_ROOT"

ok "Docker image built: vta-nitro"

# =============================================================================
# Step 7: Build and sign EIF (if nitro-cli available)
# =============================================================================
if [ "$HAS_NITRO_CLI" = true ]; then
    step 7 "Build and sign Enclave Image File"

    EIF_PATH="$DEPLOY_DIR/vta.eif"

    info "Building and signing EIF..."
    BUILD_OUTPUT=$(nitro-cli build-enclave \
        --docker-uri vta-nitro \
        --output-file "$EIF_PATH" \
        --signing-certificate "$SIGNING_DIR/signing-cert.pem" \
        --private-key "$SIGNING_DIR/signing-key.pem")

    echo "$BUILD_OUTPUT" | jq .

    PCR0=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR0')
    BUILD_PCR8=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR8')

    ok "EIF built: $EIF_PATH"
    ok "PCR0: ${PCR0:0:32}..."

    # Verify PCR8 matches
    if [ "$BUILD_PCR8" = "$PCR8" ]; then
        ok "PCR8 matches signing key"
    else
        warn "PCR8 mismatch! Build=$BUILD_PCR8, Expected=$PCR8"
        warn "This may indicate a signing key issue"
    fi

    echo "$PCR0" > "$DEPLOY_DIR/pcr0.txt"
else
    step 7 "EIF build (skipped — nitro-cli not available)"

    warn "Cannot build EIF without nitro-cli."
    warn "Transfer the Docker image and config to the EC2 instance and build there:"
    echo ""
    echo "  docker save vta-nitro | ssh ec2-user@<instance> docker load"
    echo "  scp $CONFIG_PATH ec2-user@<instance>:~/deploy/nitro/config.toml"
    echo "  ssh ec2-user@<instance>"
    echo "  nitro-cli build-enclave --docker-uri vta-nitro --output-file vta.eif \\"
    echo "      --signing-certificate signing-cert.pem --private-key signing-key.pem"
    echo ""

    if [ "$INTERACTIVE" = true ]; then
        echo -e "${BOLD}If you have PCR0 from a previous build, enter it now.${NC}"
        echo "Otherwise, leave blank and re-run this script on the EC2 instance."
        read -r -p "PCR0 (leave blank to skip KMS setup): " PCR0
    else
        PCR0=""
    fi
fi

# =============================================================================
# Step 8: KMS key with attestation policy
# =============================================================================
step 8 "KMS key setup"

KEY_ARN="${VTA_KEY_ARN:-}"

# Build the --build-admin flag if set
BUILD_ADMIN_FLAG=()
if [ -n "$BUILD_ADMIN" ]; then
    BUILD_ADMIN_FLAG=(--build-admin "$BUILD_ADMIN")
fi

if [ -z "$PCR0" ]; then
    warn "Skipping KMS key setup — no PCR0 available"
    warn "After building the EIF on the EC2 instance, run:"
    echo ""
    echo "  ./deploy/nitro/setup-kms-policy.sh \\"
    echo "      --pcr0 <PCR0_FROM_BUILD> \\"
    echo "      --pcr8 $(cat "$SIGNING_DIR/pcr8.txt") \\"
    echo "      --role $ROLE_ARN \\"
    echo "      --region $REGION"
    echo ""
elif [ -n "$KEY_ARN" ]; then
    info "Updating existing KMS key: $KEY_ARN"
    bash "$SCRIPT_DIR/setup-kms-policy.sh" \
        --pcr0 "$PCR0" \
        --pcr8 "$PCR8" \
        --role "$ROLE_ARN" \
        --key-arn "$KEY_ARN" \
        --region "$REGION" \
        "${BUILD_ADMIN_FLAG[@]}"
    ok "KMS key policy updated"
else
    info "Creating new KMS key with attestation policy..."
    KMS_OUTPUT=$(bash "$SCRIPT_DIR/setup-kms-policy.sh" \
        --pcr0 "$PCR0" \
        --pcr8 "$PCR8" \
        --role "$ROLE_ARN" \
        --region "$REGION" \
        "${BUILD_ADMIN_FLAG[@]}" 2>&1)
    echo "$KMS_OUTPUT"

    # Extract key ARN from the output
    KEY_ARN=$(echo "$KMS_OUTPUT" | grep "Key ARN:" | awk '{print $NF}')
    if [ -z "$KEY_ARN" ]; then
        # Fallback: try to get from alias
        KEY_ARN=$(aws kms describe-key --key-id "alias/vta-enclave-secrets" \
            --region "$REGION" --query 'KeyMetadata.Arn' --output text 2>/dev/null || true)
    fi

    if [ -n "$KEY_ARN" ]; then
        ok "KMS key created: $KEY_ARN"
    else
        err "Failed to extract KMS key ARN from output"
        exit 1
    fi
fi

# =============================================================================
# Step 9: Update config with KMS ARN and rebuild
# =============================================================================
if [ -n "$KEY_ARN" ] && [ -n "$PCR0" ]; then
    step 9 "Rebuild with final config"

    # Update the config with the real KMS key ARN
    sed -i.bak "s|key_arn = \"PLACEHOLDER\"|key_arn = \"$KEY_ARN\"|" "$CONFIG_PATH"
    rm -f "$CONFIG_PATH.bak"
    ok "Config updated with KMS key ARN"

    # Copy updated config for Docker build
    cp "$CONFIG_PATH" "$SCRIPT_DIR/config.toml"

    info "Rebuilding Docker image with final config..."
    docker build -f "$REPO_ROOT/Dockerfile.nitro" \
        --build-arg FEATURES="$FEATURES" \
        -t vta-nitro \
        "$REPO_ROOT"
    ok "Docker image rebuilt"

    if [ "$HAS_NITRO_CLI" = true ]; then
        info "Rebuilding EIF..."
        BUILD_OUTPUT=$(nitro-cli build-enclave \
            --docker-uri vta-nitro \
            --output-file "$EIF_PATH" \
            --signing-certificate "$SIGNING_DIR/signing-cert.pem" \
            --private-key "$SIGNING_DIR/signing-key.pem")

        NEW_PCR0=$(echo "$BUILD_OUTPUT" | jq -r '.Measurements.PCR0')
        ok "EIF rebuilt"

        if [ "$NEW_PCR0" != "$PCR0" ]; then
            info "PCR0 changed (config was baked in) — updating KMS policy..."
            PCR0="$NEW_PCR0"
            echo "$PCR0" > "$DEPLOY_DIR/pcr0.txt"

            bash "$SCRIPT_DIR/setup-kms-policy.sh" \
                --pcr0 "$PCR0" \
                --pcr8 "$PCR8" \
                --role "$ROLE_ARN" \
                --key-arn "$KEY_ARN" \
                --region "$REGION" \
                "${BUILD_ADMIN_FLAG[@]}"
            ok "KMS policy updated with new PCR0: ${PCR0:0:32}..."
        fi
    fi
else
    step 9 "Rebuild (skipped — waiting for KMS key ARN or PCR0)"
fi

# =============================================================================
# Step 10: Launch enclave
# =============================================================================
if [ "$HAS_NITRO_CLI" = true ] && [ -f "$DEPLOY_DIR/vta.eif" ]; then
    step 10 "Launch enclave"

    # Terminate any existing enclave
    EXISTING=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
    if [ -n "$EXISTING" ]; then
        if ask_yn "An enclave is already running ($EXISTING). Terminate it?" "Y"; then
            nitro-cli terminate-enclave --enclave-id "$EXISTING" >/dev/null
            ok "Terminated existing enclave"
            sleep 2
        else
            warn "Skipping enclave launch — existing enclave still running"
            SKIP_LAUNCH=true
        fi
    fi

    if [ "${SKIP_LAUNCH:-false}" != true ]; then
        info "Launching enclave (CPU=$ENCLAVE_CPU, MEM=${ENCLAVE_MEM}MiB)..."
        nitro-cli run-enclave \
            --eif-path "$DEPLOY_DIR/vta.eif" \
            --cpu-count "$ENCLAVE_CPU" \
            --memory "$ENCLAVE_MEM" \
            --enclave-cid 16

        ok "Enclave launched"
        echo ""
        nitro-cli describe-enclaves | jq '.[0] | {EnclaveID, State, EnclaveCID}'
    fi
else
    step 10 "Launch enclave (skipped)"
    if [ "$HAS_NITRO_CLI" != true ]; then
        info "Transfer EIF to EC2 instance and run:"
    fi
    echo ""
    echo "  nitro-cli run-enclave \\"
    echo "      --eif-path vta.eif \\"
    echo "      --cpu-count $ENCLAVE_CPU \\"
    echo "      --memory $ENCLAVE_MEM \\"
    echo "      --enclave-cid 16"
    echo ""
fi

# =============================================================================
# Step 11: Parent proxy
# =============================================================================
step 11 "Parent proxy"

if [ "$HAS_NITRO_CLI" = true ]; then
    # Check if enclave-proxy binary exists
    PROXY_BIN="$SCRIPT_DIR/enclave-proxy/target/release/enclave-proxy"
    if [ -f "$PROXY_BIN" ]; then
        ok "Enclave proxy binary found: $PROXY_BIN"
    else
        info "Building enclave proxy..."
        if command -v cargo &>/dev/null; then
            (cd "$SCRIPT_DIR/enclave-proxy" && cargo build --release)
            ok "Enclave proxy built"
        else
            warn "Rust not installed — cannot build enclave proxy"
            warn "Install Rust with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        fi
    fi

    if [ -f "$PROXY_BIN" ]; then
        if ask_yn "Start the parent proxy now?" "Y"; then
            info "Starting enclave proxy in background..."
            nohup "$PROXY_BIN" > "$DEPLOY_DIR/proxy.log" 2>&1 &
            PROXY_PID=$!
            echo "$PROXY_PID" > "$DEPLOY_DIR/proxy.pid"
            ok "Parent proxy started (PID $PROXY_PID, log: $DEPLOY_DIR/proxy.log)"
        fi
    fi
else
    info "On the EC2 instance, start the parent proxy:"
    echo ""
    echo "  # Build (first time only)"
    echo "  cd deploy/nitro/enclave-proxy && cargo build --release && cd ../../.."
    echo ""
    echo "  # Run"
    echo "  ./deploy/nitro/enclave-proxy/target/release/enclave-proxy"
    echo ""
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}==============================================================================${NC}"
echo -e "${BOLD}  VTA Nitro Enclave Deployment Summary${NC}"
echo -e "${BOLD}==============================================================================${NC}"
echo ""
echo -e "  Profile:          ${GREEN}$PROFILE_NAME${NC}"
echo    "  Features:         $FEATURES"
echo    "  Region:           $REGION"
echo    "  IAM Role:         $ROLE_ARN"
echo    "  Signing Key:      $SIGNING_DIR/"
echo    "  PCR8:             ${PCR8:0:32}..."
[ -n "${PCR0:-}" ] && \
echo    "  PCR0:             ${PCR0:0:32}..."
[ -n "${KEY_ARN:-}" ] && \
echo    "  KMS Key:          $KEY_ARN"
echo    "  Config:           $CONFIG_PATH"
[ -f "${EIF_PATH:-/nonexistent}" ] && \
echo    "  EIF:              $EIF_PATH"
echo    "  Enclave:          CPU=$ENCLAVE_CPU, MEM=${ENCLAVE_MEM}MiB"
echo ""

if [ -n "${KEY_ARN:-}" ] && [ -n "${PCR0:-}" ]; then
    echo -e "  ${GREEN}Deployment complete.${NC}"
    echo ""
    echo "  Verify:"
    echo "    curl http://localhost:8443/health"
    echo "    curl http://localhost:8443/attestation/status"
else
    echo -e "  ${YELLOW}Partial deployment — complete these remaining steps:${NC}"
    echo ""
    [ -z "${PCR0:-}" ] && \
    echo "  1. Build the EIF on the EC2 instance to get PCR0"
    [ -z "${KEY_ARN:-}" ] && \
    echo "  2. Run setup-kms-policy.sh with PCR0 to create the KMS key"
    echo "  3. Update config.toml with the KMS key ARN"
    echo "  4. Rebuild the Docker image and EIF"
    echo "  5. Update KMS policy with the new PCR0"
    echo "  6. Launch the enclave and start the parent proxy"
fi

echo ""
echo "  Artifacts saved to: $DEPLOY_DIR/"
echo ""
