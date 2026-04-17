#!/bin/bash
# =============================================================================
# VTA Nitro Enclave — Single-Host Dev/Test Wrapper
# =============================================================================
#
# ▓▒░ DEV / TEST ONLY ░▒▓
#
# This script is a convenience wrapper for single-host development: it
# runs build-vta.sh and deploy-enclave.sh back-to-back on the same
# machine. This means the EIF signing key ends up on the same host that
# runs the enclave, which defeats one of the main security goals of TEE
# deployment.
#
# For production, run:
#
#   1. build-vta.sh in CI (with the signing key in a CI secret store), and
#      ship the resulting bundle (vta.eif + config.toml + manifest.json)
#      to the parent EC2 instance.
#   2. deploy-enclave.sh on the parent EC2 instance. It only needs
#      nitro-cli + cargo + the bundle — no docker, no signing key, no
#      admin AWS credentials.
#
# See deploy/nitro/README.md → "Build and deployment modes" for details.
#
# Usage:
#   ./deploy-vta.sh [--non-interactive]
#
# Forwards all env vars to the underlying scripts (see their headers).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=deploy-common.sh
source "$SCRIPT_DIR/deploy-common.sh"

# ---------------------------------------------------------------------------
# Dev/test warning banner
# ---------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}${BOLD}  ┌──────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${YELLOW}${BOLD}  │  DEV / TEST SINGLE-HOST WRAPPER                                 │${NC}"
echo -e "${YELLOW}${BOLD}  │                                                                  │${NC}"
echo -e "${YELLOW}${BOLD}  │  Runs build-vta.sh and deploy-enclave.sh on the same host.      │${NC}"
echo -e "${YELLOW}${BOLD}  │  The signing key ends up on the parent host, which is NOT       │${NC}"
echo -e "${YELLOW}${BOLD}  │  appropriate for production. For prod, split the scripts:       │${NC}"
echo -e "${YELLOW}${BOLD}  │    * build-vta.sh  → CI (holds the signing key)                 │${NC}"
echo -e "${YELLOW}${BOLD}  │    * deploy-enclave.sh → parent EC2 (consumes the bundle)       │${NC}"
echo -e "${YELLOW}${BOLD}  └──────────────────────────────────────────────────────────────────┘${NC}"
echo ""

# ---------------------------------------------------------------------------
# Delegate
# ---------------------------------------------------------------------------
info "Running build-vta.sh..."
bash "$SCRIPT_DIR/build-vta.sh" "$@"

info "Running deploy-enclave.sh..."
bash "$SCRIPT_DIR/deploy-enclave.sh" "$@"

ok "Dev/test single-host deployment complete."
