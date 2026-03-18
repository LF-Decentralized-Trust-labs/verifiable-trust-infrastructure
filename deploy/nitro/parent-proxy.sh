#!/bin/bash
# =============================================================================
# VTA Nitro Enclave — Parent Instance Proxy
# =============================================================================
#
# This script runs on the PARENT EC2 instance (not inside the enclave).
# It manages all vsock↔TCP bridging for the enclave's networking:
#
#   1. INBOUND:  External clients → TCP:8443 → vsock → Enclave VTA REST API
#   2. MEDIATOR: Enclave VTA DIDComm → vsock → TCP → wss://mediator
#   3. HTTPS:    Enclave VTA HTTPS   → vsock → TCP → DID resolver / general internet
#
# The HTTPS proxy uses the `vsock-proxy` tool from aws-nitro-enclaves-cli,
# which acts as a connect-style proxy allowing the enclave to reach
# arbitrary HTTPS endpoints.
#
# Prerequisites:
#   sudo yum install -y socat aws-nitro-enclaves-cli
#   # OR
#   sudo apt install -y socat aws-nitro-enclaves-cli
#
# Usage:
#   ./parent-proxy.sh <mediator_host> [enclave_cid]
#
# Examples:
#   ./parent-proxy.sh mediator.example.com
#   ./parent-proxy.sh mediator.example.com 16
# =============================================================================

set -euo pipefail

MEDIATOR_HOST="${1:-}"
ENCLAVE_CID="${2:-}"

# ---------------------------------------------------------------------------
# Port assignments (must match enclave-entrypoint.sh)
# ---------------------------------------------------------------------------
VSOCK_INBOUND_PORT="${VSOCK_INBOUND_PORT:-5100}"     # Inbound REST
VSOCK_MEDIATOR_PORT="${VSOCK_MEDIATOR_PORT:-5200}"    # Outbound mediator
VSOCK_HTTPS_PORT="${VSOCK_HTTPS_PORT:-5300}"           # Outbound HTTPS

LISTEN_PORT="${LISTEN_PORT:-8443}"                     # External REST API port
MEDIATOR_PORT="${MEDIATOR_PORT:-443}"                  # Mediator WSS port

# ---------------------------------------------------------------------------
# Validate args
# ---------------------------------------------------------------------------
if [ -z "$MEDIATOR_HOST" ]; then
    echo "Usage: $0 <mediator_host> [enclave_cid]"
    echo ""
    echo "  mediator_host  Hostname of the DIDComm mediator (e.g., mediator.example.com)"
    echo "  enclave_cid    Enclave CID (auto-detected if omitted)"
    echo ""
    echo "Environment variables:"
    echo "  LISTEN_PORT          External REST port (default: 8443)"
    echo "  MEDIATOR_PORT        Mediator WSS port (default: 443)"
    echo "  VSOCK_INBOUND_PORT   Vsock port for inbound REST (default: 5100)"
    echo "  VSOCK_MEDIATOR_PORT  Vsock port for mediator proxy (default: 5200)"
    echo "  VSOCK_HTTPS_PORT     Vsock port for HTTPS proxy (default: 5300)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Auto-detect enclave CID
# ---------------------------------------------------------------------------
if [ -z "$ENCLAVE_CID" ]; then
    echo "Auto-detecting enclave CID..."
    ENCLAVE_CID=$(nitro-cli describe-enclaves | python3 -c "
import sys, json
enclaves = json.load(sys.stdin)
running = [e for e in enclaves if e.get('State') == 'RUNNING']
if not running:
    print('NONE', file=sys.stderr)
    sys.exit(1)
print(running[0]['EnclaveCID'])
" 2>/dev/null) || {
        echo "ERROR: No running enclave found. Start one first:"
        echo "  nitro-cli run-enclave --eif-path vta.eif --cpu-count 2 --memory 512"
        exit 1
    }
    echo "Detected enclave CID: $ENCLAVE_CID"
fi

echo ""
echo "========================================="
echo "  VTA Nitro Enclave — Parent Proxy"
echo "========================================="
echo ""
echo "  Enclave CID: ${ENCLAVE_CID}"
echo ""
echo "  [1] INBOUND  REST:    0.0.0.0:${LISTEN_PORT} → vsock:${VSOCK_INBOUND_PORT} → Enclave :8100"
echo "  [2] OUTBOUND MEDIATOR: vsock:${VSOCK_MEDIATOR_PORT} → ${MEDIATOR_HOST}:${MEDIATOR_PORT}"
echo "  [3] OUTBOUND HTTPS:    vsock:${VSOCK_HTTPS_PORT} → (allowlisted endpoints)"
echo ""
echo "  Test:"
echo "    curl http://localhost:${LISTEN_PORT}/health"
echo "    curl http://localhost:${LISTEN_PORT}/attestation/status"
echo "    curl -X POST http://localhost:${LISTEN_PORT}/attestation/report -H 'Content-Type: application/json' -d '{\"nonce\":\"deadbeef01234567\"}'"
echo ""

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
PIDS=()
cleanup() {
    echo ""
    echo "Shutting down proxies..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# [1] INBOUND: External TCP → vsock → Enclave REST API
# ---------------------------------------------------------------------------
echo "Starting inbound proxy: TCP:${LISTEN_PORT} → vsock CID ${ENCLAVE_CID}:${VSOCK_INBOUND_PORT}"
socat TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork \
    VSOCK-CONNECT:${ENCLAVE_CID}:${VSOCK_INBOUND_PORT} &
PIDS+=($!)

# ---------------------------------------------------------------------------
# [2] OUTBOUND: Enclave DIDComm → vsock → Mediator WebSocket
# ---------------------------------------------------------------------------
# The enclave's VTA connects to its local proxy (127.0.0.1:4443) which
# forwards through vsock to this port. We then forward to the actual mediator.
echo "Starting mediator proxy: vsock:${VSOCK_MEDIATOR_PORT} → ${MEDIATOR_HOST}:${MEDIATOR_PORT}"
socat VSOCK-LISTEN:${VSOCK_MEDIATOR_PORT},reuseaddr,fork \
    OPENSSL:${MEDIATOR_HOST}:${MEDIATOR_PORT},verify=1 &
PIDS+=($!)

# ---------------------------------------------------------------------------
# [3] OUTBOUND: Enclave HTTPS → vsock → Internet
# ---------------------------------------------------------------------------
# Uses vsock-proxy from aws-nitro-enclaves-cli for allowlisted HTTPS.
# vsock-proxy listens on a vsock port and acts as a TCP proxy to allowed hosts.
#
# If vsock-proxy is not available, fall back to a socat-based proxy that
# forwards to a specific DID resolver endpoint.
if command -v vsock-proxy &>/dev/null; then
    echo "Starting HTTPS proxy (vsock-proxy): vsock:${VSOCK_HTTPS_PORT} → allowlisted HTTPS endpoints"

    # vsock-proxy allowlist: hosts the enclave is permitted to reach.
    # Add additional hosts as needed (DID resolvers, WebVH servers, etc.)
    vsock-proxy ${VSOCK_HTTPS_PORT} "${MEDIATOR_HOST}" ${MEDIATOR_PORT} \
        --config <(cat <<EOF
allowlist:
- {address: "${MEDIATOR_HOST}", port: ${MEDIATOR_PORT}}
- {address: "dev.uniresolver.io", port: 443}
- {address: "resolver.identity.foundation", port: 443}
- {address: "kdsintf.amd.com", port: 443}
EOF
    ) &
    PIDS+=($!)
else
    echo "WARNING: vsock-proxy not found — using socat fallback for HTTPS"
    echo "         Install aws-nitro-enclaves-cli for proper allowlisted HTTPS proxy"
    echo "         Falling back to forwarding all traffic to ${MEDIATOR_HOST}:${MEDIATOR_PORT}"
    socat VSOCK-LISTEN:${VSOCK_HTTPS_PORT},reuseaddr,fork \
        OPENSSL:${MEDIATOR_HOST}:${MEDIATOR_PORT},verify=1 &
    PIDS+=($!)
fi

# ---------------------------------------------------------------------------
# Wait for all proxies
# ---------------------------------------------------------------------------
echo ""
echo "All proxies started. Press Ctrl+C to stop."
wait
