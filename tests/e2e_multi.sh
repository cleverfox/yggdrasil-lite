#!/usr/bin/env bash
#
# Multi-peer end-to-end test for yggdrasil-lite.
#
# Topology (yggstack1 and yggstack2 are NOT peered with each other):
#
#   curl (SOCKS5:1) ── yggstack1 <──TLS── lite_node ──TLS──> yggstack2 ── curl (SOCKS5:2)
#
# The lite_node connects to BOTH yggstack1 and yggstack2 simultaneously.
# Since the two yggstacks have no direct link, traffic from yggstack2 can
# only reach the lite_node through the lite_node's own peer connection —
# proving that multi-peer actually works.
#
# Required:
#   YGGSTACK_BIN  — path to the yggstack binary
#
# Usage:
#   YGGSTACK_BIN=/path/to/yggstack bash tests/e2e_multi.sh
#
set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────
: "${YGGSTACK_BIN:?Set YGGSTACK_BIN to the yggstack binary path}"
SOCKS_PORT1=$((RANDOM % 10000 + 20000))
SOCKS_PORT2=$((RANDOM % 10000 + 30000))
TEST_TIMEOUT="${TEST_TIMEOUT:-90}"
CURL_ATTEMPT_TIMEOUT="${CURL_ATTEMPT_TIMEOUT:-10}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Temp directory + cleanup ──────────────────────────────────────────
WORKDIR="$(mktemp -d)"
cleanup() {
    local pids=("${YGGSTACK1_PID:-}" "${YGGSTACK2_PID:-}" "${LITE_PID:-}")
    for pid in "${pids[@]}"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── Helpers ───────────────────────────────────────────────────────────
info()  { echo "==> $*"; }
fail()  { echo "FAIL: $*" >&2; exit 1; }

wait_for_line() {
    local file="$1" pattern="$2" timeout="$3" label="$4"
    local elapsed=0
    while true; do
        if grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $timeout ]]; then
            echo "--- $label log (last 30 lines) ---"
            tail -30 "$file"
            fail "Timed out waiting for $label (${timeout}s)"
        fi
    done
}

extract_match() {
    local file="$1" pattern="$2"
    local result
    result="$(grep -o "$pattern" "$file" 2>/dev/null || true)"
    echo "$result" | head -1
}

# ── 0. Ensure test keys exist ─────────────────────────────────────────
KEYS_DIR="$SCRIPT_DIR/keys"
LITE_SEED_FILE="$KEYS_DIR/lite_node.seed"
YGGSTACK_KEY_FILE="$KEYS_DIR/yggstack.key"

if [[ ! -f "$LITE_SEED_FILE" ]] || [[ ! -f "$YGGSTACK_KEY_FILE" ]]; then
    info "Test keys not found, generating..."
    cargo run --example gen_test_keys --manifest-path "$CRATE_DIR/Cargo.toml" 2>&1 \
        || fail "Failed to generate test keys"
fi

LITE_SEED="$(cat "$LITE_SEED_FILE")"
YGGSTACK_KEY="$(cat "$YGGSTACK_KEY_FILE")"
[[ -n "$LITE_SEED" ]] || fail "Empty lite_node seed"
[[ -n "$YGGSTACK_KEY" ]] || fail "Empty yggstack key"
info "Using stored test keys"

# ── 1. Generate yggstack1 config (with stored key, TLS listener only) ─────
info "Generating yggstack1 config"
"$YGGSTACK_BIN" --genconf 2>/dev/null \
    | sed 's|"tcp://0.0.0.0:0"|"tls://127.0.0.1:0"|' \
    | sed "s|\"PrivateKey\": \"[a-fA-F0-9]*\"|\"PrivateKey\": \"${YGGSTACK_KEY}\"|" \
    > "$WORKDIR/yggstack1.conf"
[[ -s "$WORKDIR/yggstack1.conf" ]] || fail "Failed to generate yggstack1 config"

# ── 2. Start yggstack1 ───────────────────────────────────────────────
info "Starting yggstack1 (SOCKS5 on 127.0.0.1:$SOCKS_PORT1)"
"$YGGSTACK_BIN" \
    --useconffile "$WORKDIR/yggstack1.conf" \
    --socks "127.0.0.1:$SOCKS_PORT1" \
    --loglevel info \
    > "$WORKDIR/yggstack1.log" 2>&1 &
YGGSTACK1_PID=$!

# Wait for TLS listener and parse the port
wait_for_line "$WORKDIR/yggstack1.log" "Listening on tls://" 15 "yggstack1 TLS"
TLS_LINE="$(extract_match "$WORKDIR/yggstack1.log" 'Listening on tls://[^ ]*')"
TLS_ADDR1="${TLS_LINE#Listening on tls://}"
[[ -z "$TLS_ADDR1" ]] && fail "Could not parse yggstack1 TLS address"
info "yggstack1 TLS at $TLS_ADDR1"

# ── 3. Generate yggstack2 config (fresh key, TLS only, NO peering with yggstack1) ──
info "Generating yggstack2 config (isolated — no peering with yggstack1)"
"$YGGSTACK_BIN" --genconf 2>/dev/null \
    | sed 's|"tcp://0.0.0.0:0"|"tls://127.0.0.1:0"|' \
    > "$WORKDIR/yggstack2.conf"
[[ -s "$WORKDIR/yggstack2.conf" ]] || fail "Failed to generate yggstack2 config"

# ── 4. Start yggstack2 ───────────────────────────────────────────────
info "Starting yggstack2 (SOCKS5 on 127.0.0.1:$SOCKS_PORT2)"
"$YGGSTACK_BIN" \
    --useconffile "$WORKDIR/yggstack2.conf" \
    --socks "127.0.0.1:$SOCKS_PORT2" \
    --loglevel info \
    > "$WORKDIR/yggstack2.log" 2>&1 &
YGGSTACK2_PID=$!

wait_for_line "$WORKDIR/yggstack2.log" "Listening on tls://" 15 "yggstack2 TLS"
TLS_LINE2="$(extract_match "$WORKDIR/yggstack2.log" 'Listening on tls://[^ ]*')"
TLS_ADDR2="${TLS_LINE2#Listening on tls://}"
[[ -z "$TLS_ADDR2" ]] && fail "Could not parse yggstack2 TLS address"
info "yggstack2 TLS at $TLS_ADDR2"

# ── 5. Build and start lite_node (multi-peer: connects to BOTH) ───────
info "Building lite_node"
cargo build --example lite_node --manifest-path "$CRATE_DIR/Cargo.toml" 2>&1 \
    || fail "Failed to build lite_node"

info "Starting lite_node (peers: $TLS_ADDR1, $TLS_ADDR2)"
cargo run --example lite_node --manifest-path "$CRATE_DIR/Cargo.toml" -- \
    "$TLS_ADDR1" "$TLS_ADDR2" --seed "$LITE_SEED" \
    > "$WORKDIR/lite_node.log" 2>&1 &
LITE_PID=$!

wait_for_line "$WORKDIR/lite_node.log" "IPv6:" 30 "lite_node IPv6"
IPV6_LINE="$(extract_match "$WORKDIR/lite_node.log" 'IPv6: *[0-9a-f:]*')"
LITE_IPV6="${IPV6_LINE#IPv6:}"
LITE_IPV6="$(echo "$LITE_IPV6" | tr -d ' ')"
[[ -z "$LITE_IPV6" ]] && fail "Could not parse lite_node IPv6 address"
info "lite_node IPv6: $LITE_IPV6"

# ── 6a. Test direct: curl → yggstack1 SOCKS5 → lite_node ─────────────
info "Test 1: direct path (curl → yggstack1 → lite_node)"
ELAPSED=0
ATTEMPT=0
DIRECT_PASSED=false
while [[ $ELAPSED -lt $TEST_TIMEOUT ]]; do
    ATTEMPT=$((ATTEMPT + 1))

    kill -0 "$YGGSTACK1_PID" 2>/dev/null || fail "yggstack1 died"
    kill -0 "$LITE_PID" 2>/dev/null || fail "lite_node died"

    RESPONSE="$(curl -s --socks5-hostname "127.0.0.1:$SOCKS_PORT1" \
        --max-time "$CURL_ATTEMPT_TIMEOUT" \
        "http://[$LITE_IPV6]:80/hello" 2>&1)" || true

    if [[ "$RESPONSE" == *"Hello, World!"* ]]; then
        info "Direct path OK (attempt $ATTEMPT, ${ELAPSED}s)"
        DIRECT_PASSED=true
        break
    fi

    sleep 2
    ELAPSED=$((ELAPSED + CURL_ATTEMPT_TIMEOUT + 2))
done

$DIRECT_PASSED || fail "Direct path failed after ${ATTEMPT} attempts"

# ── 6b. Test multi-hop: curl → yggstack2 SOCKS5 → yggstack1 → lite_node
info "Test 2: multi-hop (curl → yggstack2 → yggstack1 → lite_node)"
ELAPSED=0
ATTEMPT=0
MULTI_PASSED=false
while [[ $ELAPSED -lt $TEST_TIMEOUT ]]; do
    ATTEMPT=$((ATTEMPT + 1))

    kill -0 "$YGGSTACK1_PID" 2>/dev/null || fail "yggstack1 died"
    kill -0 "$YGGSTACK2_PID" 2>/dev/null || fail "yggstack2 died"
    kill -0 "$LITE_PID" 2>/dev/null || fail "lite_node died"

    RESPONSE="$(curl -s --socks5-hostname "127.0.0.1:$SOCKS_PORT2" \
        --max-time "$CURL_ATTEMPT_TIMEOUT" \
        "http://[$LITE_IPV6]:80/hello" 2>&1)" || true

    if [[ "$RESPONSE" == *"Hello, World!"* ]]; then
        info "Multi-hop OK (attempt $ATTEMPT, ${ELAPSED}s)"
        MULTI_PASSED=true
        break
    fi

    sleep 2
    ELAPSED=$((ELAPSED + CURL_ATTEMPT_TIMEOUT + 2))
done

$MULTI_PASSED || {
    echo ""
    echo "====================================="
    echo "  MULTI-HOP TEST FAILED"
    echo "====================================="
    echo "Expected: Hello, World!"
    echo "Got:      $RESPONSE"
    echo ""
    echo "--- yggstack1 log (last 20 lines) ---"
    tail -20 "$WORKDIR/yggstack1.log"
    echo "--- yggstack2 log (last 20 lines) ---"
    tail -20 "$WORKDIR/yggstack2.log"
    echo "--- lite_node log (last 20 lines) ---"
    tail -20 "$WORKDIR/lite_node.log"
    exit 1
}

# ── Done ──────────────────────────────────────────────────────────────
echo ""
echo "====================================="
echo "  E2E MULTI-PEER TEST PASSED"
echo "====================================="
echo "  yggstack1 <──TLS── lite_node ──TLS──> yggstack2"
echo "  (isolated — no direct link between yggstacks)"
echo "  Via yggstack1 (peer 1):  OK"
echo "  Via yggstack2 (peer 2):  OK"
echo "====================================="
exit 0
