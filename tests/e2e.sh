#!/usr/bin/env bash
#
# End-to-end test for yggdrasil-lite.
#
# Starts a yggstack-ng node (full Yggdrasil + SOCKS5 proxy), connects
# the lite_node example to it, and verifies HTTP reachability over the
# Yggdrasil overlay via curl through the SOCKS5 proxy.
#
# Required:
#   YGGSTACK_BIN  — path to the yggstack binary
#
# Usage:
#   YGGSTACK_BIN=/path/to/yggstack bash tests/e2e.sh
#
set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────
: "${YGGSTACK_BIN:?Set YGGSTACK_BIN to the yggstack binary path}"
SOCKS_PORT=$((RANDOM % 10000 + 20000))
TEST_TIMEOUT="${TEST_TIMEOUT:-60}"
CURL_ATTEMPT_TIMEOUT="${CURL_ATTEMPT_TIMEOUT:-10}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Temp directory + cleanup ──────────────────────────────────────────
WORKDIR="$(mktemp -d)"
cleanup() {
    local pids=("${YGGSTACK_PID:-}" "${LITE_PID:-}")
    for pid in "${pids[@]}"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── Helper ────────────────────────────────────────────────────────────
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
            fail "Timed out waiting for $label (${timeout}s)"
        fi
    done
}

extract_match() {
    # Safe single-match extraction that avoids SIGPIPE with pipefail
    local file="$1" pattern="$2"
    local result
    result="$(grep -o "$pattern" "$file" 2>/dev/null || true)"
    echo "$result" | head -1
}

# ── 1. Generate yggstack config ──────────────────────────────────────
info "Generating yggstack config"
# Use --genconf for a valid keypair, then replace the Listen address
"$YGGSTACK_BIN" --genconf 2>/dev/null \
    | sed 's|"tcp://0.0.0.0:0"|"tls://127.0.0.1:0"|' \
    > "$WORKDIR/yggstack.conf"

[[ -s "$WORKDIR/yggstack.conf" ]] || fail "Failed to generate yggstack config"

# ── 2. Start yggstack ────────────────────────────────────────────────
info "Starting yggstack (SOCKS5 on 127.0.0.1:$SOCKS_PORT)"
"$YGGSTACK_BIN" \
    --useconffile "$WORKDIR/yggstack.conf" \
    --socks "127.0.0.1:$SOCKS_PORT" \
    --loglevel info \
    > "$WORKDIR/yggstack.log" 2>&1 &
YGGSTACK_PID=$!

# Wait for TLS listener to bind and parse the actual port
wait_for_line "$WORKDIR/yggstack.log" "Listening on tls://" 15 "yggstack TLS listener"
TLS_LINE="$(extract_match "$WORKDIR/yggstack.log" 'Listening on tls://[^ ]*')"
TLS_ADDR="${TLS_LINE#Listening on tls://}"
[[ -z "$TLS_ADDR" ]] && fail "Could not parse TLS listen address"
info "yggstack TLS listener at $TLS_ADDR"

# ── 3. Build and start lite_node ─────────────────────────────────────
info "Building lite_node example"
cargo build --example lite_node --manifest-path "$CRATE_DIR/Cargo.toml" 2>&1 || fail "Failed to build lite_node"

info "Starting lite_node (peer: $TLS_ADDR)"
cargo run --example lite_node --manifest-path "$CRATE_DIR/Cargo.toml" -- "$TLS_ADDR" \
    > "$WORKDIR/lite_node.log" 2>&1 &
LITE_PID=$!

# Wait for the IPv6 address to be printed
wait_for_line "$WORKDIR/lite_node.log" "IPv6:" 30 "lite_node IPv6 address"
IPV6_LINE="$(extract_match "$WORKDIR/lite_node.log" 'IPv6: *[0-9a-f:]*')"
LITE_IPV6="${IPV6_LINE#IPv6:}"
LITE_IPV6="${LITE_IPV6## }"   # strip any leading spaces
LITE_IPV6="${LITE_IPV6%% }"   # strip any trailing spaces
# Remove all spaces (covers variable-width alignment)
LITE_IPV6="$(echo "$LITE_IPV6" | tr -d ' ')"
[[ -z "$LITE_IPV6" ]] && fail "Could not parse lite_node IPv6 address"
info "lite_node IPv6: $LITE_IPV6"

# ── 4. Test HTTP via SOCKS5 (retry loop) ─────────────────────────────
info "Testing HTTP: curl → SOCKS5 → yggdrasil → lite_node (timeout ${TEST_TIMEOUT}s)"
ELAPSED=0
ATTEMPT=0
while [[ $ELAPSED -lt $TEST_TIMEOUT ]]; do
    ATTEMPT=$((ATTEMPT + 1))

    # Check processes are still alive
    kill -0 "$YGGSTACK_PID" 2>/dev/null || fail "yggstack died (check $WORKDIR/yggstack.log)"
    kill -0 "$LITE_PID" 2>/dev/null || fail "lite_node died (check $WORKDIR/lite_node.log)"

    RESPONSE="$(curl -6 -s --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        --max-time "$CURL_ATTEMPT_TIMEOUT" \
        "http://[$LITE_IPV6]:80/hello" 2>&1)" || true

    if [[ "$RESPONSE" == "Hello, World!" ]]; then
        echo ""
        echo "====================================="
        echo "  E2E TEST PASSED  (attempt $ATTEMPT, ${ELAPSED}s)"
        echo "====================================="
        exit 0
    fi

    sleep 2
    ELAPSED=$((ELAPSED + CURL_ATTEMPT_TIMEOUT + 2))
done

echo ""
echo "====================================="
echo "  E2E TEST FAILED  ($ATTEMPT attempts, ${ELAPSED}s)"
echo "====================================="
echo "Expected: Hello, World!"
echo "Got:      $RESPONSE"
echo ""
echo "--- yggstack log (last 20 lines) ---"
tail -20 "$WORKDIR/yggstack.log"
echo "--- lite_node log (last 20 lines) ---"
tail -20 "$WORKDIR/lite_node.log"
exit 1
