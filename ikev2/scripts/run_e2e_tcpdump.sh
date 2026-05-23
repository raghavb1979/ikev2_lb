#!/usr/bin/env bash
# End-to-end test with packet capture (ike-lb --pcap, optional sudo tcpdump)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MAKE_FLAGS="${MAKE_FLAGS:-IKEV2_NO_SSL=1}"
LB_HOST="${LB_HOST:-127.0.0.1}"
LB_PORT="${LB_PORT:-5000}"
B1_PORT="${B1_PORT:-5001}"
B2_PORT="${B2_PORT:-5002}"
IFACE="${IFACE:-lo}"
PCAP_DIR="${PCAP_DIR:-$ROOT/docs/output/pcap}"
PCAP_FILE="$PCAP_DIR/ike_e2e_$(date +%Y%m%d_%H%M%S).pcap"
USE_TCPDUMP="${USE_TCPDUMP:-0}"

TCPDUMP_PID=""
B1_PID=""
B2_PID=""
LB_PID=""

cleanup() {
    [ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
    pkill -f "bin/ikev2-server $LB_HOST $B1_PORT" 2>/dev/null || true
    pkill -f "bin/ikev2-server $LB_HOST $B2_PORT" 2>/dev/null || true
    pkill -f "bin/ike-lb" 2>/dev/null || true
    sleep 0.3
}
trap cleanup EXIT

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $1" >&2
        exit 1
    }
}

need_cmd timeout
mkdir -p "$PCAP_DIR"

echo "== Build =="
make $MAKE_FLAGS -j$(nproc 2>/dev/null || echo 2) all >/dev/null

echo "== Start backends and load balancer (built-in PCAP) =="
cleanup
./bin/ikev2-server "$LB_HOST" "$B1_PORT" >/tmp/ike-e2e-b1.log 2>&1 &
B1_PID=$!
./bin/ikev2-server "$LB_HOST" "$B2_PORT" >/tmp/ike-e2e-b2.log 2>&1 &
B2_PID=$!
./bin/ike-lb --pcap "$PCAP_FILE" config/ike-lb.conf >/tmp/ike-e2e-lb.log 2>&1 &
LB_PID=$!
sleep 1

if ! kill -0 "$B1_PID" "$B2_PID" "$LB_PID" 2>/dev/null; then
    echo "ERROR: failed to start lab processes" >&2
    tail -20 /tmp/ike-e2e-lb.log 2>/dev/null || true
    exit 1
fi

if [ "$USE_TCPDUMP" = 1 ] && command -v tcpdump >/dev/null 2>&1; then
    echo "== Optional tcpdump on $IFACE =="
    if tcpdump -i "$IFACE" -s 0 -w "${PCAP_FILE%.pcap}_nic.pcap" \
        udp port "$LB_PORT" or udp port "$B1_PORT" or udp port "$B2_PORT" or udp port 4500 \
        >/tmp/ike-e2e-tcpdump.log 2>&1 &
    then
        TCPDUMP_PID=$!
        sleep 0.3
        kill -0 "$TCPDUMP_PID" 2>/dev/null || TCPDUMP_PID=""
    fi
fi

echo "== E2E: 3 IKE_SA_INIT exchanges via load balancer =="
PASS=0
for i in 1 2 3; do
    if timeout 8 ./bin/ikev2-client "$LB_HOST" "$LB_PORT"; then
        echo "  run $i: PASS"
        PASS=$((PASS + 1))
    else
        echo "  run $i: FAIL"
    fi
    sleep 0.3
done

cleanup
TCPDUMP_PID=""
sleep 0.3

if [ ! -s "$PCAP_FILE" ]; then
    echo "ERROR: PCAP missing or empty: $PCAP_FILE" >&2
    exit 1
fi

echo "== Analyze capture =="
if command -v tcpdump >/dev/null 2>&1; then
    "$ROOT/scripts/analyze_ike_pcap.sh" "$PCAP_FILE" "$LB_PORT" "$B1_PORT" "$B2_PORT"
else
    echo "  PCAP size: $(wc -c < "$PCAP_FILE") bytes (install tcpdump to analyze)"
fi

if [ "$PASS" -lt 3 ]; then
    echo "E2E client runs: $PASS/3 passed" >&2
    exit 1
fi

echo ""
echo "== E2E + PCAP: PASS =="
echo "  PCAP:     $PCAP_FILE"
echo "  LB log:   /tmp/ike-e2e-lb.log"
echo "  View:     tcpdump -r $PCAP_FILE -n -vv"
