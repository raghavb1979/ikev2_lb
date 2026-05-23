#!/usr/bin/env bash
# Run unit + integration tests for IKEv2 load balancer
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MAKE_FLAGS="${MAKE_FLAGS:-IKEV2_NO_SSL=1}"
LB_PORT=5000
B1_PORT=5001
B2_PORT=5002

cleanup() {
    pkill -f "bin/ikev2-server 127.0.0.1 $B1_PORT" 2>/dev/null || true
    pkill -f "bin/ikev2-server 127.0.0.1 $B2_PORT" 2>/dev/null || true
    pkill -f "bin/ike-lb" 2>/dev/null || true
    sleep 0.2
}

echo "== Build =="
make $MAKE_FLAGS clean all

echo "== Unit: IKE messages =="
./bin/test_ike_msg

echo "== Unit: load balancer =="
./bin/test_ike_lb

echo "== E2E: client -> ike-lb -> backends =="
cleanup
./bin/ikev2-server 127.0.0.1 "$B1_PORT" >/tmp/ike-b1.log 2>&1 &
./bin/ikev2-server 127.0.0.1 "$B2_PORT" >/tmp/ike-b2.log 2>&1 &
./bin/ike-lb config/ike-lb.conf >/tmp/ike-lb.log 2>&1 &
sleep 1

if timeout 8 ./bin/ikev2-client 127.0.0.1 "$LB_PORT"; then
    echo "E2E IKE_SA_INIT via load balancer: PASS"
else
    echo "E2E FAILED"
    echo "--- ike-lb log ---"
    cat /tmp/ike-lb.log || true
    echo "--- backend1 log ---"
    tail -5 /tmp/ike-b1.log || true
    cleanup
    exit 1
fi

grep -q "new IKE session" /tmp/ike-lb.log && echo "LB session stickiness log: OK"

cleanup
echo "== All tests passed =="
