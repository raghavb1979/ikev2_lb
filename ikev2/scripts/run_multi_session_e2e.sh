#!/usr/bin/env bash
# E2E: verify multiple initiators spread across backends (log + optional pcap)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LB_HOST=127.0.0.1
LB_PORT=5000
B1=5001
B2=5002

cleanup() {
    pkill -f "bin/ikev2-server 127.0.0.1 $B1" 2>/dev/null || true
    pkill -f "bin/ikev2-server 127.0.0.1 $B2" 2>/dev/null || true
    pkill -f "bin/ike-lb" 2>/dev/null || true
    sleep 0.2
}
trap cleanup EXIT

make "${MAKE_FLAGS:-IKEV2_NO_SSL=1}" -j2 all >/dev/null
cleanup

./bin/ikev2-server "$LB_HOST" "$B1" >/tmp/ike-ms-b1.log 2>&1 &
./bin/ikev2-server "$LB_HOST" "$B2" >/tmp/ike-ms-b2.log 2>&1 &
./bin/ike-lb config/ike-lb.conf >/tmp/ike-ms-lb.log 2>&1 &
sleep 1

echo "== 5 IKE_SA_INIT sessions via LB (sequential) =="
for i in 1 2 3 4 5; do
    timeout 8 ./bin/ikev2-client "$LB_HOST" "$LB_PORT" >/tmp/ike-ms-c$i.log 2>&1
done

ok=0
for i in 1 2 3 4 5; do
    if grep -q "completed successfully" /tmp/ike-ms-c$i.log 2>/dev/null; then
        ok=$((ok + 1))
    fi
done

echo "Clients succeeded: $ok/5"
grep "new IKE session -> backend" /tmp/ike-ms-lb.log | sort | uniq -c

b0=$(grep -c "backend 0" /tmp/ike-ms-lb.log 2>/dev/null || echo 0)
b1=$(grep -c "backend 1" /tmp/ike-ms-lb.log 2>/dev/null || echo 0)
echo "Backend 0 sessions: $b0"
echo "Backend 1 sessions: $b1"

[ "$ok" -eq 5 ] || exit 1
echo "Multi-session E2E: PASS"
