#!/usr/bin/env bash
# Analyze a preserved interop workdir (run as root after INTEROP_KEEP=1 failure).
set -euo pipefail

WD="${1:-}"
if [[ -z "$WD" ]]; then
    WD=$(ls -dt /tmp/ikev2-interop.* 2>/dev/null | head -1 || true)
fi
if [[ -z "$WD" || ! -d "$WD" ]]; then
    echo "Usage: sudo $0 [/tmp/ikev2-interop.XXXXXX]" >&2
    exit 1
fi

echo "=== Workdir: $WD ==="

echo ""
echo "--- ike-lb.conf ---"
cat "$WD/ike-lb.conf" 2>/dev/null || echo "(missing)"

echo ""
echo "--- ike-lb.log ---"
cat "$WD/ike-lb.log" 2>/dev/null || echo "(missing)"

echo ""
echo "--- hub strongswan.conf ---"
cat "$WD/hub-b1/strongswan.conf" 2>/dev/null || echo "(missing)"

echo ""
echo "--- hub charon (IKE_AUTH / CHILD / error) ---"
grep -E 'IKE_AUTH|CHILD|error|failed|sending packet|received packet|authentication' \
    "$WD/hub-b1/charon.log" 2>/dev/null | tail -40 || echo "(missing)"

echo ""
echo "--- spoke charon (last 30 lines) ---"
tail -30 "$WD/spoke/charon.log" 2>/dev/null || echo "(missing)"

echo ""
echo "--- spoke-init.log ---"
tail -20 "$WD/spoke-init.log" 2>/dev/null || echo "(missing)"

echo ""
echo "--- Diagnosis hints ---"
if grep -q 'drop.*backend' "$WD/ike-lb.log" 2>/dev/null; then
    echo "* ike-lb dropped backend replies — rebuild with latest ike-lb, run with IKE_LB_DEBUG=1"
fi
if grep -q 'no socket found to send.*5500' "$WD/spoke/charon.log" 2>/dev/null; then
    echo "* spoke charon not bound to port 5500 — use encap=no remote_port=5500 (current default)"
fi
if grep -q 'installing trap failed' "$WD/hub-b1/charon.log" 2>/dev/null; then
    echo "* hub trap install failed — should be fixed with remote_addrs=%any"
fi
if grep -q 'could not open IPv4 NAT-T' "$WD/hub-b1/charon.log" 2>/dev/null; then
    echo "* hub NAT-T bind conflict — need STRONGSWAN_CONF + backend port 4501"
fi
