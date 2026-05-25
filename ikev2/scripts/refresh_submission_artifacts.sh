#!/usr/bin/env bash
# Refresh interop log, last-run bundle, and submission PDF/PPTX. Requires root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }

ip netns del ikev2-hub 2>/dev/null || true
ip netns del ikev2-spoke 2>/dev/null || true
ip link del veth-hub 2>/dev/null || true
pkill -f 'bin/ike-lb' 2>/dev/null || true

make IKEV2_NO_SSL=1 all
export INTEROP_KEEP=1
export IKE_LB_DEBUG=0
./scripts/run_interop_real.sh

WD="$(ls -td /tmp/ikev2-interop.* 2>/dev/null | head -1 || true)"
if [[ -n "$WD" && -d "$WD" ]]; then
  rm -rf "$ROOT/docs/output/interop_last_run"
  cp -a "$WD" "$ROOT/docs/output/interop_last_run"
  echo "Copied workdir -> docs/output/interop_last_run"
fi

make submission-docs
echo "--- interop summary ---"
grep -E 'PASS|FAIL|SKIP|Done' "$ROOT/docs/output/interop_real.log" | tail -6
ls -la "$ROOT/docs/output/IKEv2_LoadBalancer_Report.pdf"
