#!/usr/bin/env bash
# Full demo for assignment recording — run: ./scripts/record_demo.sh
# Or: asciinema rec -c "./scripts/record_demo.sh" -t "IKEv2 LB Demo" docs/output/demo.cast
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="$ROOT/docs/output"
LOG="$OUT/demo_recording.log"

mkdir -p "$OUT"
exec > >(tee -a "$LOG") 2>&1

banner() {
    echo ""
    echo "================================================================"
    echo "  $*"
    echo "================================================================"
    echo ""
}

banner "IKEv2 Load Balancer — Assignment Demo"
echo "Date: $(date -Iseconds)"
echo "Host: $(hostname)"
echo "Repo: $ROOT"
echo ""

banner "1. Build configuration"
make show-config

banner "2. Build project"
make IKEV2_NO_SSL=1 clean all

banner "3. Unit tests"
make IKEV2_NO_SSL=1 test

banner "4. E2E with packet capture (ike-lb --pcap)"
./scripts/run_e2e_tcpdump.sh || echo "NOTE: E2E/pcap step exited non-zero (see log); continuing demo."

banner "5. Multi-session load balance"
./scripts/run_multi_session_e2e.sh || echo "NOTE: multi-session step exited non-zero; continuing demo."

banner "6. Artifacts"
ls -la "$OUT/"
ls -la "$OUT/pcap/" 2>/dev/null || true
echo ""
echo "Documentation:"
ls -1 "$ROOT/docs/"*.md

banner "Demo complete"
echo "Log file: $LOG"
echo "PCAP:     $OUT/pcap/ike_e2e_*.pcap"
echo "PDF:      $OUT/IKEv2_LoadBalancer_Report.pdf"
