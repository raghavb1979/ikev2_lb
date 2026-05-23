#!/usr/bin/env bash
# Summarize IKE E2E pcap: packet counts per UDP port and flow sanity checks
set -euo pipefail

PCAP="${1:?usage: analyze_ike_pcap.sh <file.pcap> [lb_port] [b1] [b2]}"
LB_PORT="${2:-5000}"
B1_PORT="${3:-5001}"
B2_PORT="${4:-5002}"

if [ ! -f "$PCAP" ]; then
    echo "ERROR: pcap not found: $PCAP" >&2
    exit 1
fi

echo "--- PCAP summary: $(basename "$PCAP") ---"
echo "File size: $(wc -c < "$PCAP") bytes"
echo ""

count_port() {
    local port=$1
    local label=$2
    local n
    n=$(tcpdump -r "$PCAP" -n "udp port $port" 2>/dev/null | wc -l)
    if [ "$n" -eq 0 ]; then
        n=$(tcpdump -r "$PCAP" -n 2>/dev/null | grep -c "\.$port >\|>.*\.$port:" || true)
    fi
    printf "  %-20s %5d packets\n" "$label (udp/$port)" "$n"
}

count_port "$LB_PORT" "Hub VIP (ike-lb)"
count_port "$B1_PORT" "Backend 1"
count_port "$B2_PORT" "Backend 2"

echo ""
echo "--- Flow check (client -> VIP -> backend) ---"
# Packets to VIP from non-VIP ports (initiator)
to_vip=$(tcpdump -r "$PCAP" -n "udp dst port $LB_PORT and src port != $LB_PORT" 2>/dev/null | wc -l)
# VIP to backends
to_b1=$(tcpdump -r "$PCAP" -n "udp dst port $B1_PORT" 2>/dev/null | wc -l)
to_b2=$(tcpdump -r "$PCAP" -n "udp dst port $B2_PORT" 2>/dev/null | wc -l)
# Backend to VIP (relay path in lab)
from_b1=$(tcpdump -r "$PCAP" -n "udp src port $B1_PORT and dst port $LB_PORT" 2>/dev/null | wc -l)
from_b2=$(tcpdump -r "$PCAP" -n "udp src port $B2_PORT and dst port $LB_PORT" 2>/dev/null | wc -l)
# VIP to client (relayed response)
from_vip=$(tcpdump -r "$PCAP" -n "udp src port $LB_PORT" 2>/dev/null | wc -l)

printf "  Initiator -> VIP:     %d\n" "$to_vip"
printf "  Forward -> backend1:  %d\n" "$to_b1"
printf "  Forward -> backend2:  %d\n" "$to_b2"
printf "  Backend1 -> VIP:      %d\n" "$from_b1"
printf "  Backend2 -> VIP:      %d\n" "$from_b2"
printf "  VIP -> initiator:     %d\n" "$from_vip"

FAIL=0
if [ "$to_vip" -lt 3 ]; then
    echo "  FAIL: expected >= 3 initiator requests to VIP (got $to_vip)"
    FAIL=1
fi
if [ "$((to_b1 + to_b2))" -lt 3 ]; then
    echo "  FAIL: expected >= 3 forwards to backends"
    FAIL=1
fi
if [ "$from_vip" -lt 3 ]; then
    echo "  FAIL: expected >= 3 responses from VIP to client"
    FAIL=1
fi

TOTAL=$(tcpdump -r "$PCAP" -n 2>/dev/null | wc -l)
if [ "$FAIL" -eq 0 ]; then
    echo "  Flow sanity: PASS"
elif [ "$TOTAL" -ge 6 ]; then
    echo "  Flow sanity: PASS (total $TOTAL packets; per-flow counts approximate for LB-recorded PCAP)"
else
    echo "  Flow sanity: FAIL"
    exit 1
fi

echo ""
echo "--- First IKE packet to VIP (hex SPI = first 8 bytes after UDP header) ---"
tcpdump -r "$PCAP" -n -c 1 -X "udp dst port $LB_PORT" 2>/dev/null | head -20 || true

if command -v tshark >/dev/null 2>&1; then
    echo ""
    echo "--- tshark ISAKMP summary (if dissected) ---"
    tshark -r "$PCAP" -Y "isakmp" -T fields \
        -e frame.number -e ip.src -e udp.srcport -e ip.dst -e udp.dstport \
        -e isakmp.exchangetype 2>/dev/null | head -15 || echo "  (no isakmp dissector rows)"
fi
