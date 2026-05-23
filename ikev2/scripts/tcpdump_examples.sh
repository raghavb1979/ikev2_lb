#!/usr/bin/env bash
# Reference tcpdump commands for IKEv2 load-balancer lab (manual use)
cat <<'EOF'
# --- Live capture on hub (replace eth0, hub VIP, backend ports) ---
sudo tcpdump -i eth0 -s 0 -w /tmp/hub_ike.pcap \
  'udp port 500 or udp port 4500 or udp port 5001 or udp port 5002'

# --- Live capture on loopback lab ---
tcpdump -i lo -s 0 -w ike_lab.pcap \
  'udp port 5000 or udp port 5001 or udp port 5002 or udp port 4500'

# --- Read capture: all IKE lab ports ---
tcpdump -r ike_lab.pcap -n -vv

# --- Only traffic to/from hub VIP ---
tcpdump -r ike_lab.pcap -n 'host 203.0.113.10 and (udp port 500 or udp port 4500)' -vv

# --- Show UDP payload hex (Initiator SPI = first 8 bytes of IKE header) ---
tcpdump -r ike_lab.pcap -n -X -c 5 'udp port 5000'

# --- Count packets per port ---
tcpdump -r ike_lab.pcap -n 'udp port 5000' | wc -l
tcpdump -r ike_lab.pcap -n 'udp port 5001' | wc -l
tcpdump -r ike_lab.pcap -n 'udp port 5002' | wc -l

# --- Automated E2E + pcap ---
./scripts/run_e2e_tcpdump.sh

# --- Analyze saved pcap ---
./scripts/analyze_ike_pcap.sh docs/output/pcap/ike_e2e_*.pcap

# --- Wireshark/tshark (optional) ---
tshark -r ike_lab.pcap -Y isakmp -V
EOF
