# IKE E2E Packet Captures

## Generate a capture

```bash
# Requires capture permission on loopback
sudo ./scripts/run_e2e_tcpdump.sh
# or
make test-e2e-pcap   # falls back to E2E without pcap if tcpdump denied
```

Output: `ike_e2e_YYYYMMDD_HHMMSS.pcap` in this directory.

## Analyze

```bash
./scripts/analyze_ike_pcap.sh docs/output/pcap/ike_e2e_*.pcap
tcpdump -r docs/output/pcap/ike_e2e_*.pcap -n -vv
```

## Reference commands

See `scripts/tcpdump_examples.sh`
