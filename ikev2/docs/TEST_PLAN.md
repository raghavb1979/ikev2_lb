# Test Plan — IKEv2 Load Balancer

## 1. Objectives

Verify that `ike-lb` correctly distributes and sticks IKEv2 sessions to openiked backends, and that message handling interoperates with the documented StrongSwan hub–spoke model.

## 2. Real-world practicality

Full checklist and test-to-production mapping: **[PRACTICALITY.md](PRACTICALITY.md)**.

| Concern | Lab test(s) | Production validation |
|---------|-------------|------------------------|
| Spoke uses hub VIP only | I-02, I-04 | S-01, firewall policy |
| SPI stickiness (full IKE SA) | U-03, U-04, I-02 | S-02 |
| Multiple backends / scale-out | I-05 | More spokes + `ikectl sa` |
| Algorithm / proposal alignment | U-06, U-07 | S-01, S-03 |
| Packet evidence | P-01–P-03, `--pcap` | Hub NIC `tcpdump` |
| NAT-T | — | S-04 |
| IKE_AUTH + ESP tunnel | — | S-01 + ping |
| Backend config drift | — | S-03 (negative) |
| LB/backend failure | — | Ops runbook (DESIGN §4.5) |

**Flows:** Lab uses symmetric LB relay ([FLOWS.md](FLOWS.md)); production often has **direct backend→spoke** IKE replies but **must** send initiator IKE to VIP.

---

## 3. Test scope

| In scope | Out of scope (separate lab) |
|----------|----------------------------|
| IKE header parse/encode | Full IPsec traffic |
| SPI-based backend selection | IKE_AUTH with real certificates |
| Session table stickiness | MOBIKE / rekey at scale |
| UDP relay (client ↔ LB ↔ backend) | Production TPROXY / hardware LB |
| Lab E2E with demo `ikev2-server` | Full StrongSwan + openiked cluster |

## 4. Test levels

### 4.1 Unit tests

| ID | Test | Command | Pass criteria |
|----|------|---------|---------------|
| U-01 | IKE header round-trip | `./bin/test_ike_msg` | 0 failures |
| U-02 | IKE_SA_INIT build/handle | `./bin/test_ike_msg` | session established |
| U-03 | SPI hash stability | `./bin/test_ike_lb` | same SPI → same backend index |
| U-04 | Session bind/lookup | `./bin/test_ike_lb` | client+SPI and SPI-by-backend lookup |
| U-05 | Config load | `./bin/test_ike_lb` | `config/ike-lb.conf` parses |
| U-06 | Demo SA algorithm IDs | `./bin/test_proposals` | AES-GCM-16, PRF-SHA2-256, DH14 in stub |
| U-07 | IKE_SA_INIT carries SA/KE | `./bin/test_proposals` | payloads present, KE group 14 |

### 4.2 Integration tests (automated)

| ID | Test | Command | Pass criteria |
|----|------|---------|---------------|
| I-01 | Direct client → server | `./bin/ikev2-client 127.0.0.1 5001` | "completed successfully" |
| I-02 | Client → LB → 2 backends | `scripts/run_tests.sh` | E2E PASS, LB logs new session |
| I-03 | Backend reply relay | I-02 | client receives responder SPI |
| I-04 | E2E + tcpdump capture | `make test-e2e-pcap` | 3/3 clients PASS; pcap flow sanity PASS |
| I-05 | Multi-session LB spread | `make test-e2e-multi` | 5/5 clients PASS; backends 0/1 used |

### 4.3 tcpdump / packet verification

| ID | Test | Command | Pass criteria |
|----|------|---------|---------------|
| P-01 | Capture lab IKE | `scripts/run_e2e_tcpdump.sh` | PCAP under `docs/output/pcap/` |
| P-02 | Analyze flows | `scripts/analyze_ike_pcap.sh <pcap>` | ≥3 req to VIP, forwards to backends, ≥3 replies from VIP |
| P-03 | Manual hub capture | `scripts/tcpdump_examples.sh` | Reference filters for eth0 / production VIP |

**Example (loopback lab):**

```bash
make test-e2e-pcap
tcpdump -r docs/output/pcap/ike_e2e_*.pcap -n -vv
tcpdump -r docs/output/pcap/ike_e2e_*.pcap -n -X -c 2 'udp port 5000'
```

**Example (production hub NIC):**

```bash
sudo tcpdump -i eth0 -s 0 -w hub_ike.pcap \
  'udp port 500 or udp port 4500'
# StrongSwan spoke initiates to VIP; verify forward to backend IP
```

### 4.4 Algorithm / interop flow status

See **[INTEROP.md — Required vs optional scenarios](INTEROP.md#required-vs-optional-scenarios)** and **[INTEROP_ALGORITHM_STATUS.md](INTEROP_ALGORITHM_STATUS.md)** — lab tests **do not** replace StrongSwan + openiked negotiation.

| Flow | Automated | Notes |
|------|-----------|-------|
| IKE_SA_INIT via LB | PASS | Demo client/server + StrongSwan S-01 |
| IKE_AUTH + PSK | PASS | `sudo ./scripts/run_interop_real.sh` (S-01) |
| CHILD_SA install | PASS | S-01 checks ESTABLISHED on spoke |
| ESP + ping | No | Manual after tunnel up |
| aes256gcm16-prfsha256-ecp256 | PASS (interop) | Demo stub still uses DH **14**; interop uses **ecp256** |
| NAT-T `10.10.x` | SKIP (default) | `INTEROP_NO_NAT=1`; set `INTEROP_NO_NAT=0` for S-04 |

### 4.5 System / interop tests (manual)

| ID | Test | Steps | Pass criteria |
|----|------|-------|---------------|
| S-01 | StrongSwan → VIP | Spoke `swanctl --initiate` to hub VIP | IKE + CHILD SA **ESTABLISHED** on spoke (automated) |
| S-02 | Sticky backend | Repeat 10 initiations; check `ikectl sa` on hubs | Same SPI pair on one iked |
| S-03 | openiked config parity | Mismatched proposal on one backend | Should fail (proves need for sync) |
| S-04 | NAT-T | Spoke behind NAT, UDP 4500 | IKE completes with encapsulation |

## 5. Test environment

| Component | Lab (CI) | Production validation |
|-----------|----------|---------------------|
| OS | Linux (aarch64/x86_64) | Hub router OS |
| LB | `bin/ike-lb` | VIP on hub |
| Backends | `bin/ikev2-server` or `iked` | openiked-portable |
| Client | `bin/ikev2-client` or StrongSwan | StrongSwan spokes |

Build without OpenSSL headers: `make IKEV2_NO_SSL=1`  
With OpenSSL: `make` (real DH for crypto tests)

**Build-time LB limits** (defaults used unless overridden):

| Make variable | Default |
|---------------|---------|
| `IKE_LB_MAX_SESSIONS` | 65536 |
| `IKE_LB_MAX_BACKENDS` | 32 |
| `IKE_LB_SESSION_TIMEOUT` | 3600 |

```bash
make show-config
make IKEV2_NO_SSL=1 IKE_LB_MAX_SESSIONS=65536 IKE_LB_MAX_BACKENDS=32
```

## 6. Execution

```bash
# Unit + basic E2E
make test-all

# E2E with tcpdump PCAP
make test-e2e-pcap

# 5 parallel sessions (backend distribution)
make test-e2e-multi

# Real StrongSwan spoke → ike-lb VIP → hub charon (needs root, swanctl)
sudo make test-interop-real
# Log: docs/output/interop_real.log
# Default: INTEROP_NO_NAT=1 (203.0.113.x). For 10.10.x NAT-T: INTEROP_NO_NAT=0
```

Or step by step:

```bash
make IKEV2_NO_SSL=1 test
./scripts/run_tests.sh
./scripts/run_e2e_tcpdump.sh
./scripts/run_multi_session_e2e.sh
```

## 7. Expected results (current release)

| Area | Status |
|------|--------|
| Unit (U-01–U-07) | Automated PASS (31 tests) |
| Integration (I-01–I-05) | `run_tests.sh`, `test-e2e-multi` PASS; `test-e2e-pcap` verify on host |
| StrongSwan S-01 | **Automated PASS** — `sudo make test-interop-real` or `run_interop_real.sh` |
| S-02, S-03 | Manual |
| S-04 NAT-T | Manual / `INTEROP_NO_NAT=0` (not default PASS) |

## 8. Failure analysis

| Symptom | Likely cause |
|---------|----------------|
| Client hangs via LB | Backend reply not relayed (fixed: backend socket poll) |
| IKE_AUTH fails | Proposal/cert mismatch between backends |
| Wrong backend on rekey | SPI table expired or spoke not using VIP |

## 9. Test log template (for submission)

```
Date:
Tester:
Build: make IKEV2_NO_SSL=1 / make
U-01..U-07: PASS/FAIL
I-01..I-05: PASS/FAIL
P-01..P-03: PASS/FAIL/N/A
S-01..S-04: PASS/FAIL/N/A
Notes:
```
