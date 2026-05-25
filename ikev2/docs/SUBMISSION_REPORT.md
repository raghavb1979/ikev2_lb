# IKEv2 Load Balancer — Project Report

**Project:** Hub–Spoke IKEv2 Load Balancer (OpenIKED + StrongSwan)  
**Date:** May 2026  
**Repository:** `/home/raghavendranb/ikev2`

**Generated artifacts:**

- PDF: `docs/output/IKEv2_LoadBalancer_Report.pdf`
- PPTX: `docs/output/IKEv2_LoadBalancer_Report.pptx`
- Regenerate: `make submission-docs` or `python3 scripts/generate_submission_docs.py`

---

## 1. Executive summary

Designed and implemented an **IKE-aware UDP load balancer** (`ike-lb`) for a large hub–spoke network. Hub routers run **[openiked-portable](https://github.com/openiked/openiked-portable)**; spokes use **StrongSwan**. The VIP fronts multiple `iked` backends with **SPI-based session stickiness** per RFC 7296.

---

## 2. Problem statement

| Requirement | Detail |
|-------------|--------|
| IKE stack | openiked-portable on hub routers |
| Topology | Hub–spoke (spokes → hub VIP) |
| Goal | IKEv2 load balancer across multiple `iked` instances |
| Interop | StrongSwan client or server role |

---

## 3. Structured approach (HLD → LLD → Build → Test)

### 3.1 High-level design (HLD)

- Spokes send IKE to **hub VIP** (`ike-lb` on UDP 500/4500).
- LB parses IKE header, selects backend, maintains SPI → backend table.
- Backends run **openiked** with identical `iked.conf`.
- Return path: relay via LB (lab) or direct backend→spoke (production routing).

See: `docs/DESIGN.md`

### 3.2 Low-level design (LLD)

| Module | File | Role |
|--------|------|------|
| IKE messages | `src/ike_msg.c` | Header + SA/KE/Nonce payloads |
| Crypto | `src/ike_crypto.c` | SPI, DH (OpenSSL or stub) |
| Session (responder) | `src/ike_session.c` | IKE_SA_INIT handler (demo server) |
| LB sessions | `src/ike_lb_session.c` | Config, SPI hash, session table |
| LB proxy | `src/ike_lb_main.c` | poll(), forward, reply relay |
| Demo client/server | `src/client_main.c`, `src/server_main.c` | Lab testing |

Build-time limits (defaults): **65536** sessions, **32** backends, **3600 s** timeout.

### 3.3 Execution

```bash
make IKEV2_NO_SSL=1          # or make with openssl-devel
make show-config
./bin/ike-lb config/ike-lb.conf
```

Deliverables:

- `bin/ike-lb` — load balancer
- `bin/ikev2-server`, `bin/ikev2-client` — lab IKE_SA_INIT peers
- `config/ike-lb.conf` — lab backends
- `docs/DESIGN.md`, `docs/INTEROP.md`, `docs/TEST_PLAN.md`

### 3.4 Testing / validation

| Level | Result |
|-------|--------|
| Unit `test_ike_msg` | 13/13 PASS |
| Unit `test_ike_lb` | 8/8 PASS |
| Unit `test_proposals` | 10/10 PASS |
| E2E `scripts/run_tests.sh` | IKE_SA_INIT via LB PASS |
| E2E `scripts/run_multi_session_e2e.sh` | 5/5 PASS |
| E2E `scripts/run_interop_real.sh` (S-01) | **PASS** — StrongSwan spoke → VIP → hub `charon`; CHILD SA ESTABLISHED |
| E2E `scripts/run_e2e_tcpdump.sh` | Run on lab host (PCAP flow check) |

See: `docs/TEST_PLAN.md`

### 3.5 StrongSwan interop

- Automated script: `sudo ./scripts/run_interop_real.sh` (log: `docs/output/interop_real.log`)
- Default `INTEROP_NO_NAT=1` uses `203.0.113.1/2` for reliable S-01; `10.10.x` + NAT-T (`INTEROP_NO_NAT=0`) documented as follow-up
- Config alignment: `docs/INTEROP.md`
- **Required vs Recommended vs Optional** scenarios: [INTEROP.md#required-vs-optional-scenarios](INTEROP.md#required-vs-optional-scenarios)
- Algorithm / test status: `docs/INTEROP_ALGORITHM_STATUS.md`

---

## 4. Architecture diagram

```
  [StrongSwan Spokes]
         |
         v UDP 500/4500
    +------------+
    |  ike-lb    |  Hub VIP — SPI sticky
    +------------+
      |    |    |
   iked iked iked  (openiked-portable backends)
```

---

## 5. AI usage (SDLC)

| Phase | How AI was used |
|-------|-----------------|
| Requirements | Clarified rubric vs missing problem statement |
| HLD/LLD | Architecture, hub–spoke, StrongSwan interop |
| Implementation | C IKE parser, LB proxy, Makefile, build-time config |
| Test | Test plan, unit tests, E2E script, reply-path fix |
| Docs | DESIGN, INTEROP, TEST_PLAN, this report |

---

## 6. Prompt log

**Canonical list (user prompts only, no duplicates):** [docs/PROMPTS.md](PROMPTS.md)

| # | Prompt (summary) |
|---|------------------|
| 1 | Assignment brief (rubric + submission rules) |
| 2 | `can you create the code now?` |
| 3 | `can you create the c files with make file?` |
| 4 | `you understood the problem statement clearly?` |
| 5 | IKEv2 LB + openiked-portable + StrongSwan (hub–spoke) |
| 6 | `test plan and test it?` |
| 7 | `how many requests handled concurrently` |
| 8 | `configurable at build time...` |
| 9 | `is the python file inside src/ikev2` |
| 10 | `if not required remote` (remove Python) |
| 11 | `generate a ppt or pdf... and the prompt string` |
| 12 | `tcpdump and end to end testing` |
| 13 | `all the interop with algorithms flow tested` |
| 14 | IKE interop: structure/algorithms vs other scenarios |
| 15 | `update the required vs optional scenarios` |
| 16 | `prompt string document only required prompt strings` |

Full verbatim text for prompts **1** and **5** is in `PROMPTS.md`.

---

## 7. Documentation set (all updated)

| Document | Contents |
|----------|----------|
| `docs/DESIGN.md` | HLD/LLD; link to interop scope |
| `docs/INTEROP.md` | Required / Recommended / Optional tables + checklists |
| `docs/INTEROP_ALGORITHM_STATUS.md` | Automated vs manual algorithm tests |
| `docs/TEST_PLAN.md` | U/I/P/S test IDs; interop cross-links |
| `docs/README.md` | Doc index |
| `docs/PROMPTS.md` | User prompts only (submission requirement) |
| `docs/SUBMISSION_REPORT.md` | This file |
| `docs/output/*.pdf` / `*.pptx` | Regenerate with `make submission-docs` |

---

## 8. File tree (final)

```
ikev2/
├── Makefile
├── README.md
├── bin/
├── config/ike-lb.conf
├── docs/
│   ├── README.md
│   ├── DESIGN.md
│   ├── INTEROP.md
│   ├── INTEROP_ALGORITHM_STATUS.md
│   ├── TEST_PLAN.md
│   ├── SUBMISSION_REPORT.md
│   └── output/           # PDF, PPTX, pcap/
├── scripts/
│   ├── run_tests.sh
│   ├── run_e2e_tcpdump.sh
│   ├── run_multi_session_e2e.sh
│   ├── analyze_ike_pcap.sh
│   └── generate_submission_docs.py
├── include/
├── src/
└── tests/
```

---

## 9. Session evidence / recording

| Artifact | Path |
|----------|------|
| Demo log | `docs/output/demo_recording.log` |
| Terminal capture | `docs/output/demo_session.script` |
| HTML recording | `docs/output/demo_recording.html` |
| PCAP | `docs/output/pcap/ike_e2e_*.pcap` |
| Cursor chat | Export to `docs/output/cursor_session_export.md` (manual) |

Regenerate: `make record` — see [RECORDING.md](RECORDING.md)

---

## 10. References

- https://github.com/openiked/openiked-portable
- https://github.com/strongswan/strongswan
- RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2)
