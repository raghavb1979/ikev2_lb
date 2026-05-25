# Interop & Algorithm Test Status

Required vs optional scenario list: **[INTEROP.md](INTEROP.md#required-vs-optional-scenarios)**.

## Summary

| Layer | Automated (lab) | Real peers (StrongSwan + charon hub) |
|-------|-----------------|--------------------------------------|
| IKE_SA_INIT UDP flow via `ike-lb` | **PASS** | **PASS** (`run_interop_real.sh` S-01) |
| SPI stickiness / multi-backend | **PASS** (demo) | S-02: partial log hint; full test manual |
| SA payload present (demo stub) | **PASS** | — |
| **Algorithm negotiation with real peer** | Demo stub only | **PASS** (PSK, aes256gcm16-prfsha256-ecp256) |
| IKE_AUTH + PSK | Demo stub only | **PASS** (S-01, hub + spoke `charon`) |
| CHILD_SA (kernel install) | Demo stub only | **PASS** (S-01 `swanctl --list-sas` ESTABLISHED) |
| ESP + ping across tunnel | No | Manual (not in interop script) |
| NAT-T UDP 4500 (`10.10.x`) | Demo only | **SKIP** by default; see `INTEROP_NO_NAT` below |
| Mismatched proposal on one backend | **NOT TESTED** | S-03 manual |

**Conclusion:** Load-balancer **relay + stickiness** and **StrongSwan hub–spoke IKE through VIP** are validated on a lab host with `sudo ./scripts/run_interop_real.sh` (default **S-01 PASS**). OpenIKED (`iked`) multi-backend mode is optional (`INTEROP_MODE=openiked`). Production **NAT-T on RFC1918** (`10.10.x`) still needs client-IP preservation on the backend leg (`INTEROP_NO_NAT=0` path).

### Default interop networking (`INTEROP_NO_NAT=1`)

The automated script defaults to **RFC5737 TEST-NET-3** (`203.0.113.1` hub, `203.0.113.2` spoke) so StrongSwan does not force NAT-T while the hub `charon` sees the client via `127.0.0.1` relay sockets. For the original **`10.10.x` + VIP :4500** design, run:

```bash
sudo INTEROP_NO_NAT=0 ./scripts/run_interop_real.sh   # S-04 attempted; may fail until relay preserves spoke IP
```

---

## Documented algorithm mapping (target interop)

| Function | StrongSwan (`swanctl`) | OpenIKED (`iked.conf`) | Demo `ikev2-server` stub |
|----------|------------------------|-------------------------|---------------------------|
| IKE encryption | `aes256gcm16` | `aes-256-gcm` | ENCR AES-GCM-16 (type 20/12) |
| PRF | `prfsha256` | `hmac-sha2-256` | PRF HMAC-SHA2-256 |
| IKE DH | `ecp256` | `ecpp256` | **DH group 14 (modp2048)** — lab mismatch |
| ESP | `aes256gcm16-ecp256` | `aes-256-gcm` / `ecpp256` | Not implemented |

**Action for production:** Align DH group (use `ecp256` on both sides, or `modp2048` / group 14 on both). Update demo stub and `ikev2-client` if testing against StrongSwan.

---

## What automated tests cover today

| Test ID | What it proves | What it does **not** prove |
|---------|----------------|----------------------------|
| U-01/U-02 | IKE header + IKE_SA_INIT build/parse | Real crypto negotiation |
| I-02/I-04 | LB forwards IKE; reply relay; PCAP | StrongSwan accepts proposals |
| I-05 | Sessions spread across backends | IKE_AUTH or ESP |

---

## Manual interop checklist (required for “all algorithms flow tested”)

Run on a lab VM with openiked-portable + StrongSwan installed:

```bash
# 1. Hub: two iked backends + ike-lb on VIP (see docs/INTEROP.md)
# 2. Spoke: swanctl.conf proposals = aes256gcm16-prfsha256-ecp256
swanctl --load-all
swanctl --initiate --child net

# 3. Verify on hub
ikectl sa
# 4. Verify same backend for same SPI after rekey
# 5. tcpdump on VIP: IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA
```

| Step | Pass criteria |
|------|----------------|
| IKE_SA_INIT | `swanctl` shows IKE_SA; hub `ikectl sa` shows matching SPIs |
| IKE_AUTH | Auth completes (cert or PSK per config) |
| CHILD_SA | IPsec SA installed; ping across tunnel |
| Algorithms | `ikectl sa` / `swanctl --list-sas` show AES-GCM + agreed DH/ECP |
| LB stickiness | Same hub backend for same initiator across IKE_AUTH |
| NAT-T (optional) | UDP 4500, non-ESP marker in PCAP |

---

## Local algorithm consistency test (no StrongSwan)

```bash
make test
./bin/test_proposals   # validates demo SA blob transform IDs
```
