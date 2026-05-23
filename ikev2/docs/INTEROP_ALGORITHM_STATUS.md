# Interop & Algorithm Test Status

Required vs optional scenario list: **[INTEROP.md](INTEROP.md#required-vs-optional-scenarios)**.

## Summary

| Layer | Automated (lab) | Manual (StrongSwan + openiked) |
|-------|-----------------|--------------------------------|
| IKE_SA_INIT UDP flow via `ike-lb` | **PASS** | Not run |
| SPI stickiness / multi-backend | **PASS** | Not run |
| SA payload present (demo stub) | **PASS** | Not run |
| **Algorithm negotiation with real peer** | **NOT TESTED** | Required |
| IKE_AUTH + certificates/PSK | **NOT TESTED** | Required |
| CHILD_SA / ESP (aes256gcm16-ecp256) | **NOT TESTED** | Required |
| NAT-T UDP 4500 | **NOT TESTED** | Required (S-04) |
| Mismatched proposal on one backend | **NOT TESTED** | Required (S-03) |

**Conclusion:** Load-balancer **message flow** is tested; full **StrongSwan ↔ OpenIKED algorithm interop** is documented but **not executed** in this environment (no `iked` / `charon` installed in CI).

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
