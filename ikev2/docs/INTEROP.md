# StrongSwan ↔ OpenIKED (Hub VIP + Load Balancer)

## Required vs optional scenarios

Use this table for design reviews and submission scope. **IKE interop** (structure + algorithms) is mandatory; other rows are part of a **complete hub–spoke deployment** but not all must be implemented inside `ike-lb`.

### IKE control plane (protocol interop)

| Scenario | Priority | Owner / component | Notes |
|----------|----------|-------------------|--------|
| IKEv2 message structure (RFC 7296 header, payloads) | **Required** | `ike-lb`, both peers | LB must parse SPIs and forward intact UDP payloads |
| IKE_SA_INIT exchange | **Required** | StrongSwan ↔ openiked | First hop through VIP; starts session stickiness |
| IKE_AUTH exchange | **Required** | StrongSwan ↔ openiked | Same backend as SA_INIT for same SPI pair |
| CREATE_CHILD_SA / rekey | **Required** | StrongSwan ↔ openiked | Still same IKE SA → same `iked` backend |
| Algorithm proposals (ENCR, PRF, INTEG, DH/ECP) | **Required** | Config on **all** hub backends + spoke | Must match (see config below) |
| IKE IDs + auth method (cert or PSK) | **Required** | `swanctl` + `iked.conf` | Failure here is not an LB bug |
| NAT-T (UDP 4500, non-ESP marker) | **Required** if spokes behind NAT | Spoke + hub firewall | LB should listen on 4500 as well as 500 |
| Hub VIP only on spokes (`remote_addrs`) | **Required** | Spoke config | Never point spokes at individual backend IPs |
| SPI session stickiness on `ike-lb` | **Required** | `ike-lb` | Core deliverable for this project |
| Identical `iked.conf` on every backend | **Required** | Operations | Any mismatch breaks “any backend” model |

### Load balancer & hub topology (not algorithm bytes, still required)

| Scenario | Priority | Owner / component | Notes |
|----------|----------|-------------------|--------|
| Hub–spoke topology (spoke → hub) | **Required** | Network design | Typical: StrongSwan client, hub server |
| UDP relay / asymmetric return path | **Required** | `ike-lb` + routing | Initiator always to VIP; reply may be backend → spoke |
| Backend health / removal from pool | **Recommended** | Ops / future LB | Existing IKE SAs break if backend dies mid-session |
| `ike-lb` HA (VIP failover) | **Optional** | Infra | Separate from pooling across `iked` instances |
| IKE Redirect / NOTIFY redirect | **Optional** | Standards alternative | Not used in current `ike-lb` design |

### IPsec data plane & network (after IKE succeeds)

| Scenario | Priority | Owner / component | Notes |
|----------|----------|-------------------|--------|
| CHILD_SA / ESP installation | **Required** for real VPN | Kernel + `iked` / charon | **Out of scope** for `ike-lb` code |
| ESP algorithms (`esp_proposals`) | **Required** for real VPN | Config | Align with IKE (e.g. aes256gcm16-ecp256) |
| Routing (spoke LAN ↔ hub prefixes) | **Required** for traffic | Routers / hub | Not handled by LB |
| Firewall: UDP 500/4500, ESP (proto 50) | **Required** | Network | Allow hub↔spoke return path |
| DPD / liveness | **Recommended** | StrongSwan / iked | Detect dead peers |
| MOBIKE | **Optional** | Spoke config | Only if spokes change public IP |
| PFS / rekey policies | **Optional** | Policy | Document if enterprise policy requires |

### Roles & deployment variants

| Scenario | Priority | Notes |
|----------|----------|--------|
| StrongSwan spoke → openiked hub (default) | **Required** for this project | Config examples below |
| StrongSwan hub server, openiked spoke | **Optional** | Same SPI stickiness; mirror configs |
| PSK instead of certificates | **Optional** | Still **required** to match on both sides |
| Many spokes, many hubs (scale) | **Required** to mention | Session limits, config automation |

### Testing expectations (see [TEST_PLAN.md](TEST_PLAN.md))

| Scenario | Lab (`ikev2-*` demo) | Production validation |
|----------|----------------------|------------------------|
| IKE structure + SA_INIT via LB | Automated PASS | S-01 PASS |
| IKE_AUTH + CHILD_SA (PSK, ecp256) | Not in demo | **S-01 automated PASS** (`run_interop_real.sh`) |
| ESP + ping | Not in demo | Manual |
| NAT-T (`10.10.x`, encap) | Not in demo | S-04 — use `INTEROP_NO_NAT=0`; open item |
| Backend proposal mismatch | Not in demo | Manual S-03 |

Algorithm test status detail: [INTEROP_ALGORITHM_STATUS.md](INTEROP_ALGORITHM_STATUS.md).

---

## Hub–spoke (typical): StrongSwan spoke → hub VIP

### StrongSwan (`swanctl.conf` on spoke)

```
connections {
  hub {
    version = 2
    proposals = aes256gcm16-prfsha256-ecp256
    remote_addrs = 203.0.113.10   # hub IKE VIP (ike-lb)

    local {
      id = spoke1.example.com
      auth = pubkey
      certs = spoke1.crt
    }
    remote {
      id = hub.example.com
      auth = pubkey
    }

    children {
      net {
        local_ts  = 10.1.0.0/24
        remote_ts = 10.0.0.0/8
        esp_proposals = aes256gcm16-ecp256
        start_action = trap
      }
    }
  }
}
```

Enable NAT-T if spokes are behind NAT:

```
connections.hub.local_port = 4500
connections.hub.remote_port = 4500
connections.hub.encap = yes
connections.hub.mobike = no
```

### OpenIKED (`iked.conf` on each hub backend — must match)

Use the **same** proposals and IDs on **every** backend:

```
ikev2 active ipsec \
    from 0.0.0.0/0 to 0.0.0.0/0 \
    peer hub.example.com \
    ikesa enc aes-256-gcm prf hmac-sha2-256 group ecpp256 \
    childsa enc aes-256-gcm group ecpp256 \
    srcid "@hub.example.com" \
    psk "shared-or-use-certs"
```

Point `iked` at the backend interface IP. Spokes never connect to backend IPs directly—only the VIP in front of `ike-lb`.

### StrongSwan as IKE server (less common on hub)

If the **hub** runs StrongSwan and spokes run OpenIKED:

- Place `ike-lb` (or HAProxy UDP stickiness on SPI) in front of multiple `charon` instances.
- Same SPI stickiness rules apply.
- Mirror proposal strings between `iked.conf` and `swanctl.conf`.

## Checklist before go-live

### Required

- [ ] Identical IKE/ESP proposals on all hub backends (algorithms in table above)
- [ ] Same authentication material (cert/PSK) and IKE IDs on all backends
- [ ] Spoke `remote_addrs` = hub VIP only (not backend IPs)
- [ ] `ike-lb` on VIP; SPI stickiness verified under load
- [ ] UDP 500 and 4500 allowed to VIP; hub→spoke return path for IKE and ESP
- [ ] Hub backends have routes to all spoke LANs
- [ ] `swanctl --initiate --child net` completes IKE_SA_INIT + IKE_AUTH + CHILD_SA
- [ ] Repeat initiation: same SPI pair stays on one backend (`ikectl sa` / logs)

### Recommended

- [ ] NAT-T tested if any spoke is behind NAT
- [ ] DPD / tunnel liveness configured
- [ ] Config management (Ansible/Git) keeps all `iked.conf` files identical

### Optional

- [ ] MOBIKE (mobile spokes)
- [ ] `ike-lb` VIP HA (keepalived / VRRP)
- [ ] IKE Redirect instead of transparent LB
- [ ] StrongSwan-as-hub role (reverse roles)

**Real-world test mapping:** [PRACTICALITY.md](PRACTICALITY.md) (lab vs production flows, S-01–S-04).

## References

- [openiked-portable](https://github.com/openiked/openiked-portable)
- [StrongSwan](https://github.com/strongswan/strongswan)
- RFC 7296 (IKEv2)
