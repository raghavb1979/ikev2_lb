# IKEv2 Load Balancer (Hub–Spoke)

IKE-aware UDP load balancer for **[openiked-portable](https://github.com/openiked/openiked-portable)** hubs with **StrongSwan** spoke interop.

| Document | Purpose |
|----------|---------|
| [docs/DESIGN.md](docs/DESIGN.md) | HLD / LLD, topology, SPI stickiness |
| [docs/INTEROP.md](docs/INTEROP.md) | StrongSwan + OpenIKED config; required vs optional scenarios |
| [docs/README.md](docs/README.md) | Documentation index (all docs) |
| [docs/SUBMISSION_REPORT.md](docs/SUBMISSION_REPORT.md) | Steps + prompt log (PDF/PPTX via `make submission-docs`) |

## Architecture (summary)

```
StrongSwan spokes  -->  Hub VIP (ike-lb)  -->  iked@hub1, iked@hub2, ...
                              |
                    SPI-based sticky sessions
```

- Deploy **`iked`** from openiked-portable on each hub backend.
- Run **`ike-lb`** on the hub VIP (UDP 500 / 4500).
- Spokes (StrongSwan) use the VIP as `remote_addrs`.

## Build

```bash
make IKEV2_NO_SSL=1          # or `make` with openssl-devel
make show-config             # print LB capacity settings
```

**Load balancer capacity (build-time, current defaults):**

| Variable | Default | Meaning |
|----------|---------|---------|
| `IKE_LB_MAX_SESSIONS` | `65536` | Max concurrent IKE sessions |
| `IKE_LB_MAX_BACKENDS` | `32` | Max `iked` backends in pool |
| `IKE_LB_SESSION_TIMEOUT` | `3600` | Idle session slot timeout (seconds) |

```bash
# Example: smaller table for embedded hub
make IKEV2_NO_SSL=1 IKE_LB_MAX_SESSIONS=4096 IKE_LB_MAX_BACKENDS=8
```

Binaries: `bin/ike-lb`, `bin/ikev2-server`, `bin/ikev2-client`, `bin/test_ike_msg`

## Run load balancer

```bash
cp config/ike-lb.conf.example config/ike-lb.conf
# edit backends to your iked hosts
./bin/ike-lb config/ike-lb.conf
```

## Testing (E2E + tcpdump)

```bash
make test-all              # unit + basic E2E
make test-e2e-pcap         # 3x IKE_SA_INIT (+ pcap if permitted)
make test-e2e-multi        # 5 sessions across backends
sudo ./scripts/run_e2e_tcpdump.sh   # capture on lo → docs/output/pcap/
./scripts/analyze_ike_pcap.sh docs/output/pcap/ike_e2e_*.pcap
./scripts/tcpdump_examples.sh       # manual capture reference
```

See [docs/TEST_PLAN.md](docs/TEST_PLAN.md) (tests I-04, I-05, P-01–P-03).

## Lab without openiked

Use demo backends:

```bash
./bin/ikev2-server 127.0.0.1 5001 &
./bin/ikev2-server 127.0.0.1 5002 &
./bin/ike-lb
./bin/ikev2-client 127.0.0.1 5000
```

## Components

| Binary | Role |
|--------|------|
| `ike-lb` | Production-oriented IKE SPI load balancer |
| `ikev2-server` | Minimal IKE_SA_INIT responder for testing |
| `ikev2-client` | Minimal initiator for testing |

## Production notes

- Synchronize `iked.conf` on all backends (proposals, IDs, certs).
- Ensure hub routing: backends reach spoke subnets; return IKE may be direct backend→spoke.
- For co-located LB + `iked`, use TPROXY or separate NICs if reply path must symmetric.

## References

- https://github.com/openiked/openiked-portable
- https://github.com/strongswan/strongswan
- RFC 7296
