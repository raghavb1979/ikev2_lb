# Real interop lab (StrongSwan + optional openiked)

Automated by `scripts/run_interop_real.sh` when dependencies are installed.

## Install (hub + spoke on one Linux lab VM)

```bash
# StrongSwan (spoke and/or hub backends)
sudo dnf install -y strongswan

# openiked (hub backends) — build from upstream, then:
export PATH="/path/to/openiked/install/bin:$PATH"
export IKED_BIN=iked
export IKECTL_BIN=ikectl
```

**Not required:** OpenSSL in `ike-lb` Makefile. Peers terminate IKE/IPsec.

## Modes

| Mode | Backends | Proves |
|------|----------|--------|
| `strongswan` (default if `iked` missing) | 2× `charon` | S-01 IKE_AUTH, ESP ping, S-04 NAT-T |
| `openiked` | 2× `iked` | Same + real openiked interop |

## Run

```bash
sudo ./scripts/run_interop_real.sh
# or
make test-interop-real
```

Results log: `docs/output/interop_real.log`
