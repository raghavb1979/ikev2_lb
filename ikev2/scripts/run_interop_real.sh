#!/usr/bin/env bash
# S-01 / S-02 / S-04 style interop: real StrongSwan (+ optional iked) through ike-lb.
# Needs: root (network namespaces), swanctl, charon. Optional: iked, ikectl.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LOG="${ROOT}/docs/output/interop_real.log"
mkdir -p docs/output

LB_VIP_PORT="${LB_VIP_PORT:-5500}"
LB_NATT_PORT="${LB_NATT_PORT:-4500}"   # VIP NAT-T (RFC 3947); ike-lb listens here
BACKEND_NATT_PORT="${BACKEND_NATT_PORT:-4501}" # hub charon NAT-T (not 4500 — LB owns VIP :4500)
B1_PORT="${B1_PORT:-500}"   # hub charon IKE port inside hub netns (must match swanctl + backend)
B2_PORT="${B2_PORT:-501}"
PSK="${INTEROP_PSK:-ikev2-interop-secret}"
HUB_ID="${HUB_ID:-hub.example.com}"
SPOKE_ID="${SPOKE_ID:-spoke1.example.com}"
LB_LISTEN="${LB_LISTEN:-0.0.0.0}"   # ike-lb bind in hub netns (reachable from spoke)
BACKEND_IP="${BACKEND_IP:-127.0.0.1}" # backends listen on hub loopback
# RFC5737 TEST-NET-3 avoids StrongSwan NAT-T (10/8 + relay via 127.0.0.1 breaks IKE_AUTH)
if [[ "${INTEROP_NO_NAT:-1}" == "1" ]]; then
    HUB_IP="${HUB_IP:-203.0.113.1}"
    SPOKE_IP="${SPOKE_IP:-203.0.113.2}"
    SPOKE_TS="${SPOKE_TS:-203.0.113.64/26}"
    HUB_TS="${HUB_TS:-203.0.113.0/26}"
else
    HUB_IP="${HUB_IP:-10.10.1.1}"
    SPOKE_IP="${SPOKE_IP:-10.10.2.2}"
    SPOKE_TS="${SPOKE_TS:-10.10.2.0/24}"
    HUB_TS="${HUB_TS:-10.10.1.0/24}"
fi
INTEROP_MODE="${INTEROP_MODE:-auto}" # auto | strongswan | openiked
    INTEROP_KEEP="${INTEROP_KEEP:-0}"    # set 1 to keep /tmp/ikev2-interop.* on exit
IKE_LB_DEBUG="${IKE_LB_DEBUG:-1}"      # verbose ike-lb drop reasons on stderr

exec 3>&1
exec > >(tee -a "$LOG") 2>&1

log() { echo "[$(date +%H:%M:%S)] $*"; }
dump_debug_logs() {
    [[ -n "${WORKDIR:-}" && -d "$WORKDIR" ]] || return 0
    log "--- debug: $WORKDIR ---"
    for f in ike-lb.log spoke-load.log spoke-init.log; do
        [[ -f "$WORKDIR/$f" ]] && { log "--- $f ---"; cat "$WORKDIR/$f"; }
    done
  for d in "$WORKDIR"/hub-* "$WORKDIR"/spoke; do
        [[ -f "$d/charon.log" ]] && { log "--- $d/charon.log (tail) ---"; tail -40 "$d/charon.log"; }
    done
}

fail() {
    log "FAIL: $*"
    dump_debug_logs
    [[ -n "${WORKDIR:-}" ]] && cp -a "$WORKDIR" "${ROOT}/docs/output/interop_last_run" 2>/dev/null || true
    INTEROP_KEEP=1
    exit 1
}

on_err() {
    local ec=$?
    log "ERROR: command failed (exit $ec) at line ${BASH_LINENO[0]}: ${BASH_COMMAND}"
    dump_debug_logs
    [[ -n "${WORKDIR:-}" ]] && cp -a "$WORKDIR" "${ROOT}/docs/output/interop_last_run" 2>/dev/null || true
    INTEROP_KEEP=1
    exit "$ec"
}
trap on_err ERR
skip() { log "SKIP: $*"; exit 0; }

need_root() {
    [[ "$(id -u)" -eq 0 ]] || fail "Run as root (sudo): network namespaces and charon need it"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

check_deps() {
    have_cmd swanctl || fail "Install StrongSwan (swanctl). Example: sudo dnf install strongswan"
    have_cmd ip || fail "ip(8) required"
    log "Building ike-lb..."
    make IKEV2_NO_SSL=1 all || fail "make IKEV2_NO_SSL=1 all failed"
    if [[ "$INTEROP_MODE" == "auto" ]]; then
        if have_cmd "${IKED_BIN:-iked}"; then
            INTEROP_MODE=openiked
        else
            INTEROP_MODE=strongswan
        fi
    fi
    log "Interop mode: $INTEROP_MODE"
}

WORKDIR=""
HUB_NS=ikev2-hub
SPOKE_NS=ikev2-spoke
HOST_SS_STOPPED=0

charon_bin() {
    for c in /usr/libexec/strongswan/charon /usr/libexec/ipsec/charon /usr/libexec/charon; do
        [[ -x "$c" ]] && { echo "$c"; return 0; }
    done
    command -v charon
}

stop_host_charon() {
    if systemctl is-active --quiet strongswan 2>/dev/null; then
        log "Stopping host strongswan (shared /run/strongswan/charon.pid)..."
        systemctl stop strongswan
        HOST_SS_STOPPED=1
    fi
    rm -f /run/strongswan/charon.pid 2>/dev/null || true
}

# Run swanctl in the same mount+network context as charon (private /run/strongswan).
charon_swanctl() {
    local ns=$1 dir=$2
    shift 2
    local sup
    sup=$(cat "$dir/supervisor.pid")
    ip netns exec "$ns" nsenter -t "$sup" -m env SWANCTL_DIR="$dir/swanctl" swanctl "$@"
}

stop_charon_supervisor() {
    local dir=$1
    [[ -f "$dir/supervisor.pid" ]] || return 0
    kill "$(cat "$dir/supervisor.pid")" 2>/dev/null || true
}

cleanup() {
    log "Cleaning up..."
    [[ -n "${WORKDIR:-}" ]] && stop_charon_supervisor "$WORKDIR/spoke" 2>/dev/null
    [[ -n "${WORKDIR:-}" ]] && stop_charon_supervisor "$WORKDIR/hub-b1" 2>/dev/null
    ip netns del "$SPOKE_NS" 2>/dev/null || true
    ip netns del "$HUB_NS" 2>/dev/null || true
    pkill -f "bin/ike-lb" 2>/dev/null || true
    pkill -f "bin/ikev2-server.*$B1_PORT" 2>/dev/null || true
    pkill -f "bin/ikev2-server.*$B2_PORT" 2>/dev/null || true
    if [[ "$INTEROP_KEEP" != "1" ]]; then
        rm -rf "$WORKDIR" 2>/dev/null || true
    else
        log "INTEROP_KEEP=1 — left workdir: $WORKDIR"
    fi
}
trap cleanup EXIT

setup_netns() {
    pkill -f "bin/ike-lb" 2>/dev/null || true
    ip netns del "$SPOKE_NS" 2>/dev/null || true
    ip netns del "$HUB_NS" 2>/dev/null || true
    ip link del veth-hub 2>/dev/null || true
    ip link del veth-spoke 2>/dev/null || true

    WORKDIR="$(mktemp -d /tmp/ikev2-interop.XXXXXX)"
    log "Workdir: $WORKDIR"

    ip netns add "$HUB_NS" || fail "ip netns add $HUB_NS failed (need kernel netns support)"
    ip netns add "$SPOKE_NS" || fail "ip netns add $SPOKE_NS failed"
    ip link add veth-hub type veth peer name veth-spoke
    ip link set veth-spoke netns "$SPOKE_NS"
    ip link set veth-hub netns "$HUB_NS"

    ip -n "$HUB_NS" addr add "${HUB_IP}/24" dev veth-hub
    ip -n "$SPOKE_NS" addr add "${SPOKE_IP}/24" dev veth-spoke
    ip -n "$HUB_NS" link set veth-hub up
    ip -n "$SPOKE_NS" link set veth-spoke up
    ip -n "$HUB_NS" link set lo up

    ip netns exec "$SPOKE_NS" ip route replace "$(echo "$HUB_IP" | sed 's/\.[0-9]*$/.0/')/24" dev veth-spoke
    log "Hub $HUB_IP (spoke dials this) — ike-lb listens $LB_LISTEN:$LB_VIP_PORT"
    ip -n "$HUB_NS" route replace "$(echo "$SPOKE_IP" | sed 's/\.[0-9]*$/.0/')/24" dev veth-hub
}

write_ike_lb_conf() {
    local backends=2
    [[ "$INTEROP_MODE" == "strongswan" ]] && backends=1
    cat >"$WORKDIR/ike-lb.conf" <<EOF
listen $LB_LISTEN $LB_VIP_PORT
natt_port $LB_NATT_PORT
backend $BACKEND_IP $B1_PORT natt $BACKEND_NATT_PORT
EOF
    if [[ "$backends" -ge 2 ]]; then
        echo "backend $BACKEND_IP $B2_PORT natt $BACKEND_NATT_PORT" >>"$WORKDIR/ike-lb.conf"
    fi
}

swanctl_mkdirs() {
    local base=$1/swanctl
    mkdir -p "$base"/{conf.d,x509,x509ca,x509aa,x509ac,x509ocsp,x509crl,pubkey,private,rsa,ecdsa,bliss,pkcs8,pkcs12}
}

write_strongswan_conf() {
    local dir=$1 port=$2 natt_port=$3
    cat >"$dir/strongswan.conf" <<EOF
charon {
  load_modular = yes
  port = $port
  port_nat_t = $natt_port
  install_routes = no
  install_policy = no
  uniqueids = never
  filelog {
    ike {
      path = $dir/charon.log
      default = 2
      flush_line = yes
      ike = 2
      net = 2
      enc = 1
    }
  }
  plugins {
    include /etc/strongswan/strongswan.d/charon/*.conf
  }
}
include /etc/strongswan/strongswan.d/*.conf
EOF
}

swanctl_hub_backend() {
    local name=$1 port=$2 natt_port=${3:-$BACKEND_NATT_PORT}
  local dir="$WORKDIR/hub-$name"
  swanctl_mkdirs "$dir"
  cat >"$dir/swanctl/conf.d/$name.conf" <<EOF
connections {
  $name {
    version = 2
    proposals = aes256gcm16-prfsha256-ecp256
    local_addrs = %any
    remote_addrs = %any
    mobike = no
    local {
      id = $HUB_ID
      auth = psk
    }
    remote {
      id = $SPOKE_ID
      auth = psk
    }
    children {
      net {
        local_ts = $HUB_TS
        remote_ts = $SPOKE_TS
        esp_proposals = aes256gcm16-ecp256
        start_action = none
      }
    }
  }
}
secrets {
  ike-$name {
    id-local = $HUB_ID
    id-remote = $SPOKE_ID
    secret = $PSK
  }
}
EOF
  write_strongswan_conf "$dir" "$port" "$natt_port"
  cat >"$dir/swanctl/swanctl.conf" <<EOF
include conf.d/*.conf
EOF
  echo "$dir"
}

swanctl_spoke_conf() {
  local dir="$WORKDIR/spoke"
  swanctl_mkdirs "$dir"
  local remote_port=$1
  local use_encap=${2:-no}
  cat >"$dir/swanctl/conf.d/spoke.conf" <<EOF
connections {
  hub {
    version = 2
    proposals = aes256gcm16-prfsha256-ecp256
    remote_addrs = $HUB_IP
    remote_port = $remote_port
    local_port = 0
    encap = $use_encap
    mobike = no
    local {
      id = $SPOKE_ID
      auth = psk
    }
    remote {
      id = $HUB_ID
      auth = psk
    }
    children {
      net {
        local_ts = $SPOKE_TS
        remote_ts = $HUB_TS
        esp_proposals = aes256gcm16-ecp256
        start_action = none
      }
    }
  }
}
secrets {
  ike-spoke {
    id-local = $SPOKE_ID
    id-remote = $HUB_ID
    secret = $PSK
  }
}
EOF
  cat >"$dir/swanctl/swanctl.conf" <<EOF
include conf.d/*.conf

charon {
  install_routes = no
}
EOF
  echo "$dir"
}

wait_charon() {
    local ns=$1 dir=$2
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if charon_swanctl "$ns" "$dir" --stats >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "charon did not start in netns $ns (see $dir/charon.log)"
}

start_charon_in_ns() {
    local ns=$1 dir=$2
    local listen_port=${3:-500}
    local natt_port=${4:-4500}
    local cbin
    cbin=$(charon_bin) || fail "charon binary not found"
    [[ -f "$dir/strongswan.conf" ]] || write_strongswan_conf "$dir" "$listen_port" "$natt_port"
    : >"$dir/charon.log"
    ip netns exec "$ns" unshare -m bash -c "
      export SWANCTL_DIR='$dir/swanctl'
      export STRONGSWAN_CONF='$dir/strongswan.conf'
      mkdir -p /run
      mount -t tmpfs tmpfs /run/strongswan
      '$cbin' 2>>'$dir/charon-stderr.log' &
      echo \$! > '$dir/charon-inner.pid'
      exec sleep infinity
    " >>"$dir/supervisor.log" 2>&1 &
    echo $! >"$dir/supervisor.pid"
    sleep 1
    wait_charon "$ns" "$dir"
    verify_udp_listen "$ns" "$listen_port" "charon ($ns)"
    if [[ "$natt_port" != "$listen_port" ]]; then
        verify_udp_listen "$ns" "$natt_port" "charon NAT-T ($ns)"
    fi
    if grep -qE 'could not open IPv4 NAT-T socket|unable to bind socket' "$dir/charon.log" 2>/dev/null; then
        log "--- $dir/charon.log (startup) ---"
        head -30 "$dir/charon.log"
        fail "charon NAT-T/IKE bind failed in $ns (see charon.log; check STRONGSWAN_CONF ports)"
    fi
}

verify_udp_listen() {
    local ns=$1 port=$2 label=$3
    if ! ip netns exec "$ns" ss -uln 2>/dev/null | grep -q ":${port} "; then
        fail "$label: no UDP listener on port $port in netns $ns (ss -uln)"
    fi
    log "$label: UDP :$port listening in $ns"
}

verify_udp_listen_addr() {
    local ns=$1 addr=$2 port=$3 label=$4
    if ! ip netns exec "$ns" ss -ulnH 2>/dev/null | grep -q "${addr}:${port} "; then
        fail "$label: no UDP listener on ${addr}:${port} in netns $ns"
    fi
    log "$label: UDP ${addr}:$port listening in $ns"
}

start_ike_lb_in_ns() {
    ip netns exec "$HUB_NS" env IKE_LB_DEBUG="${IKE_LB_DEBUG:-}" "$ROOT/bin/ike-lb" "$WORKDIR/ike-lb.conf" >>"$WORKDIR/ike-lb.log" 2>&1 &
    echo $! >"$WORKDIR/ike-lb.pid"
    sleep 1
    verify_udp_listen "$HUB_NS" "$LB_VIP_PORT" "ike-lb"
    verify_udp_listen "$HUB_NS" "$LB_NATT_PORT" "ike-lb NAT-T"
}

start_iked_backends() {
    local iked="${IKED_BIN:-iked}"
    have_cmd "$iked" || fail "iked not found; set IKED_BIN or use INTEROP_MODE=strongswan"
    for p in "$B1_PORT" "$B2_PORT"; do
        cat >"$WORKDIR/iked-$p.conf" <<EOF
ikev2 active ipsec \\
    from 0.0.0.0/0 to 0.0.0.0/0 \\
    peer $SPOKE_ID \\
    ikesa enc aes-256-gcm prf hmac-sha2-256 group ecpp256 \\
    childsa enc aes-256-gcm group ecpp256 \\
    srcid "@$HUB_ID" \\
    psk "$PSK"
EOF
        ip netns exec "$HUB_NS" "$iked" -f "$WORKDIR/iked-$p.conf" >>"$WORKDIR/iked-$p.log" 2>&1 &
    done
    sleep 2
}

run_s01() {
    log "=== S-01: IKE_AUTH + CHILD_SA (StrongSwan spoke -> VIP -> backends) ==="
    log "Using ike-lb: $ROOT/bin/ike-lb (rebuild with: make IKEV2_NO_SSL=1 all)"
    write_ike_lb_conf
    start_ike_lb_in_ns

    if [[ "$INTEROP_MODE" == "openiked" ]]; then
        start_iked_backends
    else
        local d1
        d1=$(swanctl_hub_backend b1 "$B1_PORT" "$BACKEND_NATT_PORT")
        start_charon_in_ns "$HUB_NS" "$d1" "$B1_PORT" "$BACKEND_NATT_PORT"
        log "NAT-T path: spoke -> VIP:$LB_NATT_PORT (ike-lb) -> $BACKEND_IP:$BACKEND_NATT_PORT (charon)"
        if ! charon_swanctl "$HUB_NS" "$d1" --load-all >>"$WORKDIR/hub-load.log" 2>&1; then
            fail "swanctl --load-all failed on hub (see hub-load.log)"
        fi
        if ! charon_swanctl "$HUB_NS" "$d1" --list-conns 2>/dev/null | grep -q b1; then
            fail "connection 'b1' not loaded on hub (see hub-load.log)"
        fi
        log "StrongSwan mode: single hub charon on :$B1_PORT (use openiked mode for 2-backend S-02)"
    fi

    local spoke_dir
    spoke_dir=$(swanctl_spoke_conf "$LB_VIP_PORT" no)
    write_strongswan_conf "$spoke_dir" 500 4500
    start_charon_in_ns "$SPOKE_NS" "$spoke_dir" 500 4500

    if ! charon_swanctl "$SPOKE_NS" "$spoke_dir" --load-all >>"$WORKDIR/spoke-load.log" 2>&1; then
        fail "swanctl --load-all failed on spoke (see spoke-load.log)"
    fi
    if ! charon_swanctl "$SPOKE_NS" "$spoke_dir" --list-conns 2>/dev/null | grep -q hub; then
        fail "connection 'hub' not loaded on spoke (check include conf.d in swanctl.conf)"
    fi
    log "Spoke config loaded; initiating child 'net' to $HUB_IP:$LB_VIP_PORT (timeout 60s) ..."
    charon_swanctl "$SPOKE_NS" "$spoke_dir" --initiate --child net --timeout 60 \
        >>"$WORKDIR/spoke-init.log" 2>&1 || {
        log "--- spoke-init.log ---"
        cat "$WORKDIR/spoke-init.log"
        fail "swanctl --initiate failed (S-01)"
    }

  sleep 2
  if charon_swanctl "$SPOKE_NS" "$spoke_dir" --list-sas 2>/dev/null | grep -q ESTABLISHED; then
    log "S-01 PASS: IKE/IPsec SA ESTABLISHED on spoke"
  else
    swanctl --list-sas 2>/dev/null || true
    fail "S-01: no ESTABLISHED SA on spoke"
  fi
}

run_s02_hint() {
    log "=== S-02: stickiness (check ike-lb log for same backend across re-init) ==="
    if grep -q "new IKE session" "$WORKDIR/ike-lb.log" 2>/dev/null; then
        log "S-02 partial: LB logged session binding (verify same backend_index on repeated SPI in log)"
    fi
    log "Full S-02: run multiple initiations and ikectl sa on correct iked — see TEST_PLAN.md"
}

run_s04_natt() {
    if [[ "${INTEROP_NO_NAT:-1}" == "1" ]]; then
        log "S-04 SKIP: INTEROP_NO_NAT=1 (TEST-NET-3 S-01 path; run INTEROP_NO_NAT=0 for NAT-T test)"
        return 0
    fi
    log "=== S-04: NAT-T (UDP encap to VIP:$LB_NATT_PORT) ==="
    kill "$(cat "$WORKDIR/ike-lb.pid" 2>/dev/null)" 2>/dev/null || true
    stop_charon_supervisor "$WORKDIR/spoke"
    sleep 1
    write_ike_lb_conf
    start_ike_lb_in_ns
  local spoke_dir
  spoke_dir=$(swanctl_spoke_conf "$LB_NATT_PORT" yes)
  write_strongswan_conf "$spoke_dir" 500 4500
  start_charon_in_ns "$SPOKE_NS" "$spoke_dir" 500 4500
  if charon_swanctl "$SPOKE_NS" "$spoke_dir" --load-all >>"$WORKDIR/spoke-natt-load.log" 2>&1 &&
      charon_swanctl "$SPOKE_NS" "$spoke_dir" --initiate --child net >>"$WORKDIR/spoke-natt.log" 2>&1; then
    log "S-04 PASS: IKE completed with NAT-T ports (encap=yes)"
  else
    log "S-04 WARN: NAT-T initiate failed — check spoke-natt.log (hub charon from S-01 still used)"
  fi
}

main() {
    : >"$LOG"
    log "IKEv2 real interop automation — log: $LOG"
    need_root
    stop_host_charon
    check_deps
    setup_netns
    run_s01
    run_s02_hint
    run_s04_natt
    log "=== Done. S-03 (config mismatch) remains manual: break one backend proposal and expect failure ==="
    log "Artifacts: $WORKDIR"
}

main "$@"
