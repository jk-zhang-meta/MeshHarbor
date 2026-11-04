#!/usr/bin/env bash
# Provision a relay PoP (coturn + derp-relay + SNI nginx) on a fresh
# Debian/Ubuntu VPS. Idempotent — re-run after editing pop.env.
#
# Prereqs (see README.md):
#   1. DNS A records for COTURN_HOST + DERP_HOST -> this VPS.
#   2. /opt/relay-pop/pop.env filled in (copy pop.env.example).
#   3. /opt/relay-pop/bin/derp-relay — the Linux binary
#      (cargo build -p derp-relay --release on the build host, scp here).
#   4. This directory's templates + compose file copied to /opt/relay-pop.
set -euo pipefail

POP=/opt/relay-pop
[ -f "$POP/pop.env" ] || { echo "ERROR: $POP/pop.env missing (copy pop.env.example)"; exit 1; }
[ -x "$POP/bin/derp-relay" ] || { echo "ERROR: $POP/bin/derp-relay missing/not executable"; exit 1; }
set -a; . "$POP/pop.env"; set +a
for v in REGION COTURN_HOST DERP_HOST PUBLIC_IP TURN_SHARED_SECRET DERP_TICKET_PUBLIC_KEY; do
  [ -n "${!v:-}" ] && [ "${!v}" != "CHANGE-ME" ] || { echo "ERROR: $v not set in pop.env"; exit 1; }
done

echo "== relay-pop provision: region=$REGION coturn=$COTURN_HOST derp=$DERP_HOST"

# ── base packages ────────────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 curl socat gettext-base \
  iptables-persistent >/dev/null
systemctl enable --now docker >/dev/null

# ── sysctl: UDP buffers for sustained relaying ───────────────────────────────
cat >/etc/sysctl.d/90-relay-pop.conf <<'EOF'
net.core.rmem_max=8388608
net.core.wmem_max=8388608
net.core.rmem_default=1048576
net.core.wmem_default=1048576
EOF
sysctl -q --system

# ── iptables: UDP/443 -> coturn 3478 (corp firewalls pass UDP/443 as QUIC).
# DNAT preserves the client source address — mandatory for TURN. Same
# pattern as the fleet workers (scripts/coturn-patch-workers.py).
iptables -t nat -C PREROUTING -d "$PUBLIC_IP" -p udp --dport 443 \
  -j DNAT --to-destination "$PUBLIC_IP":3478 2>/dev/null || \
iptables -t nat -A PREROUTING -d "$PUBLIC_IP" -p udp --dport 443 \
  -j DNAT --to-destination "$PUBLIC_IP":3478
# coturn's prometheus exporter (:9641) binds every interface and has no
# listen-address option — keep it loopback-only (derp-relay's /stats scrape).
iptables -C INPUT -p tcp --dport 9641 ! -i lo -j DROP 2>/dev/null || \
iptables -A INPUT -p tcp --dport 9641 ! -i lo -j DROP
netfilter-persistent save >/dev/null

# ── TLS: acme.sh HTTP-01 standalone on :80, one cert covering both names ────
mkdir -p "$POP/certs"
if [ ! -d "$HOME/.acme.sh" ]; then
  curl -s https://get.acme.sh | sh -s email="ops@${COTURN_HOST#*.}" >/dev/null
fi
ACME="$HOME/.acme.sh/acme.sh"
if [ ! -f "$POP/certs/fullchain.pem" ]; then
  "$ACME" --issue --standalone -d "$COTURN_HOST" -d "$DERP_HOST" --server letsencrypt
  "$ACME" --install-cert -d "$COTURN_HOST" \
    --fullchain-file "$POP/certs/fullchain.pem" \
    --key-file "$POP/certs/key.pem" \
    --reloadcmd "cd $POP && docker compose -f docker-compose.pop.yml restart coturn nginx"
  chmod 644 "$POP/certs/"*.pem   # containers run unprivileged users
fi

# ── render configs ───────────────────────────────────────────────────────────
if [ -n "${PRIVATE_IP:-}" ]; then
  export EXTERNAL_IP_LINE="external-ip=${PUBLIC_IP}/${PRIVATE_IP}"
  export RELAY_IP="${PRIVATE_IP}"
else
  export EXTERNAL_IP_LINE="# external-ip not needed (public IP bound directly)"
  export RELAY_IP="${PUBLIC_IP}"
fi
envsubst < "$POP/turnserver.conf.tpl" > "$POP/turnserver.conf.new"
if cmp -s "$POP/turnserver.conf.new" "$POP/turnserver.conf" 2>/dev/null; then
  rm -f "$POP/turnserver.conf.new"
else
  mv "$POP/turnserver.conf.new" "$POP/turnserver.conf"
  COTURN_CONF_CHANGED=1
fi
envsubst '${REGION} ${COTURN_HOST} ${DERP_HOST}' \
  < "$POP/nginx-pop.conf.tpl" > "$POP/nginx-pop.conf"

# ── start / refresh the stack ────────────────────────────────────────────────
cd "$POP"
docker compose -f docker-compose.pop.yml up -d
# `up -d` won't bounce coturn for a changed bind-mounted config — do it
# explicitly, but only when the rendered config actually changed.
if [ -n "${COTURN_CONF_CHANGED:-}" ]; then
  docker compose -f docker-compose.pop.yml restart coturn
fi
docker compose -f docker-compose.pop.yml ps

echo "== done. Verify from anywhere:"
echo "   python3 scripts/relay-pop/healthcheck.py $REGION=$COTURN_HOST:3478,$DERP_HOST"
echo "   (then append the region to MESHHARBOR__RELAY__REGIONS and redeploy the web)"
