#!/usr/bin/env bash
#
# peer-relay-port-audit.sh — FR-19 relay-host firewall drift guard.
#
# A peer relay (docs/fr/FR-19-peer-relays.md) forwards ciphertext for other
# tenant nodes over UDP on its relay port (default 3478). If the relay host's
# firewall does not admit that port — OR admits it but a DNAT/redirect steals
# it upstream of the socket — the relay binds a socket and answers nothing:
# `mh status` reads "bound — NOT yet proven reachable" and every member's
# reachability probe silently fails. This script is the drift guard. It asserts,
# on the relay host itself, that the port is admitted by a rule that NAMES the
# port (SCOPED, not merely a permissive policy) AND that nothing DNATs it away.
# Modelled on the deploy repo's mediasoup-rtc-forwarding.sh.
#
# Usage:
#   peer-relay-port-audit.sh check   [PORT]   # exit 0 iff the port is relay-ready
#   peer-relay-port-audit.sh explain [PORT]   # same, but always prints findings
#
# PORT defaults to 3478. Override via the argument or $PORT.
#
# Exit codes:
#   0  a scoped UDP-PORT allow rule is present and nothing DNATs the port
#   1  the port is NOT admitted (closed / no matching rule)          ← drift
#   2  admitted only by a blanket allow-all policy (present, NOT scoped: §884)
#   4  admitted by the filter but a DNAT/redirect CONSUMES it upstream of the
#      socket (e.g. a coturn COTURN_DNAT on 3478 — this is why a cluster node
#      like mars cannot host a relay on 3478 even though 3478 "looks" open)
#   3  no supported firewall backend found (cannot make a determination)
#
# The weekly cron on the build host pushes this over the overlay mesh to each
# relay-serving host and files a GitHub issue when the exit code is non-zero
# (see docs/fr/FR-19-peer-relays.md §Operations). Run it by hand any time.

set -uo pipefail

MODE="${1:-check}"
PORT="${2:-${PORT:-3478}}"
EXPLAIN=0
[ "$MODE" = "explain" ] && EXPLAIN=1

say()  { [ "$EXPLAIN" = 1 ] && echo "$@" || true; }
fail() { echo "peer-relay-port-audit: $1" >&2; exit "$2"; }

case "$PORT" in
  ''|*[!0-9]*) fail "PORT must be numeric, got '$PORT'" 3 ;;
esac

# A port inside an nft/iptables set literal `{ ..., PORT, ... }` or standalone.
PSET="($PORT|\{[^}]*[[:space:],{]$PORT[[:space:],}]}?[^}]*\})"

# ── firewalld ────────────────────────────────────────────────────────────────
# firewalld is a filter-only front here (the cluster's DNAT lives in raw
# iptables/nft, checked below). Scoped = an explicit `<port>/udp` in the active
# zone. present-but-not-scoped = the zone target is ACCEPT with no such port.
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  zone="$(firewall-cmd --get-default-zone 2>/dev/null)"
  ports="$(firewall-cmd --zone="$zone" --list-ports 2>/dev/null)"
  fwd="$(firewall-cmd --zone="$zone" --list-forward-ports 2>/dev/null)"
  say "backend=firewalld zone=$zone ports=[$ports] forward-ports=[$fwd]"
  # A forward-port that redirects our port elsewhere is a consuming DNAT.
  if printf '%s\n' "$fwd" | grep -Eq "port=$PORT:proto=udp:toport="; then
    fail "$PORT/udp is redirected by a firewalld forward-port (consumed upstream)" 4
  fi
  if printf ' %s ' "$ports" | grep -qw "$PORT/udp"; then
    say "OK: $PORT/udp is an explicit (scoped) rule in zone $zone"
    exit 0
  fi
  target="$(firewall-cmd --zone="$zone" --get-target 2>/dev/null)"
  say "no scoped $PORT/udp rule; zone target=${target:-default}"
  [ "$target" = "ACCEPT" ] && fail "$PORT/udp admitted only by a blanket zone target=ACCEPT (present, NOT scoped)" 2
  fail "$PORT/udp is NOT admitted by zone $zone (closed)" 1
fi

# ── nftables ─────────────────────────────────────────────────────────────────
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
  ruleset="$(nft list ruleset 2>/dev/null)"
  say "backend=nftables"
  # A DNAT/redirect on the port consumes it before the relay socket. Check
  # FIRST: a filter 'accept' is meaningless if prerouting steals the packet.
  if printf '%s\n' "$ruleset" | grep -Eiq "udp dport $PSET .*(dnat|redirect)"; then
    say "found udp/$PORT dnat/redirect (nat hook)"
    fail "udp/$PORT is consumed by a DNAT/redirect upstream of the socket" 4
  fi
  # Scoped accept: a rule that names udp dport PORT and accepts. (grep is
  # line-oriented, so `.*` spans the rest of the line, never a newline.)
  if printf '%s\n' "$ruleset" | grep -Eiq "udp dport $PSET .*accept"; then
    say "OK: nft rule accepts udp dport $PORT (scoped)"
    exit 0
  fi
  if printf '%s\n' "$ruleset" | grep -Eiq "type filter hook input .*policy accept"; then
    fail "udp/$PORT admitted only by an input chain 'policy accept' (present, NOT scoped)" 2
  fi
  fail "no nft rule accepts udp dport $PORT (closed)" 1
fi

# ── iptables (legacy) ────────────────────────────────────────────────────────
if command -v iptables >/dev/null 2>&1 && iptables -S >/dev/null 2>&1; then
  filt="$(iptables -S 2>/dev/null)"
  nat="$(iptables -t nat -S 2>/dev/null)"
  say "backend=iptables"
  if printf '%s\n' "$nat" | grep -Eiq -- "-p udp .*--dport $PORT .*-j (DNAT|REDIRECT)"; then
    fail "udp/$PORT is consumed by a nat -j DNAT/REDIRECT upstream of the socket" 4
  fi
  if printf '%s\n' "$filt" | grep -Eiq -- "-p udp .*--dport $PORT( |,|:).*-j ACCEPT|-p udp .*--dport $PORT -j ACCEPT"; then
    say "OK: iptables ACCEPTs udp --dport $PORT (scoped)"
    exit 0
  fi
  policy="$(printf '%s\n' "$filt" | grep -E '^-P INPUT ' | awk '{print $3}')"
  say "no scoped udp/$PORT ACCEPT; INPUT policy=${policy:-?}"
  [ "$policy" = "ACCEPT" ] && fail "udp/$PORT admitted only by INPUT policy ACCEPT (present, NOT scoped)" 2
  fail "udp/$PORT is NOT admitted (INPUT policy=${policy:-?}, no scoped rule)" 1
fi

fail "no supported firewall backend (firewalld/nft/iptables) found — cannot audit" 3
