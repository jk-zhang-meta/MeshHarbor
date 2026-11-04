#!/usr/bin/env bash
#
# peer-relay-port-audit-cron.sh — FR-19 weekly relay-firewall drift audit.
#
# Pushes the canonical peer-relay-port-audit.sh to each relay-serving node and
# runs `explain`, then files a GitHub issue on drift. Mirrors the deploy repo's
# mediasoup-rtc-forwarding-audit.sh, but over **Fleet RPC (`mh exec`)**
# instead of ssh/scp: a relay host such as scw-m2-asahi is a Scaleway box that
# is NOT on the cluster SSH-CA, so the mesh's own control plane is the reach.
#
# Why: the relay port rule is host-local firewall state invisible to ArgoCD and
# the app. When it drifts (closed, or DNAT-stolen — the mars class), the relay
# binds a socket and answers nothing: members fall back to DERP/TURN and the pod
# is never offloaded, silently. This audit is the guard.
#
# Requires: a `mh` CLI that can reach a permitted-to-originate daemon, and
# `gh`. ⚠️ `mh exec` needs NO user token — the LOCAL daemon relays it over
# its own server connection (the SERVER authorizes: org kill-switch + the
# originating device's permission + the target's policy + the target's own
# `exec_enabled`). So the only requirement on the cron host is that the CLI can
# reach its daemon's LocalAPI socket (root-owned) and that daemon is permitted to
# originate. LIVE HOME: mars — set `MESHHARBOR_EXEC="sudo -n mh exec"` (its
# daemon runs as root, and gjovanov has passwordless sudo + gh + the sibling
# mediasoup cron). Prove the fire path without issue churn: `DRY_RUN=1 PEER_RELAY_PORT=3479`.
#
# Env: PEER_RELAY_PORT (default 3478), PEER_RELAY_AGENTS ("label=agent-id …"),
#      MESHHARBOR_EXEC (default "mh exec"; "sudo -n mh exec" on mars),
#      DRY_RUN=1 (log "WOULD file issue" instead of creating one).

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
CANON="$DIR/peer-relay-port-audit.sh"
PORT="${PEER_RELAY_PORT:-3478}"
DRY="${DRY_RUN:-0}"
# How to invoke Fleet RPC. Default assumes a root-context CLI; on mars (cron runs
# as gjovanov) set MESHHARBOR_EXEC="sudo -n mh exec" — no user token is needed,
# the local root-owned daemon relays it.
MESHHARBOR_EXEC="${MESHHARBOR_EXEC:-mh exec}"
# Relay-serving agents: label=agent-id. Expand this as relays are approved.
AGENTS="${PEER_RELAY_AGENTS:-scw-m2-asahi=6a7f91d64f1248bba31904ce}"
LOG_DIR="${LOG_DIR:-$HOME/peer-relay-port-audit}"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/latest.log"
: > "$LOG"

[ -r "$CANON" ] || { echo "FATAL: canonical check not found at $CANON" | tee -a "$LOG"; exit 3; }
B64="$(base64 -w0 "$CANON")"

FAILED=""
for entry in $AGENTS; do
  name="${entry%%=*}"
  aid="${entry#*=}"
  echo "=== $name ($aid) port=$PORT $(date -u +%FT%TZ) ===" >> "$LOG"
  # Push the check over the control WS, run it as root, clean up, propagate rc.
  if ! $MESHHARBOR_EXEC "$aid" \
        "printf '%s' '$B64' | base64 -d > /tmp/pra.sh && sudo bash /tmp/pra.sh explain $PORT; rc=\$?; rm -f /tmp/pra.sh; exit \$rc" \
        >> "$LOG" 2>&1; then
    FAILED="$FAILED $name(drift)"
  fi
done

if [ -n "$FAILED" ]; then
  echo "AUDIT FAILED:$FAILED" >> "$LOG"
  TITLE="FR-19 peer-relay port drift:$FAILED"
  BODY="$(printf 'Weekly audit: the UDP relay port %s is not admitted by a SCOPED rule (or is DNAT-consumed) on:%s\n\nA relay there binds a socket and answers nothing — members fall back to DERP/TURN and the API pod is not offloaded, silently.\n\nFix: open a scoped `%s/udp` rule with no DNAT stealing it. Check: `scripts/peer-relay-port-audit.sh`.\n\nLog tail:\n```\n%s\n```' "$PORT" "$FAILED" "$PORT" "$(tail -40 "$LOG")")"
  if [ "$DRY" = 1 ]; then
    echo "[DRY_RUN] WOULD file GitHub issue: $TITLE" | tee -a "$LOG"
  elif command -v gh > /dev/null 2>&1 && gh auth status > /dev/null 2>&1; then
    gh issue create --repo jk-zhang-meta/MeshHarbor --title "$TITLE" --body "$BODY" >> "$LOG" 2>&1 \
      || echo "gh issue creation failed" >> "$LOG"
  else
    echo "gh unavailable — drift NOT reported" >> "$LOG"
  fi
  exit 1
fi
echo "AUDIT OK $(date -u +%FT%TZ)" >> "$LOG"
