#!/usr/bin/env bash
# Single source of truth for the licence split (FR-24).
#
# Every other consumer — scripts/apply-spdx.sh, the licensing CI workflow, the
# `license` field audit — sources this file. The point is that changing the
# server licence later (to FSL-1.1-ALv2 or BUSL-1.1, say) is editing ONE line
# here plus the licence text file, not a sweep through the tree.
#
# The classification below is derived from the workspace dependency graph, not
# from intuition about what a crate is "for". The rule that produced it:
#
#   A crate compiled into BOTH the server and a shipped agent binary must take
#   the CLIENT licence. Otherwise the agent inherits the server's copyleft, and
#   an AGPL binary on a customer endpoint is a procurement blocker.
#
# That is why tunnel-core / remote_control / localapi / tcp-turn-conn are MPL
# despite `crates/api` linking all four. See LICENSING.md.

set -euo pipefail

# ── The licences ──────────────────────────────────────────────────────────────
SERVER_LICENCE="AGPL-3.0-only"
CLIENT_LICENCE="MPL-2.0"
DOCS_LICENCE="CC-BY-4.0"

COPYRIGHT_HOLDER="G ROX EOOD"
COPYRIGHT_YEAR="2026"

# ── Paths ─────────────────────────────────────────────────────────────────────
# SERVER: the control plane — what a competitor would host against us.
SERVER_PATHS=(
  crates/api
  crates/services
  crates/db
  crates/config
  crates/core
  crates/modules
  crates/derp-relay
  crates/tests
  ui
)

# CLIENT: everything installed on a machine, PLUS the four crates shared with
# the server (they must match the weaker side — see the header).
CLIENT_PATHS=(
  agents/meshharbord
  agents/meshharbor-desktop
  agents/meshharbor-cli-shim
  agents/meshharbor-setup
  agents/meshharbor-cli
  crates/agent-core
  crates/hive-node
  crates/meshharbor-setup-core
  crates/tunnel-core
  crates/remote_control
  crates/localapi
  crates/tcp-turn-conn
)

# CLIENT files inside a SERVER path: a single FILE compiled into both the web
# app and a shipped client takes the CLIENT licence, by the same rule as the
# shared crates above. Exact paths, checked before SERVER_PATHS — a directory
# never goes here.
CLIENT_FILES=(
  # Bundled into the desktop companion as
  # agents/meshharbor-desktop/src/front/mesh-util.js (FR-84 D5c).
  ui/src/utils/mesh.ts
)

# Never touched: upstream code keeps upstream headers, and generated files are
# regenerated. Matched as substrings of the path.
EXCLUDE_PATTERNS=(
  crates/vendored/
  /target/
  /node_modules/
  /dist/
  ui/e2e/
)

# ── Cargo package names, for the CI dependency-graph assertion ────────────────
SERVER_CRATES=(
  meshharbor-api
  meshharbor-core
  meshharbor-mod-saas
  meshharbor-mod-chat
  meshharbor-mod-conference
  meshharbor-mod-fleet
  meshharbor-mod-remote
  meshharbor-mod-network
  meshharbor-mod-hive
  meshharbor-mod-vault
  meshharbor-services
  meshharbor-db
  meshharbor-config
  derp-relay
  meshharbor-tests
)

CLIENT_CRATES=(
  roomlerd
  meshharbor-desktop
  meshharbor-cli-shim
  meshharbor-setup
  meshharbor-cli
  meshharbor-node-core
  meshharbor-hive-node
  meshharbor-setup-core
  meshharbor-tunnel-core
  meshharbor-remote-control
  meshharbor-localapi
  tcp-turn-conn
)

# Binaries we actually ship to end users. The licensing workflow asserts that no
# SERVER_CRATE appears anywhere in these dependency graphs — that assertion, not
# the header sweep, is what stops the split from silently rotting.
SHIPPED_AGENT_CRATES=(
  roomlerd
  meshharbor-cli
  meshharbor-cli-shim
  meshharbor-desktop
  meshharbor-setup
)

# ── Helpers ───────────────────────────────────────────────────────────────────

# is_excluded <path> -> rc 0 if the path is deliberately outside the sweep.
is_excluded() {
  local path="$1" p
  for p in "${EXCLUDE_PATTERNS[@]}"; do
    case "$path" in *"$p"*) return 0 ;; esac
  done
  return 1
}

# licence_for <path> -> SPDX id on stdout, or empty + rc 1 if unclassified.
licence_for() {
  local path="$1" p

  for p in "${EXCLUDE_PATTERNS[@]}"; do
    case "$path" in *"$p"*) return 1 ;; esac
  done

  for p in "${CLIENT_FILES[@]}"; do
    [ "$path" = "$p" ] && { printf '%s' "$CLIENT_LICENCE"; return 0; }
  done

  for p in "${SERVER_PATHS[@]}"; do
    case "$path" in "$p"/*) printf '%s' "$SERVER_LICENCE"; return 0 ;; esac
  done

  for p in "${CLIENT_PATHS[@]}"; do
    case "$path" in "$p"/*) printf '%s' "$CLIENT_LICENCE"; return 0 ;; esac
  done

  case "$path" in docs/*) printf '%s' "$DOCS_LICENCE"; return 0 ;; esac

  return 1
}

# licence_for_crate <cargo package name> -> SPDX id on stdout.
licence_for_crate() {
  local name="$1" c
  for c in "${SERVER_CRATES[@]}"; do
    [ "$c" = "$name" ] && { printf '%s' "$SERVER_LICENCE"; return 0; }
  done
  for c in "${CLIENT_CRATES[@]}"; do
    [ "$c" = "$name" ] && { printf '%s' "$CLIENT_LICENCE"; return 0; }
  done
  return 1
}
