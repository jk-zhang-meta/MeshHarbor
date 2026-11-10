#!/usr/bin/env bash
# Run some (or all) e2e specs against the standing `meshharbor-e2e` stack, on
# demand. The nightly (`e2e-nightly.sh`) runs the whole suite and triages it;
# this is the one you want while working on a spec or bisecting a build.
#
# Usage, from the build host:
#   scripts/e2e-run.sh                             # whole suite, current image
#   scripts/e2e-run.sh '' e2e/mention.spec.ts      # one spec, current image
#   scripts/e2e-run.sh v20260829-abc123 e2e/conference.spec.ts e2e/chat.spec.ts
#
# The first argument pins the stack to an image tag. 🔑 That is what makes an
# A/B possible: the e2e namespace is deliberately NOT ArgoCD-managed, so any
# historical tag can be pinned and the SAME spec run against both sides. A test
# that has not been shown to fail on the broken build has proven nothing.
#
# Like the nightly, this drives the `pwrunner` sidecar INSIDE the app pod.
# ⚠️ Not a browser out here: this host has no route to the pod network (so no
# RTP ever arrives), and a Service URL is not a secure context (so
# `navigator.mediaDevices` does not exist). Both are why the conference specs
# "failed" for months. See docs/fr/FR-37-e2e-in-cluster.md.
set -uo pipefail

NS=meshharbor-e2e
REPO="${REPO:-$HOME/wt-e2e-lane}"
TAG="${1:-}"; shift || true
SPECS=("$@")

note() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
die()  { echo "ABORT: $*" >&2; exit 2; }

cd "$REPO" || die "no repo at $REPO (override with REPO=)"
git fetch origin --quiet || note "git fetch failed — running with the existing checkout"
git checkout --quiet --detach origin/master || note "could not detach at origin/master"
note "specs at $(git log --oneline -1)"

# Run the script the checkout just produced, not the one bash opened: bash
# reads a script as it executes it, and a changed file mid-run executes a mix
# of old and new text (see e2e-nightly.sh, 2026-09-06).
if [ "${E2E_RUN_REEXEC:-}" != "1" ]; then
  STAGED="$(mktemp)"
  cp "$REPO/scripts/e2e-run.sh" "$STAGED" || die "could not stage the updated script"
  E2E_RUN_REEXEC=1 exec bash "$STAGED" "$TAG" "${SPECS[@]}"
fi

if [ -n "$TAG" ]; then
  # FR-73: a bare tag is resolved against the registry the deploy repo names
  # (`newName` in the prod overlay — GHCR since P2, the build host's registry
  # before), so `hosted-<date>-<sha7>` and the old `v<date>-<id>` tags both
  # pin. A tag containing `/` is taken as a full image reference.
  case "$TAG" in
    */*) IMG="$TAG" ;;
    *)
      # The registry prod pulls from, read from the cluster's own Deployment —
      # the deploy repo's clone on this host is stale by construction since
      # FR-73 (promotes push GitHub, nothing pulls here), so it is only the
      # fallback, pulled first.
      REG=$(kubectl -n meshharbor get deploy meshharbor2 -o jsonpath='{.spec.template.spec.containers[?(@.name=="meshharbor2")].image}' 2>/dev/null | sed -E 's/:[^:/]+$//')
      if [ -z "$REG" ]; then
        DEPLOY_REPO="${DEPLOY_REPO:-$HOME/meshharbor-deploy}"
        git -C "$DEPLOY_REPO" pull --quiet --ff-only 2>/dev/null || true
        REG=$(awk '/newName:/ {print $2; exit}' "$DEPLOY_REPO/k8s/overlays/prod/kustomization.yaml" 2>/dev/null)
        [ -n "$REG" ] || { REG=ghcr.io/jk-zhang-meta/meshharbor; note "no cluster read and no deploy repo at $DEPLOY_REPO — assuming $REG"; }
      fi
      IMG="$REG:$TAG" ;;
  esac
  note "pinning the stack to $IMG"
  kubectl -n "$NS" set image deploy/meshharbor2 "meshharbor2=$IMG" >/dev/null \
    || die "could not set the image"
  kubectl -n "$NS" rollout status deploy/meshharbor2 --timeout=300s >/dev/null || die "the stack did not roll to $IMG"
fi
# ⚠️ Select the app container BY NAME. `containers[0]` is the sidecar now, and
# this line reported the browser image as "the stack" the first time it ran.
note "stack on $(kubectl -n "$NS" get deploy meshharbor2   -o jsonpath='{.spec.template.spec.containers[?(@.name=="meshharbor2")].image}')"

POD=$(kubectl -n "$NS" get pod -l app=meshharbor2 -o jsonpath='{.items[0].metadata.name}')
[ -n "$POD" ] || die "no meshharbor2 pod in $NS"
kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[*].name}' | tr ' ' '\n' | grep -qx pwrunner \
  || die "pod $POD has no pwrunner sidecar — apply k8s/overlays/e2e from the deploy repo"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# ⚠️ minus e2e/video/ — that spec uses bun-only JSON-import syntax and kills
# collection under node, taking the whole run with it.
rsync -a --exclude node_modules --exclude dist --exclude test-results \
      --exclude playwright-report --exclude e2e/video "$REPO/ui/" "$WORK/ui/"
kubectl -n "$NS" exec "$POD" -c pwrunner -- rm -rf /work
kubectl -n "$NS" cp "$WORK/ui" "$POD":/work -c pwrunner >/dev/null 2>&1 || die "could not copy the specs in"

note "running ${SPECS[*]:-the whole suite}"
kubectl -n "$NS" exec "$POD" -c pwrunner -- bash -lc "
  cd /work && npm i --no-audit --no-fund --loglevel=error >/dev/null 2>&1 &&
  CI=1 E2E_BASE_URL=http://127.0.0.1 E2E_API_URL=http://127.0.0.1 \
  E2E_MAILPIT_URL=http://mailpit:8025 \
  npx playwright test ${SPECS[*]:-} --reporter=line --timeout=60000 --retries=0"
RC=$?
note "playwright exit $RC"
exit "$RC"
