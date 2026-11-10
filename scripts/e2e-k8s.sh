#!/bin/bash
# MeshHarbor e2e orchestrator. Run on the build host from any directory.
# Override REPO_ROOT / DEPLOY_REPO / REGISTRY env vars if your local
# layout differs from the defaults below.
#
# Usage:
#   scripts/e2e-k8s.sh smoke       # Phase 1: run a single auth spec
#   scripts/e2e-k8s.sh first-cut   # Phase 2: 22 specs, skip media/oauth/email
#   scripts/e2e-k8s.sh full        # Phase 3: all 29 specs (needs Phase 3 infra)
#   scripts/e2e-k8s.sh --reset full # wipe DB pods + minio first
#   scripts/e2e-k8s.sh --build full # force rebuild of e2e image even if cached
#
# Outputs the HTML report path on success.
#
# Flow:
#   1. (Optionally) build + push meshharbor-e2e:<sha> if specs/lockfile
#      changed since the last build.
#   2. Apply the e2e overlay (idempotent).
#   3. Wait for stack ready.
#   4. Smoke-probe meshharbor2 /health.
#   5. Render + apply the Job manifest.
#   6. Stream logs.
#   7. Poll for /results/.done in the runner pod.
#   8. kubectl cp results out.
#   9. Print the path to the HTML report.
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$HOME/meshharbor}"
DEPLOY_REPO="${DEPLOY_REPO:-$HOME/meshharbor-deploy}"
NAMESPACE="${NAMESPACE:-meshharbor-e2e}"
REGISTRY="${REGISTRY:?set REGISTRY=<internal-registry>}"
IMAGE_NAME="meshharbor-e2e"
RESULTS_ROOT="${RESULTS_ROOT:-$HOME/e2e-results}"

RESET=0
FORCE_BUILD=0
# Phase 1 Chunk 1D — opt-in agent harness. When --with-agents is set,
# the orchestrator (a) waits for the agent-e2e StatefulSet's 2 Pods
# to be Ready alongside the API stack, and (b) blocks on the seed
# Job completing before treating the stack as ready. Default OFF so
# the existing Playwright-only path keeps its ~3 min run time on
# stacks that don't have the agent overlay applied yet.
WITH_AGENTS=0
MODE=""
for arg in "$@"; do
  case "$arg" in
    --reset)        RESET=1 ;;
    --build)        FORCE_BUILD=1 ;;
    --with-agents)  WITH_AGENTS=1 ;;
    smoke|first-cut|full) MODE="$arg" ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done
[ -z "$MODE" ] && { echo "usage: $0 [--reset] [--build] [--with-agents] smoke|first-cut|full" >&2; exit 2; }

cd "$REPO_ROOT"
GIT_SHA=$(git rev-parse --short HEAD)
IMAGE_TAG="$GIT_SHA"
IMAGE_REF="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"

# ──────────────────────────────────────────────────────────────────────
# 1. Build + push image (skip if remote tag already exists and no force)
# ──────────────────────────────────────────────────────────────────────
build_needed() {
  [ "$FORCE_BUILD" = "1" ] && return 0
  # Cheap check: does the registry already have this tag?
  local manifest
  manifest=$(curl -sf -o /dev/null -w "%{http_code}" \
    "https://$REGISTRY/v2/$IMAGE_NAME/manifests/$IMAGE_TAG" 2>&1 || true)
  [ "$manifest" = "200" ] && return 1
  return 0
}

if build_needed; then
  echo "[e2e-k8s] building $IMAGE_REF"
  docker build -f Dockerfile.e2e -t "$IMAGE_REF" .
  docker tag "$IMAGE_REF" "$REGISTRY/$IMAGE_NAME:latest"
  docker push "$IMAGE_REF"
  docker push "$REGISTRY/$IMAGE_NAME:latest"
else
  echo "[e2e-k8s] reusing existing $IMAGE_REF (use --build to force)"
fi

# ──────────────────────────────────────────────────────────────────────
# 2. Apply overlay (idempotent). Optionally reset DB state first.
# ──────────────────────────────────────────────────────────────────────
echo "[e2e-k8s] applying overlay (namespace: $NAMESPACE)"
kubectl apply -k "$DEPLOY_REPO/k8s/overlays/e2e/"

if [ "$RESET" = "1" ]; then
  echo "[e2e-k8s] --reset: wiping DB pods to recreate emptyDirs"
  kubectl -n "$NAMESPACE" delete pod -l app=mongodb --ignore-not-found
  kubectl -n "$NAMESPACE" delete pod -l app=minio   --ignore-not-found
  kubectl -n "$NAMESPACE" delete pod -l app=redis   --ignore-not-found
fi

# ──────────────────────────────────────────────────────────────────────
# 3. Wait for stack ready
# ──────────────────────────────────────────────────────────────────────
echo "[e2e-k8s] waiting for stack ready"
# Mailpit added in Cycle 4 Chunk 1 to capture SMTP for email-flows.spec.ts.
# It boots in seconds (single container, no persistent state), but include
# it in the wait so the orchestrator fails fast if the deployment is
# missing or unhealthy rather than the spec hitting connection-refused
# 30 s later.
for selector in "app=mongodb" "app=redis" "app=minio" "app=mailpit" "app=meshharbor2"; do
  kubectl -n "$NAMESPACE" wait --for=condition=ready pod \
    -l "$selector" --timeout=180s
done

# Phase 1 Chunk 1D — agent harness wait. The agent-e2e StatefulSet
# can't reach Ready until (a) the API is up (already waited above),
# (b) the seed Job has created the admin/tenant, and (c) the
# bootstrap Secret holds the real tenant_id (operator-side step
# documented in scripts/e2e-k8s/AGENT-E2E.md). If --with-agents is
# set but the harness hasn't been brought up yet, fail loud here
# rather than mid-test with a "no enrolled agent" cryptic error.
if [ "$WITH_AGENTS" = "1" ]; then
  echo "[e2e-k8s] --with-agents: waiting for seed Job + 2 agent Pods"
  # Seed Job: ttlSecondsAfterFinished=0 so once it's gone, it
  # already ran successfully. If it's still present we wait for
  # completion (typical ~5 s).
  if kubectl -n "$NAMESPACE" get job/agent-e2e-seed >/dev/null 2>&1; then
    kubectl -n "$NAMESPACE" wait --for=condition=complete --timeout=120s \
      job/agent-e2e-seed || {
        echo "[e2e-k8s] seed Job failed; check kubectl logs job/agent-e2e-seed" >&2
        kubectl -n "$NAMESPACE" logs job/agent-e2e-seed >&2 || true
        exit 1
      }
  fi
  kubectl -n "$NAMESPACE" wait --for=condition=ready pod \
    -l "app=agent-e2e" --timeout=180s || {
      echo "[e2e-k8s] agent-e2e Pods never reached Ready — likely a stale" >&2
      echo "          tenant_id in secret-agent-e2e-bootstrap.yaml. See" >&2
      echo "          scripts/e2e-k8s/AGENT-E2E.md for the rebake runbook." >&2
      kubectl -n "$NAMESPACE" logs -l app=agent-e2e --tail=80 >&2 || true
      exit 1
    }
  echo "[e2e-k8s] agent harness ready ($(kubectl -n "$NAMESPACE" get pod -l app=agent-e2e --no-headers | wc -l) Pods)"
fi

# ──────────────────────────────────────────────────────────────────────
# 4. Smoke probe
# ──────────────────────────────────────────────────────────────────────
echo "[e2e-k8s] smoke-probing http://meshharbor2.${NAMESPACE}.svc.cluster.local/health"
kubectl -n "$NAMESPACE" run smoke-probe --rm -i --restart=Never \
  --image=curlimages/curl:8.10.1 -- \
  curl -sf "http://meshharbor2/health" || {
    echo "[e2e-k8s] smoke probe FAILED" >&2
    exit 1
  }

# ──────────────────────────────────────────────────────────────────────
# 5. Render + apply Job manifest. Use mode to pick --grep / --grep-invert.
# ──────────────────────────────────────────────────────────────────────
JOB_NAME="e2e-run-$(date +%s)"
PW_GREP=""
PW_GREP_INVERT=""
PW_SKIP_PHASE_3=""
case "$MODE" in
  smoke)
    # Tightest filter — auth specs only. Validates pipeline.
    PW_GREP="register|login"
    PW_SKIP_PHASE_3="1"
    ;;
  first-cut)
    # Excludes the Phase 3-dependent specs via the playwright.config
    # `testIgnore` (E2E_SKIP_PHASE_3=1 enables it). NOT via grep-
    # invert — that matches test names, not file paths, so file-
    # name regexes there silently match nothing.
    PW_SKIP_PHASE_3="1"
    ;;
  full)
    : # no filter — Phase 3 infra must be in place
    ;;
esac

echo "[e2e-k8s] creating Job $JOB_NAME (grep=$PW_GREP grep-invert=$PW_GREP_INVERT)"
cat <<YAML | kubectl -n "$NAMESPACE" apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: $JOB_NAME
  labels:
    app: e2e-runner
    mode: "$MODE"
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 86400
  # Hard upper bound on the Job — if the orchestrator script that
  # normally `kubectl cp`s artifacts and deletes the Job dies (SSH
  # disconnect, Ctrl+C, host reboot), the run-e2e.sh entrypoint's
  # \`tail -f /dev/null\` keeps the pod alive forever. Without this,
  # Prometheus' KubeJobNotCompleted alert fires after 12 h. Force
  # the Job to fail at 1 h so ttlSecondsAfterFinished kicks in and
  # the namespace stays clean. Normal runs finish in ~10-15 min so
  # 3600 s leaves plenty of headroom.
  activeDeadlineSeconds: 3600
  template:
    metadata:
      labels:
        app: e2e-runner
        job-name: $JOB_NAME
    spec:
      restartPolicy: Never
      imagePullSecrets:
        - name: regcred
      containers:
        - name: playwright
          image: $IMAGE_REF
          imagePullPolicy: Always
          env:
            - name: E2E_BASE_URL
              value: "http://meshharbor2"
            - name: E2E_API_URL
              value: "http://meshharbor2"
            - name: VITE_API_URL
              value: "http://meshharbor2"
            # Mailpit HTTP API endpoint used by fetchActivationEmail
            # in the email-flows spec. Mailpit's web UI / REST API
            # listens on :8025 inside the cluster. (Backticks in this
            # comment would be eaten by bash command-substitution in
            # the heredoc — kept plain for safety.)
            - name: E2E_MAILPIT_URL
              value: "http://mailpit:8025"
            - name: CI
              value: "true"
            # Single-quoted YAML so backslashes in the regex (e.g.
            # 'oauth\.spec\.ts') don't trip YAML's double-quote
            # escape rules ('\.' isn't a valid double-quote escape
            # sequence, fails parsing). Bash heredoc still expands
            # the \$VAR inside single quotes (single quotes are
            # literal YAML chars, not shell quotes here).
            - name: PW_GREP
              value: '$PW_GREP'
            - name: PW_GREP_INVERT
              value: '$PW_GREP_INVERT'
            - name: E2E_SKIP_PHASE_3
              value: '$PW_SKIP_PHASE_3'
          volumeMounts:
            - name: results
              mountPath: /results
      volumes:
        - name: results
          emptyDir: {}
YAML

# ──────────────────────────────────────────────────────────────────────
# 6. Stream logs
# ──────────────────────────────────────────────────────────────────────
echo "[e2e-k8s] waiting for Job pod to be ready"
kubectl -n "$NAMESPACE" wait --for=condition=ready pod \
  -l "job-name=$JOB_NAME" --timeout=120s

POD=$(kubectl -n "$NAMESPACE" get pod -l "job-name=$JOB_NAME" \
  -o jsonpath='{.items[0].metadata.name}')

# Poll for /results/.done — set inside the container by run-e2e.sh
# AFTER Playwright exits. Don't use `kubectl logs -f` here because
# the container's run-e2e.sh ends with `tail -f /dev/null` (to keep
# the pod alive long enough for kubectl cp), so logs -f would hang
# until SIGTERM. Polling the marker file is the explicit completion
# signal. Cap at 45 min — Cycle 4 Chunk 1 added Mailpit-polling
# email-flows tests + retries on a flaky mention test pushed
# wall-clock past the prior 30-min cap (run #1 finished at ~40 min).
# Pod's `activeDeadlineSeconds: 3600` still caps absolute runtime.
echo "[e2e-k8s] waiting for Playwright to finish (/results/.done in $POD)"
DONE=0
for i in $(seq 1 540); do
  if kubectl -n "$NAMESPACE" exec "$POD" -- test -f /results/.done 2>/dev/null; then
    DONE=1
    break
  fi
  sleep 5
done
[ "$DONE" = "1" ] || { echo "[e2e-k8s] timeout waiting for /results/.done" >&2; exit 1; }

# ──────────────────────────────────────────────────────────────────────
# 7. Dump full logs (now that the run is finished)
# ──────────────────────────────────────────────────────────────────────
echo "[e2e-k8s] === pod logs ==="
kubectl -n "$NAMESPACE" logs "$POD" --tail=2000 || true
echo "[e2e-k8s] === end pod logs ==="

EXIT_CODE=$(kubectl -n "$NAMESPACE" exec "$POD" -- cat /results/exit-code 2>/dev/null || echo "?")
echo "[e2e-k8s] Playwright exit code: $EXIT_CODE"

# ──────────────────────────────────────────────────────────────────────
# 8. kubectl cp results
# ──────────────────────────────────────────────────────────────────────
mkdir -p "$RESULTS_ROOT"
DEST="$RESULTS_ROOT/$JOB_NAME"
echo "[e2e-k8s] copying /results -> $DEST"
kubectl -n "$NAMESPACE" cp "$POD:/results" "$DEST"

# ──────────────────────────────────────────────────────────────────────
# 9. Print HTML report path; clean up the Job
# ──────────────────────────────────────────────────────────────────────
HTML="$DEST/html/index.html"
if [ -f "$HTML" ]; then
  echo "[e2e-k8s] HTML report: $HTML"
  echo "[e2e-k8s] open with: xdg-open $HTML  (or scp $HOSTNAME:$HTML .)"
fi

echo "[e2e-k8s] deleting Job $JOB_NAME (pod retained until ttlSecondsAfterFinished=86400)"
kubectl -n "$NAMESPACE" delete pod "$POD" --grace-period=5

exit "$EXIT_CODE"
