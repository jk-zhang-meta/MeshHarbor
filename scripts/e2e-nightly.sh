#!/usr/bin/env bash
# Nightly Playwright sweep against the standing `roomler-ai-e2e` stack.
#
# The suite has NO GitHub CI lane (it needs a full backend + Mailpit), and
# when it never runs it rots: the first manual sweep (2026-07-28) found two
# shipped auth bugs. This script keeps it honest from the build host.
#
# What it does, in order:
#   1. Fast-forwards the repo clone: the source of THIS script and of the
#      expected-failures list. The SPECS come from the image's own commit
#      (step 4), never from master.
#   2. Points the e2e stack's roomler2 at the CURRENT PROD image tag (read
#      from the deploy repo's prod overlay) via `kubectl set image` — the
#      e2e namespace is deliberately NOT ArgoCD-managed.
#   3. Runs the browser as the `pwrunner` sidecar INSIDE the app pod.
#      ⚠️ The stack's MESHHARBOR__APP__FRONTEND_URL must equal the origin the
#      browser uses — here http://127.0.0.1, and a PORT is part of an Origin.
#      Since the session-cookie migration the /ws upgrade authenticates by
#      COOKIE and refuses an untrusted Origin with 403 (cookies are ambient
#      and a WS upgrade is not subject to CORS), which silently disarmed every
#      realtime spec for a week. Both live in the deploy repo's e2e overlay,
#      so they move together.
#   4. Copies the spec tree AT THE COMMIT THE IMAGE WAS BUILT FROM into that
#      sidecar and runs the suite there (minus
#      e2e/video/ — that spec is bun-only syntax).
#   5. Diffs the failing specs against scripts/e2e-expected-failures.txt and
#      writes ~/e2e-nightly/LATEST (one summary line) + a dated full log.
#      Unexpected failures ⇒ exit 1 (and a GitHub issue, if `gh` is authed).
#
# Install (build host) — note BOTH details, each of which silently killed this
# lane once:
#   crontab: 30 3 * * * REPO=$HOME/wt-e2e-lane bash $HOME/wt-e2e-lane/scripts/e2e-nightly.sh >> $HOME/e2e-nightly/cron.log 2>&1
#   * invoked through `bash`, because this file was committed 100644 and the
#     bare-path form failed `Permission denied` EVERY night from install until
#     2026-08-29 — into a log nobody reads. The mode bit is fixed too, but the
#     cron line should not depend on it.
#   * REPO points at a dedicated worktree, never the shared clone: that clone
#     is routinely parked on another session's branch.
set -uo pipefail

REPO="${REPO:-$HOME/roomler-ai}"
DEPLOY_REPO="${DEPLOY_REPO:-$HOME/roomler-ai-deploy}"
OUT="${OUT:-$HOME/e2e-nightly}"
NS=roomler-ai-e2e
# ⚠️ The runner image is pinned in the deploy repo's e2e overlay (the
# `pwrunner` sidecar), NOT here: browser binaries are version-locked to the
# image, so bumping @playwright/test means bumping that manifest too.
STAMP="${E2E_NIGHTLY_STAMP:-$(date -u +%Y%m%d-%H%M)}"
LOG="$OUT/$STAMP.log"
mkdir -p "$OUT"

note() { echo "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$LOG"; }
fail_hard() { note "ABORT: $*"; echo "$STAMP INFRA-FAIL: $*" > "$OUT/LATEST"; exit 2; }

# ── 1. fresh specs ───────────────────────────────────────────────────
cd "$REPO" || fail_hard "repo missing"
# Detach at origin/master rather than `git pull`, for the reason deploy-api.sh
# already learned: a shared clone gets parked on someone's branch, and
# `--ff-only` then FAILS and this script cheerfully runs whatever specs happen
# to be checked out — a nightly that silently tests an unmerged branch is worse
# than one that does not run. Detaching also works inside a worktree, which is
# what the cron should point REPO at.
git fetch origin --quiet || note "git fetch failed — running with the existing checkout"
git checkout --quiet --detach origin/master || note "could not detach at origin/master — running with the existing checkout"
note "repo at $(git log --oneline -1) (this script and the expected-failures list)"

# ── 1b. run the script step 1 just checked out, not the one bash opened ──────
# bash reads a script as it executes it. When the checkout above changes THIS
# file, the rest of the run can execute a mix of the old and the new text —
# 2026-09-06: a pre-FR-73 copy of this script, invoked exactly as the cron line
# does, pinned the stack to `registry.roomler.ai/…:hosted-…`, a tag that
# registry never had, and the e2e pod sat in ImagePullBackOff. So the updated
# file is copied out and exec'd once, with the update step skipped.
if [ "${E2E_NIGHTLY_REEXEC:-}" != "1" ]; then
  cp "$REPO/scripts/e2e-nightly.sh" "$OUT/e2e-nightly.current.sh" || fail_hard "could not stage the updated script"
  E2E_NIGHTLY_REEXEC=1 E2E_NIGHTLY_STAMP="$STAMP" exec bash "$OUT/e2e-nightly.current.sh" "$@"
fi

# ── 2. sync the e2e stack to the prod image ──────────────────────────
# The image prod RUNS, read from the cluster — the truth, whatever registry it
# came from and however it was promoted. Since FR-73 the promote pushes the
# deploy repo on GitHub and nothing pulls the build host's clone, so that clone
# is stale by construction; it is only the fallback, pulled first, when the
# cluster cannot be read.
PRODIMG=$(kubectl -n roomler-ai get deploy roomler2 -o jsonpath='{.spec.template.spec.containers[?(@.name=="roomler2")].image}' 2>/dev/null)
if [ -z "$PRODIMG" ]; then
  note "could not read the prod image from the cluster — falling back to the deploy repo's overlay"
  git -C "$DEPLOY_REPO" pull --quiet --ff-only 2>/dev/null || note "deploy repo pull failed — its overlay may be stale"
  PRODNAME=$(awk '/newName:/ {print $2; exit}' "$DEPLOY_REPO/k8s/overlays/prod/kustomization.yaml")
  PRODTAG=$(awk '/newTag:/ {print $2; exit}' "$DEPLOY_REPO/k8s/overlays/prod/kustomization.yaml")
  [ -n "$PRODNAME" ] && [ -n "$PRODTAG" ] || fail_hard "could not read the prod image from the cluster or the deploy repo"
  PRODIMG="${PRODNAME}:${PRODTAG}"
fi
# The tag alone, for LATEST and the regression issue (the second hand-run of
# 2026-09-06 died here under `set -u`: the summary lines still said $PRODTAG).
PRODTAG="${PRODIMG##*:}"
kubectl -n "$NS" set image deploy/roomler2 "roomler2=${PRODIMG}" >> "$LOG" 2>&1
kubectl -n "$NS" rollout status deploy/roomler2 --timeout=300s >> "$LOG" 2>&1 || fail_hard "e2e stack failed to roll to ${PRODIMG}"
note "e2e stack on ${PRODIMG}"

# ── 3. the browser is IN the pod ─────────────────────────────────────
# FR-37. There are no port-forwards any more, and that is the point.
#
# The old lane ran a browser on THIS host and reached the stack through
# `kubectl port-forward`, which forwards one TCP port and no media — and this
# host has no route to the pod network anyway (`ip route get <podIP>` leaves
# via the default route), so no RTP was ever going to arrive. Every conference
# spec failed for months and the baseline blamed unforwarded RTC ports.
#
# The browser now runs as the `pwrunner` sidecar inside the app pod, so:
#   * the app is `http://127.0.0.1`, which is a SECURE CONTEXT — a Service URL
#     is not, and `navigator.mediaDevices` is simply UNDEFINED there;
#   * mediasoup announces 127.0.0.1, so media has nowhere to get lost;
#   * the Origin matches `frontend_url`, so the cookie-authenticated /ws
#     upgrade is not refused (that 403 silently disarmed every realtime spec
#     for a week);
#   * the ~60 lines of self-healing port-forward supervisor this replaces are
#     gone, along with the failure mode where a forward stays alive while
#     forwarding nothing.
POD=$(kubectl -n "$NS" get pod -l app=roomler2 -o jsonpath='{.items[0].metadata.name}')
[ -n "$POD" ] || fail_hard "no roomler2 pod in $NS"
kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[*].name}' | tr ' ' '
' | grep -qx pwrunner   || fail_hard "pod $POD has no pwrunner sidecar — apply k8s/overlays/e2e in the deploy repo"
note "runner: $POD/pwrunner"
curl_in_pod() { kubectl -n "$NS" exec "$POD" -c pwrunner -- curl -sf -o /dev/null -m 8 "$1"; }
curl_in_pod http://127.0.0.1/health || fail_hard "the app is not answering inside its own pod"

# ── 3b. the agent-e2e harness (FR-114) ───────────────────────────────
# Its six specs skip without E2E_AGENT_E2E_TENANT_ID. When the harness's
# StatefulSet is there, find its tenant BY SLUG from inside the runner (this
# host has no route to the pod network) and hand it to both runs below; when
# it is not, they skip as before and this log says why. Never a pinned id: a
# wiped e2e DB gets a fresh tenant and the lookup still finds it. The admin's
# credentials come from the harness's own Secret, the one the agents use.
AGENT_ENV=""
if kubectl -n "$NS" get statefulset agent-e2e >/dev/null 2>&1; then
  ae_secret() { kubectl -n "$NS" get secret agent-e2e-bootstrap -o jsonpath="{.data.$1}" 2>/dev/null | base64 -d 2>/dev/null; }
  AE_EMAIL=$(ae_secret admin_email)
  AE_PASS=$(ae_secret admin_password)
  AE_TID=""
  if printf '%s%s' "$AE_EMAIL" "$AE_PASS" | grep -qE '^[A-Za-z0-9@._+-]+$'; then
    AE_TOKEN=$(kubectl -n "$NS" exec "$POD" -c pwrunner -- curl -fsS -m 10 -X POST http://127.0.0.1/api/auth/login \
      -H 'content-type: application/json' -d "{\"email\":\"$AE_EMAIL\",\"password\":\"$AE_PASS\"}" 2>/dev/null \
      | grep -oE '"access_token":"[^"]+"' | cut -d'"' -f4)
    [ -n "$AE_TOKEN" ] && AE_TID=$(kubectl -n "$NS" exec "$POD" -c pwrunner -- curl -fsS -m 10 http://127.0.0.1/api/tenant \
      -H "authorization: Bearer $AE_TOKEN" 2>/dev/null \
      | grep -oE '\{[^{}]*"slug":"agent-e2e"[^{}]*\}' | grep -oE '"id":"[0-9a-f]{24}"' | head -1 | cut -d'"' -f4)
  fi
  if [ -n "$AE_TID" ]; then
    AGENT_ENV="E2E_AGENT_E2E_TENANT_ID=$AE_TID E2E_AGENT_E2E_ADMIN_EMAIL=$AE_EMAIL E2E_AGENT_E2E_ADMIN_PASSWORD=$AE_PASS"
    note "agent-e2e harness: tenant $AE_TID, $(kubectl -n "$NS" get statefulset agent-e2e -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0) agent(s) ready — its specs run"
  else
    note "agent-e2e harness present, but its tenant did not resolve (has the seed Job run?) — its specs skip"
  fi
else
  note "no agent-e2e harness in $NS — its specs skip"
fi

# ── 4. run the suite ─────────────────────────────────────────────────
# The specs come from the commit the image under test was built from: the
# server runs that commit, so its specs are the ones that describe it. Master's
# can run ahead of the image. Measured 2026-10-20 (#2573): FR-115's billing
# specs, merged nine minutes before the run, ran against an image that
# predated them, and the lane filed a "regression" for a feature that had not
# shipped. The SCRIPT and the expected-failures list stay master's, so a fix
# to the lane itself still applies the same night. A tag that names no commit
# this clone knows falls back to master's specs, and the log says so.
SPEC_SRC="$REPO/ui"
SPEC_TREE="$OUT/ui-at-image"
IMG_SHA="${PRODTAG##*-}"
if [[ "$PRODTAG" =~ ^hosted-[0-9]{8}-[0-9a-f]{7,40}$ ]] \
  && IMG_COMMIT=$(git -C "$REPO" rev-parse --verify --quiet "${IMG_SHA}^{commit}"); then
  if rm -rf "$SPEC_TREE" && mkdir -p "$SPEC_TREE" \
    && git -C "$REPO" archive "$IMG_COMMIT" ui | tar -x -C "$SPEC_TREE"; then
    SPEC_SRC="$SPEC_TREE/ui"
    note "specs at ${IMG_COMMIT:0:9}, the commit ${PRODTAG} was built from ($(git -C "$REPO" rev-list --count "$IMG_COMMIT..HEAD") behind master)"
  else
    note "could not stage the specs at ${IMG_SHA}: running master's"
  fi
else
  note "the image tag ${PRODTAG} names no commit this clone knows: running master's specs"
fi
WORK="$OUT/ui-work"
rsync -a --delete --exclude node_modules --exclude dist --exclude test-results   --exclude playwright-report --exclude e2e/video "$SPEC_SRC/" "$WORK/"
# The sidecar keeps nothing between runs, so ship the tree and install there.
kubectl -n "$NS" exec "$POD" -c pwrunner -- rm -rf /work
kubectl -n "$NS" cp "$WORK" "$POD":/work -c pwrunner >/dev/null 2>&1   || fail_hard "could not copy the spec tree into the runner"
kubectl -n "$NS" exec "$POD" -c pwrunner -- bash -lc "
  cd /work && npm i --no-audit --no-fund --loglevel=error >/dev/null 2>&1 &&
  CI=1 E2E_BASE_URL=http://127.0.0.1 E2E_API_URL=http://127.0.0.1   E2E_MAILPIT_URL=http://mailpit:8025 $AGENT_ENV  npx playwright test --reporter=line --timeout=60000 --retries=3" >> "$LOG" 2>&1
RC=$?


# ── 5. triage against the expected-failures baseline ─────────────────
CLEAN=$(sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$LOG" | tr '\r' '\n')
SUMMARY=$(echo "$CLEAN" | grep -E '^\s+[0-9]+ (passed|failed|flaky|skipped)' | tr -d ' ' | paste -sd' ' -)
# Only GENUINELY-failed specs count — a spec listed under "N flaky"
# recovered on retry and PASSED, so it must NOT trigger a regression.
# Playwright's line reporter prints the failed block first, then flaky /
# skipped / passed summaries; slice out exactly the failed block.
FAILED=$(echo "$CLEAN" \
  | awk '/^  [0-9]+ failed/{f=1;next} /^  [0-9]+ (flaky|skipped|passed|interrupted|did not run)/{f=0} f' \
  | grep -oE '\[chromium\] › [^ ]+ › .*' | sed 's/ *$//' | sort -u)

# Only the list's ENTRIES are patterns, never its comments. `grep -F -f` has no
# comment syntax: every line of the file was a pattern, and its one bare "#"
# line matched any failure carrying a "#", as a title's issue number does
# ("… (#1631)"), passing it as EXPECTED. Measured 2026-10-21:
# remote-switch-device.spec.ts could not fail the night. A blank line would be
# worse still (the empty pattern matches every failure), so both are dropped.
EXPECTED="$OUT/expected-failures.patterns"
grep -vE '^[[:space:]]*(#|$)' "$REPO/scripts/e2e-expected-failures.txt" | tr -d '\r' > "$EXPECTED"

UNEXPECTED=""
if [ -n "$FAILED" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qFf "$EXPECTED" <<< "$f"; then
      UNEXPECTED+="$f"$'\n'
    fi
  done <<< "$FAILED"
fi

# ── 6. VERIFY unexpected failures in isolation ───────────────────────
# A real regression fails deterministically; a spec caught in a blip during the
# loaded main run recovers when re-run alone. Re-run exactly the unexpected
# specs, with no concurrent load, and keep only the ones that STILL fail —
# that's the blip-vs-real discriminator, so the lane doesn't cry wolf.
if [ -n "$UNEXPECTED" ]; then
  note "UNEXPECTED (pre-verify):"; echo "$UNEXPECTED" | tee -a "$LOG"
  VSPECS=$(echo "$UNEXPECTED" | grep -oE 'e2e/[^ :]+\.spec\.ts' | sort -u | tr '\n' ' ')
  VLOG="$OUT/$STAMP-verify.log"
  kubectl -n "$NS" exec "$POD" -c pwrunner -- bash -lc "
    cd /work &&
    CI=1 E2E_BASE_URL=http://127.0.0.1 E2E_API_URL=http://127.0.0.1 \
    E2E_MAILPIT_URL=http://mailpit:8025 $AGENT_ENV \
    npx playwright test $VSPECS --reporter=line --timeout=60000 --retries=3" > "$VLOG" 2>&1
  VCLEAN=$(sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$VLOG" | tr '\r' '\n')
  VFAILED=$(echo "$VCLEAN" \
    | awk '/^  [0-9]+ failed/{f=1;next} /^  [0-9]+ (flaky|skipped|passed|interrupted|did not run)/{f=0} f' \
    | grep -oE '\[chromium\] › [^ ]+ › .*' | sed 's/ *$//' | sort -u)
  # Survivors that are STILL not baseline-expected = real regressions.
  UNEXPECTED=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    grep -qFf "$EXPECTED" <<< "$f" || UNEXPECTED+="$f"$'\n'
  done <<< "$VFAILED"
fi

if [ -n "$UNEXPECTED" ]; then
  note "CONFIRMED REGRESSION (survived isolated re-run):"
  echo "$UNEXPECTED" | tee -a "$LOG"
  echo "$STAMP REGRESSION ($SUMMARY) tag=$PRODTAG — see $LOG" > "$OUT/LATEST"
  if command -v gh > /dev/null 2>&1 && gh auth status > /dev/null 2>&1; then
    gh issue create --repo gjovanov/roomler-ai \
      --title "e2e nightly regression ($STAMP)" \
      --body "$(printf 'Image: %s\nSummary: %s\n\nRegressions (failed the main run AND the isolated re-run):\n```\n%s```\n' "$PRODIMG" "$SUMMARY" "$UNEXPECTED")" \
      >> "$LOG" 2>&1 || note "gh issue creation failed"
  fi
  exit 1
fi

echo "$STAMP OK ($SUMMARY) tag=$PRODTAG rc=$RC" > "$OUT/LATEST"
note "OK ($SUMMARY)"
# Keep the last 14 logs.
ls -1t "$OUT"/2*.log 2>/dev/null | tail -n +15 | xargs -r rm -f
