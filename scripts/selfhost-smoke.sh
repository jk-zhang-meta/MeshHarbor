#!/usr/bin/env bash
# FR-42 (#967) — bring the self-hosted stack up from a CLEAN CLONE, following
# docs/self-hosting.md verbatim, and report every deviation.
#
# The value is the "verbatim": each command below is copy-pasted from the
# document. A step that only works because the operator knew what was meant is
# a documentation defect, and catching those before a stranger does is the
# whole point. Re-run it after any change to the compose file or the doc.
#
#   bash scripts/selfhost-smoke.sh        # ~/selfhost-test, log at ~/selfhost-run.log
set -uo pipefail

RUN=~/selfhost-test
LOG=~/selfhost-run.log
: > "$LOG"
say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

say "=== FR-42 P0: self-host from a clean clone ==="
say "docker: $(docker --version)"
say "compose: $(docker compose version | head -1)"
say "host: $(. /etc/os-release; echo "$PRETTY_NAME") $(uname -m)"

# --- clean slate ------------------------------------------------------------
if [ -d "$RUN" ]; then
  say "tearing down any previous run"
  (cd "$RUN" && docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost down -v >/dev/null 2>&1) || true
  rm -rf "$RUN"
fi

# --- STEP 1: the document's clone ------------------------------------------
say "STEP 1  git clone (document says: git clone https://github.com/jk-zhang-meta/MeshHarbor.git)"
T0=$(date +%s)
git clone --depth 1 https://github.com/jk-zhang-meta/MeshHarbor.git "$RUN" >>"$LOG" 2>&1 \
  || { say "FAIL: clone"; exit 1; }
cd "$RUN"
say "        cloned in $(( $(date +%s) - T0 ))s, HEAD=$(git rev-parse --short HEAD)"

# --- does the document's file actually exist in a clean clone? -------------
for f in docker-compose.selfhost.yml .env.selfhost.example docs/self-hosting.md; do
  [ -f "$f" ] && say "        ✔ $f present" || { say "        ✘ MISSING $f"; exit 1; }
done

# --- STEP 2: the document's cp + fill --------------------------------------
say "STEP 2  cp .env.selfhost.example .env.selfhost, then fill the 4 REQUIRED values"
cp .env.selfhost.example .env.selfhost
JWT=$(openssl rand -hex 32)
TURN=$(openssl rand -hex 32)
MONGOPW=$(openssl rand -hex 24)
MINIOPW=$(openssl rand -hex 24)
sed -i "s|^MESHHARBOR_JWT_SECRET=.*|MESHHARBOR_JWT_SECRET=$JWT|" .env.selfhost
sed -i "s|^MESHHARBOR_TURN_SECRET=.*|MESHHARBOR_TURN_SECRET=$TURN|" .env.selfhost
sed -i "s|^MONGO_ROOT_PASSWORD=.*|MONGO_ROOT_PASSWORD=$MONGOPW|" .env.selfhost
sed -i "s|^MINIO_ROOT_PASSWORD=.*|MINIO_ROOT_PASSWORD=$MINIOPW|" .env.selfhost
say "        filled; remaining empty REQUIRED values: $(grep -cE '^(MESHHARBOR_JWT_SECRET|MESHHARBOR_TURN_SECRET|MONGO_ROOT_PASSWORD|MINIO_ROOT_PASSWORD)=$' .env.selfhost)"

# --- STEP 3: the document's up ---------------------------------------------
say "STEP 3  docker compose ... up -d --build   (document claims 10-20 min first build)"
BUILD_T0=$(date +%s)
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost up -d --build >>"$LOG" 2>&1
RC=$?
BUILD_SECS=$(( $(date +%s) - BUILD_T0 ))
say "        up exited rc=$RC after ${BUILD_SECS}s ($(( BUILD_SECS / 60 ))m$(( BUILD_SECS % 60 ))s)"
if [ $RC -ne 0 ]; then
  say "FAIL: compose up. Last 40 lines:"
  tail -40 "$LOG"
  docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost ps 2>&1 | tee -a "$LOG"
  exit 1
fi

say "        containers:"
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost ps --format '          {{.Service}}  {{.State}}  {{.Status}}' 2>&1 | tee -a "$LOG"

# --- STEP 4: the document's health check -----------------------------------
say "STEP 4  curl -fsS http://localhost:8080/health  (document's own command)"
for i in $(seq 1 60); do
  if curl -fsS http://localhost:8080/health >/dev/null 2>&1; then
    say "        /health answered 200 after ${i}0s"
    curl -fsS http://localhost:8080/health 2>&1 | head -3 | tee -a "$LOG"
    break
  fi
  [ "$i" = 60 ] && { say "        ✘ /health never answered within 600s"; docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost logs --tail 60 meshharbor 2>&1 | tee -a "$LOG"; exit 1; }
  sleep 10
done

# --- STEP 5: does the SPA actually serve? ----------------------------------
say "STEP 5  the page a human would open"
CODE=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/ 2>&1)
say "        GET / -> $CODE"
say "        install.sh -> $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/api/setup/install.sh)"
say "        stripe/plans -> $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/api/stripe/plans)"

say "=== P0 COMPLETE — build ${BUILD_SECS}s ==="
