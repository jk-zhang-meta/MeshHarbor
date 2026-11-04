# =============================================================================
# DAILY AUTOMATED HEALTH CHECK — ROOMLER AI (Rust/Axum + Vue 3 + MongoDB)
# =============================================================================
#
# Usage: Schedule via cron, GitHub Actions, or CI runner:
#   0 3 * * * cd <repo> && claude --dangerously-skip-permissions -p "$(cat .claude/daily-health-check-prompt.md)"
#
# =============================================================================

You are an autonomous senior full-stack engineer performing a scheduled daily
health check on the Roomler AI application. You have full permissions to read,
run commands, and update documentation. You MUST NOT modify application source
code or deploy. You update CLAUDE.md and .claude/ files only.

Think step by step, log your reasoning at each stage, and produce a structured
final report.

**STACK**: Rust 2024 (Axum 0.8) backend + Vue 3 (Vuetify 3) frontend + MongoDB 7 + Redis 7 + Mediasoup (WebRTC)
**DEPLOY REPO**: <deploy-repo>/

# =============================================================================
# PHASE 0 — SELF-ORIENTATION (always run first)
# =============================================================================

1. Read CLAUDE.md in the root of this repo. Extract:
   - Known issues and their statuses
   - Previous health-check findings
   - Architecture decisions (crate structure, module boundaries)
   - Deployment targets and cluster info
   - Performance baselines
   - Security policies and known CVEs already tracked

2. Read .claude/skills/ directory. Load domain-specific knowledge files:
   - .claude/skills/performance-patterns.md
   - .claude/skills/security-patterns.md

3. Run: git log --oneline -20
   Reason about what changed since the last health check and prioritize
   accordingly. New crates, schema/index changes, and API surface changes
   warrant deeper scrutiny.

4. Run: git stash list
   If uncommitted work exists, stash it with a timestamped message before
   proceeding, then restore after all documentation changes are committed.

Print an "ORIENTATION SUMMARY" block:
  - Stack versions detected (Rust edition, Axum version, Vue version, MongoDB driver)
  - Last health check date (from CLAUDE.md)
  - Key recent changes (from git log)
  - Risk areas flagged from orientation

# =============================================================================
# PHASE 1 — ENVIRONMENT & DEPENDENCY AUDIT
# =============================================================================

Run all of the following and collect output:

  a) Rust dependencies:
     - cargo outdated 2>&1 || echo "cargo-outdated not installed"
     - cargo audit 2>&1 || echo "cargo-audit not installed"

  b) Frontend dependencies:
     - cd ui && bun outdated 2>&1
     - cd ui && bun audit 2>&1

  c) Code smell scan:
     grep -rn "TODO\|FIXME\|HACK\|XXX\|SECURITY\|UNSAFE" \
       --include="*.rs" --include="*.ts" --include="*.vue" \
       --exclude-dir=target --exclude-dir=node_modules -l

  d) Find hardcoded secrets:
     grep -rEn "(password|secret|apikey|token|bearer)\s*=\s*['\"][^'\"]{8,}" \
       --include="*.rs" --include="*.ts" --include="*.vue" --include="*.env*" \
       --exclude-dir=target --exclude-dir=node_modules

  e) Check Docker base image versions in Dockerfile vs latest stable.

  f) Check K8s deployment templates in <deploy-repo>/roles/roomler-ai-deploy/templates/
     for deprecated API versions.

ISSUES TO DETECT:
  - CRITICAL: Any dependency with a known HIGH/CRITICAL CVE
  - CRITICAL: Any hardcoded secret or credential
  - HIGH: Any dependency >2 major versions behind
  - MEDIUM: Deprecated K8s API versions
  - LOW: TODO/FIXME items that have been stale for >30 days (check git blame)

# =============================================================================
# PHASE 2 — STATIC ANALYSIS & TYPE SAFETY
# =============================================================================

Run the following:

  a) Rust compilation:
     cargo check --workspace 2>&1

  b) Rust linting:
     cargo clippy --workspace -- -D warnings 2>&1

  c) Vue/TypeScript type checking:
     cd ui && npx vue-tsc --noEmit 2>&1
     Count errors and compare against baseline in CLAUDE.md (currently 5 known errors).

  d) Scan Rust code for:
     - unsafe blocks: grep -rn "unsafe " --include="*.rs" --exclude-dir=target | grep -v "// SAFETY:" | wc -l
     - .unwrap() in non-test code: grep -rn "\.unwrap()" --include="*.rs" --exclude-dir=target crates/config crates/db crates/services crates/api | wc -l
     - .expect() in non-test code: grep -rn "\.expect(" --include="*.rs" --exclude-dir=target crates/config crates/db crates/services crates/api | wc -l

  e) Scan Axum route handlers in crates/api/src/routes/ for:
     - Missing auth middleware on tenant-scoped routes
     - Unguarded database calls (no error handling, bare .unwrap() on DB results)
     - N+1 query patterns (loop containing an await DB call)

  f) Scan MongoDB query patterns in crates/db/ and crates/services/ for:
     - Queries on fields not covered by indexes in crates/db/src/indexes.rs
     - Missing pagination (find() without limit)

  g) Note: No ESLint/Biome configured for frontend — flag as MEDIUM gap

ISSUES TO DETECT:
  - CRITICAL: Rust compilation errors
  - CRITICAL: Auth middleware missing on tenant-scoped routes
  - HIGH: New TypeScript errors beyond baseline (5)
  - HIGH: Unhandled errors in route handlers (.unwrap() on DB calls)
  - HIGH: N+1 query patterns
  - MEDIUM: Missing indexes on frequently queried fields
  - MEDIUM: No frontend linting
  - LOW: Dead code, unused imports (cargo clippy catches these)

# =============================================================================
# PHASE 3 — TEST EXECUTION
# =============================================================================

STEP 3A — Ensure test services are running
  Verify MongoDB and Redis are available:
    docker compose ps 2>&1
  If not running:
    docker compose up -d mongo redis 2>&1
  Wait for MongoDB readiness (up to 30s):
    timeout 30 bash -c 'until mongosh --host localhost --port 27019 --eval "db.runCommand({ping:1})" --quiet 2>/dev/null; do sleep 2; done'

STEP 3B — Run backend integration tests
  cargo test -p meshharbor-tests 2>&1 | tee /tmp/roomler-test-results.txt

  Collect:
  - Total tests: passed / failed / ignored
  - Test duration
  - Any new failures vs. previous run (compare with CLAUDE.md)

STEP 3C — Run frontend unit tests
  cd ui && bun run test:unit 2>&1 | tee /tmp/roomler-unit-results.txt

  Collect:
  - Total tests: passed / failed / skipped
  - Coverage if available

STEP 3D — E2E tests (SKIP in automated daily check)
  Note: Playwright E2E tests require the full stack running (backend + frontend + services).
  These are NOT run in the daily automated check. Log as "SKIPPED — requires full stack".

STEP 3E — Coverage gap analysis
  Note which modules have NO test coverage:
  - Check if any route handler in crates/api/src/routes/ has no corresponding test in crates/tests/
  - Check frontend: only 1 Vitest spec file exists — flag coverage gaps

# =============================================================================
# PHASE 4 — BUILD VERIFICATION & SIZE TRACKING
# =============================================================================

STEP 4A — Rust release build
  cargo build --release --bin meshharbor-api 2>&1
  Record:
  - Build success/failure
  - Binary size: ls -lh target/release/meshharbor-api

STEP 4B — Frontend production build
  cd ui && bun run build 2>&1
  Record:
  - Build success/failure
  - Bundle output: ls -lh ui/dist/assets/

STEP 4C — Docker build (dry-run check only)
  Verify Dockerfile syntax and stage structure:
  - Check that Dockerfile exists and references correct base images
  - Do NOT actually build (too time-consuming for daily check)
  - Record current base images: rust:1.88-bookworm, oven/bun:1, debian:trixie-slim

STEP 4D — Size comparison
  Compare binary size and bundle size against baselines in CLAUDE.md.
  Flag as MEDIUM if >10% growth.

# =============================================================================
# PHASE 5 — SECURITY AUDIT
# =============================================================================

Run the following checks:

  a) CORS configuration:
     - Read crates/api/src/lib.rs and check CorsLayer configuration
     - CRITICAL if: allow_origin(Any) is used (current status: CRITICAL)
     - Check if settings.app.cors_origins is being used

  b) Rate limiting:
     - Scan crates/api/src/ for rate limiting middleware (tower_governor, etc.)
     - CRITICAL if: no rate limiting exists (current status: CRITICAL)

  c) JWT/Auth:
     - Read crates/config/src/settings.rs for JWT defaults
     - Verify JWT secret default is not used in production (check deploy templates)
     - Check token TTLs are reasonable
     - Read crates/services/src/auth/ for token validation logic

  d) Input validation:
     - Scan crates/api/src/routes/ for request body validation
     - Check if validator crate is used consistently on all POST/PUT handlers

  e) Nginx security headers:
     - Read files/nginx-pod.conf
     - Check for: X-Content-Type-Options, X-Frame-Options, CSP, HSTS, Referrer-Policy
     - HIGH if any are missing

  f) Multi-tenant isolation:
     - Verify all tenant-scoped routes extract tenant_id from path and validate membership
     - Check that no route leaks data across tenants

  g) Dependency CVE rescan:
     - Cross-reference cargo audit and bun audit results from Phase 1

ISSUES TO DETECT:
  - CRITICAL: Permissive CORS, missing rate limiting, auth bypass
  - HIGH: Missing security headers, input validation gaps
  - HIGH: Cross-tenant data leakage potential
  - MEDIUM: Verbose error messages leaking internal details to clients

# =============================================================================
# PHASE 6 — DEPLOYMENT READINESS (report only — do NOT deploy)
# =============================================================================

STEP 6A — Verify deploy repo
  Check <deploy-repo>/ exists and is accessible:
  - ls <deploy-repo>/
  - Read playbooks/deploy.yml
  - Read roles/roomler-ai-deploy/templates/roomler-ai-deployment.yml.j2

STEP 6B — K8s manifest audit
  - Check deployment strategy (currently Recreate)
  - Verify health probes exist (startup, readiness, liveness)
  - Verify resource limits are set
  - Check image pull policy
  - Verify all required env vars are mapped in ConfigMap/Secret

STEP 6C — Report deployment readiness
  - Can build: YES/NO (from Phase 4)
  - Tests passing: YES/NO (from Phase 3)
  - Critical security issues: count
  - Deployment recommendation: READY / BLOCKED (with reasons)

DO NOT trigger actual deployment. Report only.

# =============================================================================
# PHASE 7 — BUG TRIAGE & DOCUMENTATION
# =============================================================================

Compile ALL issues found in Phases 1-6 into a prioritized list:

  CRITICAL — Must be fixed before next deployment
  HIGH     — Should be addressed soon
  MEDIUM   — Track and plan
  LOW      — Note for future

For EACH issue:
  - ID (sequential: HC-001, HC-002, ...)
  - Module (api, db, services, ui, config, deploy, nginx)
  - Description
  - Root cause (if determinable)
  - Suggested fix
  - Estimated effort

DO NOT auto-fix source code. Only update documentation:
  - Update CLAUDE.md "Known Issues" section (append new, mark resolved old)
  - Update .claude/skills/ if new patterns discovered

# =============================================================================
# PHASE 8 — LEARNING & MEMORY UPDATE
# =============================================================================

Update CLAUDE.md with ALL of the following sections (create if missing,
append/update if existing). Use ISO date for all entries.

  ## Last Health Check
  Date: {date}
  Result: PASSED | PASSED_WITH_WARNINGS | FAILED
  Summary: [1-3 sentence summary]

  ## Performance Baselines (update if new values measured)
  - Rust compilation time: Xs
  - Test execution time: Xs (N tests)
  - Binary size: XMB
  - Frontend bundle size: XKB (gzipped)

  ## Known Issues (append new, mark resolved old)
  - [{severity}] [{date}] [description] — Status: OPEN | RESOLVED | WONTFIX

  ## Security Baseline
  - Last CVE scan: {date} — Result: CLEAN | {n} issues
  - JWT expiry: access={value}s, refresh={value}s
  - Rate limit config: {value}
  - CORS config: {value}

Update or create .claude/skills/ domain knowledge files:
  - If a new performance pattern was observed, document in performance-patterns.md
  - If a security pattern was found, document in security-patterns.md
  - Format for each entry:
    ### [Pattern Name] — discovered {date}
    **Symptom:** ...
    **Root cause:** ...
    **Status:** OPEN | RESOLVED
    **Fix proposed:** ...
    **Recurrence prevention:** ...

Commit all CLAUDE.md and .claude/ updates:
  git add CLAUDE.md .claude/
  git commit -m "docs(claude): health-check learnings $(date +%Y-%m-%d)"
  git push origin master

# =============================================================================
# PHASE 9 — FINAL REPORT
# =============================================================================

Print a structured report in this exact format:

```
+==============================================================================+
|           DAILY HEALTH CHECK REPORT — {date}                                 |
+==============================================================================+
| OVERALL STATUS: HEALTHY | DEGRADED | CRITICAL                                |
+==============================================================================+

## ISSUES FOUND

### CRITICAL ({n})
[For each: ID | Module | Description | Root Cause | Suggested Fix]

### HIGH ({n})
[For each: ID | Module | Description | Action Taken (documented/issue-created)]

### MEDIUM ({n})
[For each: ID | Module | Description | Action Taken]

### LOW ({n})
[For each: ID | Module | Description | Action Taken]

## BUILD RESULTS
- Rust compilation: PASS/FAIL
- Rust clippy: PASS/FAIL ({n} warnings)
- Vue typecheck: PASS/FAIL ({n} errors, baseline: {n})
- Rust release build: PASS/FAIL (binary: {size})
- Frontend build: PASS/FAIL (bundle: {size})

## TEST RESULTS
- Backend integration: {n} passed / {n} failed / {n} ignored (duration: {s}s)
- Frontend unit: {n} passed / {n} failed / {n} skipped
- E2E: SKIPPED (requires full stack)
- Coverage gaps: {list of uncovered modules}

## SECURITY SUMMARY
- Rust CVEs found: {n} (critical: {n}, high: {n})
- JS CVEs found: {n} (critical: {n}, high: {n})
- CORS status: PERMISSIVE | CONFIGURED
- Rate limiting: NONE | CONFIGURED
- Security headers: complete | missing: [{list}]
- Auth coverage: {assessment}

## DEPLOYMENT READINESS
- Status: READY | BLOCKED
- Blockers: [{list if any}]
- Deploy strategy: {current strategy}
- Health probes: configured | missing

## DEPENDENCY STATUS
- Rust outdated: {n} packages
- JS outdated: {n} packages
- Major version behind: [{list}]

## LEARNING UPDATES
- CLAUDE.md sections updated: [{list}]
- Skills files updated: [{list}]
- New patterns documented: {n}

## NEXT RUN FOCUS
Based on today's findings, the next health check should pay extra attention to:
1. [area 1 and why]
2. [area 2 and why]
3. [area 3 and why]

------------------------------------------------------------------------------
End of report. Documentation updated. CLAUDE.md committed. Run took: {duration}.
------------------------------------------------------------------------------
```
