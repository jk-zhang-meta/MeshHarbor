# Implementation Plan: Daily Automated Health Check for Roomler AI

## Requirements Restatement

Replicate the same health check infrastructure from the lgr repo, adapted for roomler-ai's Rust/Axum/Vue 3/MongoDB stack:

1. **`CLAUDE.md`** — Project knowledge base (architecture, commands, patterns, known issues, health check results)
2. **`.claude/skills/`** — Domain knowledge files (performance-patterns.md, security-patterns.md)
3. **`.claude/daily-health-check-prompt.md`** — Self-contained health check prompt adapted from the template (Elysia→Axum, bun test→cargo test, etc.)
4. **`.github/workflows/daily-health-check.yml`** — GitHub Actions workflow for automated daily execution

## Key Differences from lgr (Elysia.js) → roomler-ai (Rust/Axum)

| Aspect | lgr | roomler-ai |
|--------|-----|------------|
| Backend | Elysia.js (Bun) | Rust (Axum 0.8) |
| Backend test | `bun run test` | `cargo test -p meshharbor-tests` |
| Typecheck | `bunx tsc --noEmit` | `cargo clippy` (Rust) + `vue-tsc --noEmit` (Vue) |
| Lint | `bun run lint` | No linting configured |
| Dep audit | `bun audit` | `cargo audit` (Rust) + `bun audit` (UI) |
| Dep outdated | `bun outdated` | `cargo outdated` (Rust) + `bun outdated` (UI) |
| Frontend | Vue 3 + Vuetify 3 | Same |
| DB | MongoDB (Mongoose) | MongoDB (native driver v3.2) |
| Deploy | Docker Compose | Ansible → K8s (roomler-ai-deploy) |
| CI | None | None (creating new) |

## Phase 1: Create `CLAUDE.md`

**File**: `<repo>/CLAUDE.md`

Content sections (mirroring lgr's structure):
- **Project Overview**: Roomler AI — real-time collaboration platform (chat, video conferencing, file sharing, rooms). Rust backend + Vue 3 frontend + MongoDB.
- **Commands**: cargo build, cargo test, cargo clippy, bun run dev, bun run build, bun run test:unit, bun run e2e, docker compose up -d
- **Architecture**: 5-crate workspace (config, db, services, api, tests), crate dependency flow, ~75 API routes
- **Crate Structure**: config → db → services → api; tests depends on api+config+db
- **Multi-Tenancy**: tenant_id scoping on all data models, tenant_members collection
- **Auth Pattern**: JWT (jsonwebtoken 9) + Argon2, access/refresh tokens, OAuth (5 providers)
- **Route Pattern**: Axum Router with nested routes under `/api/tenant/{tenant_id}/...`
- **DB Model Pattern**: MongoDB native driver, 15 collections, 19 model files, indexes in indexes.rs
- **Frontend Conventions**: Vue 3 + Vuetify 3 + Pinia (setup stores), TipTap editor, mediasoup WebRTC
- **Test Setup**: Cargo integration tests (random DB per test), Vitest (1 spec), Playwright (18 specs)
- **Environment**: docker-compose.yml (MongoDB:27019, Redis:6379, MinIO:9000, coturn)
- **Deployment**: Docker multi-stage build → Ansible → K8s (roomler-ai-deploy repo)
- **Known Issues**: (initially populated with current findings from exploration)
- **Last Health Check**: (placeholder for first run)

## Phase 2: Create `.claude/skills/` Directory

**File**: `<repo>/.claude/skills/performance-patterns.md`
- Initial content: document known patterns (CORS permissive config, deployment strategy Recreate, no rate limiting)

**File**: `<repo>/.claude/skills/security-patterns.md`
- Initial content: document known security findings (permissive CORS, no rate limiting, JWT default secret, missing nginx security headers, 5 TS type errors)

## Phase 3: Create `.claude/daily-health-check-prompt.md`

**File**: `<repo>/.claude/daily-health-check-prompt.md`

Heavily adapted from the template. Key adaptations:

### Phase 0 — Self-Orientation
- Read CLAUDE.md, .claude/skills/, git log, git stash (same as template)

### Phase 1 — Environment & Dependency Audit
- `cargo outdated` (Rust deps) + `bun outdated` in ui/ (JS deps)
- `cargo audit` (Rust CVEs) + `bun audit` (JS CVEs)
- Code smell scan: TODO/FIXME/HACK/XXX/SECURITY/UNSAFE in *.rs, *.ts, *.vue
- Hardcoded secrets scan in *.rs, *.ts, *.vue, *.env*
- Dockerfile base image check (rust:1.88-bookworm, oven/bun:1, debian:trixie-slim)
- K8s manifest check in roomler-ai-deploy templates

### Phase 2 — Static Analysis & Type Safety
- `cargo check --workspace` (compilation)
- `cargo clippy --workspace -- -D warnings` (Rust lint)
- `cd ui && vue-tsc --noEmit` (Vue typecheck — baseline: 5 errors)
- No ESLint/Biome (note as gap)
- Scan Axum route handlers for: missing auth middleware, unguarded DB calls, N+1 patterns
- Scan MongoDB usage: queries without indexes, missing pagination
- Rust-specific: .unwrap()/.expect() outside tests, unsafe blocks, unnecessary .clone()

### Phase 3 — Test Execution
- Start services: `docker compose up -d mongo redis minio`
- Backend: `cargo test -p meshharbor-tests` (114 integration tests)
- Frontend unit: `cd ui && bun run test:unit` (Vitest)
- E2E: NOT run in automated daily check (requires full stack + browser)
- Coverage gap analysis (note: Rust coverage requires cargo-tarpaulin)

### Phase 4 — Performance Profiling
- Skip (no autocannon/k6 configured; note as gap for future setup)
- Check binary size: `ls -la target/release/meshharbor-api`
- Check Docker image size

### Phase 5 — Security Audit
- CORS audit: check lib.rs for CorsLayer config (CRITICAL: currently Any/Any/Any)
- Rate limiting check: scan for rate limiting middleware (CRITICAL: none exists)
- JWT: check settings.rs defaults (secret="change-me-in-production", TTLs)
- Auth middleware: verify all tenant-scoped routes require auth
- nginx security headers: check files/nginx-pod.conf
- Dependency CVE rescan

### Phase 6 — UI Quality Check
- Skip automated Playwright in daily check
- Check for Vue build warnings
- Verify TypeScript error count vs baseline

### Phase 7 — Bug Triage & Report
- Compile all issues, prioritize CRITICAL→HIGH→MEDIUM→LOW
- Do NOT auto-fix source code
- Update CLAUDE.md with findings
- Generate report to `.claude/reports/YYYY-MM-DD-health-check.md`

### Phase 8 — Deployment Readiness (report only)
- `cargo build --release` verification
- `cd ui && bun run build` verification
- Docker build dry-run check
- Report deployment readiness status (do NOT trigger actual deployment)

### Phase 9 — Learning & Memory Update
- Update CLAUDE.md sections: Last Health Check, Known Issues, Performance Baselines
- Update .claude/skills/ if new patterns discovered
- Commit CLAUDE.md and .claude/ updates

### Phase 10 — Final Report
- Structured report (same format as template)
- Overall status: HEALTHY / DEGRADED / CRITICAL

## Phase 4: Create GitHub Actions Workflow

**File**: `<repo>/.github/workflows/daily-health-check.yml`

```yaml
name: Daily Health Check
on:
  schedule:
    - cron: '0 6 * * *'   # 6:00 UTC daily
  workflow_dispatch:

jobs:
  health-check:
    runs-on: ubuntu-latest
    timeout-minutes: 60

    services:
      mongo:
        image: mongo:7
        ports: ['27019:27017']
        env:
          MONGO_INITDB_ROOT_USERNAME: roomler
          MONGO_INITDB_ROOT_PASSWORD: R00m1eR_5uper5ecretPa55word
      redis:
        image: redis:7-alpine
        ports: ['6379:6379']

    steps:
      - Checkout repo
      - Install Rust toolchain (stable) + clippy
      - Rust cache (Swatinem/rust-cache)
      - Install cargo-audit
      - Install Bun
      - Install UI deps (bun install --frozen-lockfile)
      - Install system deps (libclang-dev, cmake, python3-pip for mediasoup)
      - Install Claude Code CLI
      - Create reports directory
      - Run health check prompt via Claude Code
      - Commit results (CLAUDE.md + reports)
      - Upload report artifact
      - Notify on failure (Slack webhook)
```

## Files to Create (4 files)

| # | File | Est. Lines | Purpose |
|---|------|-----------|---------|
| 1 | `CLAUDE.md` | ~180 | Project knowledge base |
| 2 | `.claude/skills/performance-patterns.md` | ~20 | Performance patterns (initial) |
| 3 | `.claude/skills/security-patterns.md` | ~30 | Security patterns (initial) |
| 4 | `.claude/daily-health-check-prompt.md` | ~450 | Health check prompt adapted for Rust stack |
| 5 | `.github/workflows/daily-health-check.yml` | ~100 | GitHub Actions workflow |

## Implementation Order

1. `CLAUDE.md` (foundation — the prompt reads this first)
2. `.claude/skills/*.md` (knowledge files the prompt consumes)
3. `.claude/daily-health-check-prompt.md` (the prompt itself)
4. `.github/workflows/daily-health-check.yml` (automation wrapper)

## Risks

- **mediasoup native build in CI**: Requires libclang-dev + cmake. GitHub Actions ubuntu-latest may need explicit install.
- **MongoDB auth in CI**: docker-compose uses auth but cargo tests default to `mongodb://localhost:27019` without auth. CI needs `ROOMLER__DATABASE__URL` env var.
- **Rust compilation time in CI**: Full workspace build ~5-10 min. Using Swatinem/rust-cache mitigates.
- **No cargo-tarpaulin**: Rust code coverage requires additional tooling (not blocking).
- **Claude Code API costs**: Daily health check consumes API tokens. ~50 turns per run.

## Decisions Made (recommended defaults)

- **Deployment**: Report-only (no auto-deploy via Ansible)
- **Auto-fix scope**: Report + CLAUDE.md commits only (no source code changes)
- **Execution**: GitHub Actions (with manual trigger option)
