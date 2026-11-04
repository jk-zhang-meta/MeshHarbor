# Performance Patterns — MeshHarbor

### Deployment Strategy: Recreate — noted 2026-03-10
**Symptom:** Downtime during deployments
**Root cause:** K8s deployment uses `strategy: Recreate` instead of `RollingUpdate`
**Status:** OPEN — acceptable for current scale, revisit when zero-downtime is required
**Recurrence prevention:** When scaling beyond single-pod, switch to RollingUpdate with readiness gates

### MongoDB Native Driver: No ORM Overhead — noted 2026-03-10
**Pattern:** MeshHarbor uses MongoDB native driver (v3.2) directly, not Mongoose
**Benefit:** No document overhead (no .lean() needed like Mongoose), raw BSON queries
**Caution:** All queries are raw BSON documents — ensure proper indexing for every hot-path query
**Index registry:** `crates/db/src/indexes.rs` — 15 collections with comprehensive indexes

### Binary + Image Size Tracking — noted 2026-03-10
**Pattern:** Monitor `target/release/meshharbor-api` binary size and Docker image size
**Status:** Baseline not yet established — will be captured on first health check run
**Recurrence prevention:** Health check compares against baseline and flags >10% growth
