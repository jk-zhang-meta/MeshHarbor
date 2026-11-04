# Security Patterns — Roomler AI

### CORS Fully Permissive — discovered 2026-03-10
**Symptom:** Any origin can make authenticated requests to the API
**Root cause:** `CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)` in `crates/api/src/lib.rs:20-23`
**Status:** OPEN — CRITICAL risk for production
**Fix proposed:** Use `settings.app.cors_origins` (already defined in Settings struct) to configure allowed origins:
```rust
let cors = CorsLayer::new()
    .allow_origin(settings.app.cors_origins.iter().map(|o| o.parse().unwrap()).collect::<Vec<_>>())
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
    .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
```
**Recurrence prevention:** Health check scans for `allow_origin(Any)` in lib.rs

### No Rate Limiting — discovered 2026-03-10
**Symptom:** All endpoints are unthrottled — vulnerable to brute-force and DoS
**Root cause:** No rate limiting middleware configured in Axum
**Status:** OPEN — HIGH risk, especially for /api/auth/login
**Fix proposed:** Add `tower_governor` or custom rate limiting middleware
**Recurrence prevention:** Health check scans route files for rate limiting middleware

### JWT Default Secret — discovered 2026-03-10
**Symptom:** Default JWT secret is "change-me-in-production"
**Root cause:** `crates/config/src/settings.rs:239` sets `.set_default("jwt.secret", "change-me-in-production")`
**Status:** OPEN — production MUST override via `MESHHARBOR__JWT__SECRET` env var
**Recurrence prevention:** Health check verifies JWT secret length > 32 chars in production

### Missing Nginx Security Headers — discovered 2026-03-10
**Symptom:** No security headers in nginx responses
**Root cause:** `files/nginx-pod.conf` has no `add_header` directives
**Status:** OPEN — MEDIUM risk
**Fix proposed:** Add to nginx config:
```nginx
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' wss:; media-src 'self' blob:;" always;
```
**Recurrence prevention:** Health check audits nginx config for security headers

### Auth Middleware Coverage — discovered 2026-03-10
**Symptom:** Need to verify all tenant-scoped routes require authentication
**Root cause:** Axum uses middleware layers — must ensure auth middleware covers all `/api/tenant/*` routes
**Status:** Needs verification — health check should scan for unprotected tenant routes
**Recurrence prevention:** Health check cross-references route definitions with auth middleware application
