# FR-50: The installer cannot know which server handed it to you

> **CLOSED 2026-09-01** — issue #1083 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#1083](https://github.com/gjovanov/roomler-ai/issues/1083) ·
Status: **P0 — spec** (2026-08-31) · Child of
[FR-42](FR-42-selfhost-verified-on-a-clean-box.md) (#967), which found this by
running the documented self-host path on a clean box.

## Goal

A device installed from a self-hosted Roomler must enrol **against that
Roomler**. Today it enrols against the hosted service, because the installer
carries a compile-time default and a piped script cannot see the URL it was
fetched from.

The fix belongs on the server, not in the document: the route that serves the
script substitutes the default before the bytes leave the process.

## Root cause, with anchors

`scripts/install.sh:46`

```sh
SERVER="https://roomler.ai"
```

`scripts/install.ps1:64`

```powershell
[string]$Server = 'https://roomler.ai',
```

Both are served by `crates/api/src/routes/setup_release.rs:170-189` as
compile-time constants:

```rust
const INSTALL_SH: &str = include_str!("../../../../scripts/install.sh");
const INSTALL_PS1: &str = include_str!("../../../../scripts/install.ps1");

pub async fn install_script_sh() -> Response {
    script_response(INSTALL_SH, "text/x-shellscript; charset=utf-8")
}
```

The handlers take **no state and no request** — they cannot know their own
origin even in principle. And the documented invocation is a pipe:

```sh
curl -fsSL https://my-roomler.example/api/setup/install.sh | sh -s -- --role daemon --token <jwt>
```

so there is no filename, no `$0`, and no referrer for the script to inspect
either. The information exists only on the server.

## What the operator actually experiences

This is the **first thing anyone does after their own stack comes up**, and it
fails in the least legible way available:

1. They copy the one-liner from *their* server's docs.
2. `curl` fetches it from their host. The script downloads the agent from
   *their* host too (`$SERVER/api/agent/installer/...` — that part is
   parameterised and works).
3. It then runs `roomlerd enroll --server https://roomler.ai --token <jwt>`.
4. The hosted service rejects a token only their server can verify.

The error names the token, not the server. Nothing in the output says
`roomler.ai` was contacted unless the operator reads the whole log. A
self-hoster's reasonable first conclusion is that **the product's enrolment is
broken**, and the FR-42 field run reached exactly that conclusion before
reading the source.

⚠️ It is also worse than a plain failure on the `--role tunnel` path, where the
enrolment is the *only* server-bound step: a tunnel client that enrols against
`roomler.ai` with a token from elsewhere leaks the token's existence to a
third-party server. Not the token's *value* — it is single-use and invalid
there — but the request is made.

## Key design

**Substitute at serve time from `app.frontend_url`.**

`frontend_url` is already the canonical "which server am I" value: it builds
OAuth returns (`routes/auth.rs:167`), invite links (`routes/invite.rs:636`),
subscriber confirm/unsubscribe links (`routes/subscribe.rs:157,204`) and — since
the 2026-07-28 tightening — the **CORS origin policy** itself
(`crates/api/src/origin.rs:37`). A deployment whose `frontend_url` is wrong has
a broken SPA before it has a broken installer. So this adds no new failure mode;
it makes the installer follow an identity the deployment already had to get
right.

### The substitution must be locked, not hopeful

A blind `String::replace` on a shell script is a silent-failure machine: edit
the line, and the server keeps serving the old default with nothing failing.

So each script carries an explicit, commented marker line, and the route holds
the needle as a constant with a **unit test asserting it occurs exactly once**
in each embedded script. Editing the line fails the build.

```rust
const SERVER_NEEDLE_SH: &str = "SERVER=\"https://roomler.ai\"";
const SERVER_NEEDLE_PS1: &str = "[string]$Server = 'https://roomler.ai',";

#[test]
fn the_server_default_is_substitutable_exactly_once() {
    assert_eq!(INSTALL_SH.matches(SERVER_NEEDLE_SH).count(), 1);
    assert_eq!(INSTALL_PS1.matches(SERVER_NEEDLE_PS1).count(), 1);
}
```

### The value is validated, and a bad one changes nothing

`frontend_url` is config, and config arrives from an environment variable. The
substituted text lands inside a shell double-quoted string and a PowerShell
single-quoted string, in a script that then runs **as root / SYSTEM**. A value
containing `"`, `$`, `` ` `` or a newline would be command injection into an
installer, authored by whoever can set an env var on the API.

So the accepted shape is narrow and positive — scheme, host, optional port,
nothing else:

```
^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/?$
```

Anything outside it (a path, userinfo, a query, any shell metacharacter) is
**refused, and the compiled-in default is served unchanged**, with a warning
logged. Refusing to substitute is always safe: it is exactly today's behaviour.

⚠️ Deliberately **not** the request's `Host` header. It is client-controlled, it
varies with every reverse proxy in front, and it would make the served script
depend on how it was addressed rather than on how the deployment is configured
— a difference nobody could debug from the output.

### Prod is a byte-for-byte no-op — verified before writing the code

```
$ kubectl -n roomler-ai get cm -o yaml | grep FRONTEND_URL
    MESHHARBOR__APP__FRONTEND_URL: https://roomler.ai
```

The hosted service substitutes `https://roomler.ai` for `https://roomler.ai`.
That is what makes this safe to ship without a staged rollout: the population
that could regress is the population whose served bytes do not change.

## Phases

| # | Phase | Kill switch | Status |
|---|-------|-------------|--------|
| P1 | Serve-time substitution + needle lock + value validation | Serve the compiled-in default (validation refusal path); no flag needed — the fallback *is* today's behaviour | planned |
| P2 | Docs: drop the `--server` caveat for the served path, keep it for a git checkout | n/a (docs) | planned |
| P3 | Startup warning when `environment=production` and `frontend_url` is still the built-in dev default | n/a | proposed |

## Acceptance criteria

- [ ] `curl <self-hosted>/api/setup/install.sh` returns a script whose `SERVER`
      is that host, not `roomler.ai` — verified against a **running** self-host
      instance, not a unit test
- [ ] `curl https://roomler.ai/api/setup/install.sh` is byte-identical to the
      committed `scripts/install.sh`
- [ ] the same holds for `install.ps1`
- [ ] a `frontend_url` carrying a shell metacharacter serves the compiled-in
      default and logs a refusal (unit test)
- [ ] editing the `SERVER=` line in either script fails `cargo test -p meshharbor-api`
- [ ] `docs/self-hosting.md` and `README.md` no longer instruct the reader to
      pass `--server` on the served path

## Out of scope

- **The GUI wizard** (`agents/meshharbor-setup`) has a server field the operator
  fills in, and is not piped. Unaffected.
- **`roomler self-update`** resolving its own origin — a different fetch with a
  different (signed) trust story, tracked separately.
- **Publishing a container image** so the self-host path is a pull rather than a
  build. Real, and the single largest remaining friction on that path, but it is
  FR-42's P3, not this.

## Open decisions

- **P3's scope.** Warning at startup on a default `frontend_url` in production
  is cheap and catches the misconfiguration this FR now depends on. Refusing to
  boot (the JWT-secret precedent) is too aggressive: a wrong `frontend_url`
  degrades links, it does not compromise anything.

## Field-verification log

_(appended as it happens)_
