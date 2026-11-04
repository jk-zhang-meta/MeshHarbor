# FR-66: A healthy host is told to re-enroll, on every single service start

**Issue:** [#1263](https://github.com/gjovanov/roomler-ai/issues/1263) ·
**Status:** **COMPLETE** — P1 + P2 shipped and mutation-checked, P3 field-verified
on 0.4.55 → 0.4.73 with the failing run on 0.4.53 recorded beside it ·
**Owner:** agent/windows-service

## Goal

`roomlerd` must not log an operator-actionable ERROR that is false. Specifically:
a feature-flag probe that expects to find nothing, and correctly handles finding
nothing, must not emit `the host must be re-enrolled` about a host that is
enrolled, connected, and serving.

## Field evidence (neo16, 0.4.48, 2026-09-02)

Every service start logs this — three times on the day it was found:

```
ERROR config unreadable and no usable previous copy — the host must be re-enrolled
  path=C:\ProgramData\roomler\roomler\config.toml
  error=reading config at C:\ProgramData\roomler\roomler\config.toml:
        The system cannot find the file specified. (os error 2)
  prev=C:\ProgramData\roomler\roomler\config.toml.prev
  prev_error=... (os error 2)
```

The host it says that about:

```
● (this device)
  version     0.4.48        mode  service (SYSTEM)
  server      connected
  enrollments primary  connected, overlay tun (primary)
              jovanov  connected, overlay tun
```

Both enrollments up, overlay carrying traffic, config saved **that morning**.

### Why the file it names is legitimately absent

Three log lines apart, the same start says:

```
config: resolved load path
  config_path=C:\Windows\system32\config\systemprofile\...\roomler\config\config.toml
  is_system_context=true
  machine_global=C:\ProgramData\roomler\roomler\config.toml
supervisor: M3 A1 auto-swap (user-context -> SystemContext) is DISABLED (default)
supervisor: spawned worker  pid=109640  session_id=1  elevated=true
```

The worker runs **in session 1 as the elevated user**, so the config it actually
uses is `%APPDATA%\roomler\roomler\config\config.toml` — live, 3 670 bytes,
rewritten the same day, with a healthy same-second `.prev` beside it (the atomic
save working exactly as designed). The machine-global path is simply not this
install's topology. Nothing is wrong.

## Root cause

`agents/meshharbord/src/win_service/supervisor.rs:974` — `netd_enabled()`:

```rust
fn netd_enabled() -> bool {
    if let Some(v) = tunnel_core::env::node_env("OVERLAY_NETD") {
        return netd_flag_truthy(&v);
    }
    let p = crate::config::machine_global_config_path();
    crate::config::load(&p)
        .ok()
        .and_then(|c| c.overlay_netd)
        .unwrap_or(false)
}
```

Its **behaviour is correct**: `.ok()` + `unwrap_or(false)` means "absent ⇒ the
flag is off", which is right, and `overlay_netd` gates a scaffold that (per its
own doc comment) *hosts nothing yet*.

The defect is that `config::load` (`crates/agent-core/src/config.rs:2608`) is
not a neutral reader. On the both-copies-missing arm it logs
`tracing::error!(… "the host must be re-enrolled")`
(`crates/agent-core/src/config.rs:2620-2417`) before returning `Err`.

That severity is right for its *original* caller — the 2026-08-12 self-heal for
an all-NUL config, where the worker really was exit-1'ing every 60 s and
re-enrollment really was the remedy. It is wrong for a probe asking whether an
optional flag happens to be set somewhere it usually isn't.

**A shared helper logging at the severity of its worst caller.** Every caller
inherits the loudest interpretation of a failure, including the callers for whom
that failure is the normal case.

## Why it matters more than a noisy line

1. **It prescribes a destructive remedy.** Re-enrollment is not free: removal is
   final (`overlay_nodes` rows are tombstoned, `find_live_by_tenant_and_machine`
   is live-scoped), so a device that re-enrolls gets a **fresh lease and never
   its old address back**. An operator who believes this line renumbers a
   working host.
2. **It destroys the signal it exists to send.** The genuine all-NUL case emits
   the identical line, so the message that was designed to be unmissable is now
   indistinguishable from routine start-up noise. The self-heal's own comment
   says *"Loud, because silently running on an older config must never look like
   a normal boot"* — that property is already lost.
3. **It is invisible to every health check.** `roomler status`, `roomler peers`
   and the server's `is_online` all read healthy, so nothing contradicts the log.
   This is the inverse of the `systemctl is-active` trap in `CLAUDE.md`: there,
   a healthy host reads dead; here, a healthy host reads doomed.

## Design

**The probe must not go through the recovery path at all.** Absence of an
optional machine-global config is not a failure to be recovered from — it is an
expected input to a boolean question.

- `config::load` keeps its behaviour and its ERROR **unchanged**: its contract is
  *"load the config this process runs on"*, and for that caller the message and
  its severity are correct.
- Add a sibling for probes that returns `Option<AgentConfig>` and logs at most
  `debug!`, then point `netd_enabled()` at it. Naming it for the question rather
  than the mechanism (`load_optional` / `probe`) is what stops the next probe
  reaching for `load` again.
- ⚠️ Do **not** fix this by softening `load`'s ERROR to `warn!`. The all-NUL case
  is exactly as serious as it was, and quietening it to fix a caller that should
  not be calling it would trade a false alarm for a missed one.

## Phases

| phase | what | kill switch | status |
|---|---|---|---|
| P1 | `config::read_if_present` + `netd_enabled()` uses it; the no-ERROR property unit-locked and mutation-checked | revert (one function) | **shipped** |
| P2 | audit all 37 `config::load` call sites — is the failure normal for that caller? | per-call-site | **shipped** — 1 more fixed, 6 correct as-is |
| P3 | field-verify on the host that produced the evidence: a service restart logs no ERROR, and an induced unreadable config still does | — | **✅ FIELD-VERIFIED** — last ERROR on 0.4.53 (the final build without the fix); 21 starts across 0.4.55→0.4.73 since, zero |
| P4 | docs, in the house style (the docs-before-close rule, #1401): `docs/installation.md` § "The host must be re-enrolled — when to believe it" — the two readers, a flowchart of which to pick and what each logs, and why a false re-enroll is a destructive remedy rather than noise | — (docs) | **done 2026-09-25**, after the close — the verification-debt guard (#1598) found FR-66 closed with no docs criterion |

### P2 audit — all 37 call sites

Seven swallow the error; the question asked of each was *is absence normal for
this caller?*

| call site | absent is normal? | verdict |
|---|---|---|
| `win_service/supervisor.rs` `netd_enabled()` | **yes** — an optional flag on a path most installs don't have | **fixed (P1)** |
| `main.rs` enroll, reuse existing `machine_id` | **yes** — a first enrollment has no config *by definition* | **fixed** |
| `meshharbor-desktop/commands.rs` `load_optional_config` | no — guarded by `path.exists()` first, so only *exists-but-corrupt* reaches `load` | leave: corruption is a real fault worth ERROR |
| `localapi_state.rs` live config (cleanup) | no — this **is** the config the daemon runs on | leave: correct |
| `localapi_state.rs` stale config | no — the caller named a specific file it expects | leave: correct |
| `main.rs` per-org base after a join | no — its own comment says *"the join already wrote this file, so a failure here means something else broke it"* | leave: correct |
| `main.rs` clean-run promotion reload | no — the daemon's own config | leave: correct |
| `main.rs` graceful-shutdown reload | no — the daemon's own config | leave: correct |

⚠️ The enroll site is arguably **worse than the one that started this FR**: it
fires `the host must be re-enrolled` during the very operation that enrolls the
machine. It had gone unnoticed because it is one line in a verbose successful
enrollment, whereas the supervisor's fires on every start forever.

## Acceptance criteria

- [x] A service start on a host with no machine-global config logs **no** ERROR.
      *(unit-locked: `a_probe_is_silent_but_load_still_demands_re_enrollment`)*
- [x] `netd_enabled()` still returns `false` in that case (behaviour unchanged) —
      the change is `load(..).ok()` → `read_if_present(..)`, both `Option`.
- [x] The env lever `ROOMLERD_OVERLAY_NETD` still wins over the file — untouched,
      it returns before the file is consulted.
- [x] An actually-unreadable config still logs `the host must be re-enrolled` at
      ERROR. Both halves are in one test, and it is **mutation-checked**: with
      `read_if_present` reverted to `load`, it fails with the production message
      quoted back verbatim.
- [x] Every remaining `config::load` caller is either correct at ERROR severity
      or moved to the probe reader, with the reason recorded per call site — see
      the P2 table above.
- [x] Field-verified on the originating host across a real service restart —
      and shown FAILING on the build immediately before, which is what makes the
      pass mean anything.
- [x] Docs, in the house style and linked from `docs/README.md` (the
      docs-before-close rule, #1401) — P4: `docs/installation.md` § "The host
      must be re-enrolled — when to believe it" carries both readers with their
      anchors, a flowchart of which to pick and what each logs (including the
      `.prev` RECOVERED path, which needs no action), and why the false alarm
      mattered: the remedy it prescribes is destructive.
      *Added 2026-09-25, after the close.*

## Open decisions

- Whether P2 finds a third caller worth moving. If it finds none, the probe
  reader is still justified — the point is that the next one has somewhere right
  to go.
- Whether the machine-global probe should exist at all on a user-context install,
  or whether `netd_enabled()` should read the worker's own resolved config. That
  is a bigger question about which config owns a supervisor-level flag, and it is
  deliberately **not** bundled here.

## Out of scope

- The ~2-hourly service restarts observed on the same host (01:47, 03:47, 05:48,
  06:06 on 2026-09-02, one worker exiting `code=2`). Same log, unrelated cause,
  and folding them together would make both harder to reason about. Worth its own
  FR once the cadence is characterised.
- The peer-presence marker path in the same log block
  (`system_context::peer_presence::marker_path()`, under `%PROGRAMDATA%`). That
  is a correctly-frozen FR-46 anchor, not a defect. ⚠️ Named by its code location
  rather than spelled out, deliberately: writing the literal path here would add
  an unclassified retired-name occurrence, and the FR-21/FR-46 audit refuses it —
  correctly, since a new document is exactly where the old spelling should stop
  spreading. This paragraph is that guard working, recorded rather than
  suppressed.

## Field-verification log

| date | build | what was proven |
|---|---|---|
| 2026-09-25 | docs | **Docs written after the close.** FR-66 closed on 2026-09-06, the day after the docs-before-close rule reached master, with no docs criterion; the verification-debt guard (#1598) flagged it. The section sits in `docs/installation.md` beside the enrollment path this FR also fixed, and leads with the reason a false alarm here is not cosmetic — re-enrollment is final and costs the device its overlay address. Anchors re-checked against master: `config.rs:2496` / `:2533` / `:2563`, `supervisor.rs:961` (the spec's `:2349` / `:958` had drifted) |
| 2026-09-06 | 0.4.53 → 0.4.73, neo16 | **P3 field-verified, with the failing run alongside it.** The last `the host must be re-enrolled` on this host is `2026-09-03T02:50:47Z`, on a service start running **0.4.53** — the final release *without* the fix. The very next start, `10:11:20Z` the same morning on **0.4.55**, the first fixed build it ran, logged nothing; **21 service starts** across 0.4.55 → 0.4.73 since, **zero** occurrences. The precondition still holds throughout — the machine-global config is still absent, so the trigger never went away, only the false alarm did. ⚠️ The line-for-line comparison is the strongest part: in both builds the sequence runs *service started → M3 A1 auto-swap → desktop companion refreshing → **[slot]** → peer-presence transition → spawned worker*, and only the ERROR occupying that slot is gone. Nothing else moved |
| 2026-09-06 | ⚠️ method | **I called this "not verified" first, and the reason is worth more than the verdict.** `git tag --contains <the master SHA>` reported the fix's first release as **0.4.72**, which put it *after* every build whose logs were clean and made the pass look like a coincidence that had already happened for some other reason. It is wrong because **release tags here are cut from a lineage separate from master**: the same change exists on that lineage under a different SHA, and asking whether the *master* commit is an ancestor of a *tag* answers "have the two lineages converged", not "does this release contain this change". The first question resolves 18 releases too late. ⇒ to date a fix against releases, find the SHA **on the tag lineage** (`git log <tag-a>..<tag-b> -- <path>`) and test ancestry with that. 🔑 The generalisable form: an ancestry query answers a question about **one graph**, and a repo with two publishing lineages has two |
| 2026-09-03 | CI | **FR-46's guard caught this FR's own spec, on the first push.** The out-of-scope paragraph originally spelled the peer-presence marker path out in full, which is an unclassified retired-name occurrence; `Retired-name audit (FR-21)` failed the PR with `unclassified rose 0 -> 1` and named the file and line. Reworded to point at `peer_presence::marker_path()` instead — a new document is exactly where the old spelling should stop spreading, and there is no "current name" to substitute because the path is a deliberately frozen anchor. ⚠️ Recorded rather than silently fixed: this is the first time that guard has fired on a document nobody was thinking about it in, which is the only kind of evidence that it works |
| 2026-09-03 | P1+P2, local | **The test is mutation-checked, so its pass means something.** Reverting `read_if_present` to `load` fails it with the production defect quoted back: `ERROR … the host must be re-enrolled path=/tmp/…/config.toml`. Both halves live in one test on purpose — without the *load must still shout* half, "make it quiet" passes by softening `load`'s ERROR to `warn!`, which trades a false alarm for a missed one; without the *probe must be silent* half the defect is unobservable, since `netd_enabled()` already returned the correct boolean while telling every healthy host to re-enroll. ⚠️ Nothing weaker than reading the emitted tracing events can lock this: the bug is entirely in SEVERITY, and every return value involved was already right |
| 2026-09-02 | 0.4.48, neo16 | The ERROR fires on every service start of a fully healthy host. Established that the worker runs `session_id=1 elevated=true` and uses `%APPDATA%\roomler\roomler\config\config.toml` (live, rewritten same day, healthy `.prev`), so the machine-global path it names is legitimately absent rather than lost. Traced to `netd_enabled()` probing that path for one optional flag through `config::load`, which logs the re-enroll ERROR on the both-copies-missing arm |
