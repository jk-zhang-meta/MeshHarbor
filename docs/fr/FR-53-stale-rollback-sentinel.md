# FR-53: A recovered device warns about a crash loop forever

> **CLOSED 2026-09-01** — issue #1123 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#1123](https://github.com/jk-zhang-meta/MeshHarbor/issues/1123) ·
Status: **P1 implemented; P2 needs a release** (2026-09-01) · Found while shooting FR-41's demo: the
device on camera was displaying this.

## Goal

An attention sentinel should describe the device's **current** state. A
`rollback_failed` sentinel currently outlives the problem it describes by every
subsequent version, so a healthy device tells its owner it is broken and
instructs them to reinstall by hand.

## The evidence

`macbook-pro`, 2026-09-01, in the desktop companion's Overview panel — filmed by
accident while recording the product demo:

> **Attention required**
> MeshHarbor agent: crash loop detected (auto-rollback failed).
> **Version 0.4.34 has crashed 3 times within 10 min. Last known good version: 0.4.33.**
> Automatic rollback could not be applied: automatic install failed: refusing to
> self-update: `installer -target /` requires root, but this agent runs as uid
> 501 (the per-user LaunchAgent). …
> **Recommended action: download the previous installer from … and reinstall manually.**

The same panel, four fields lower, reports **App version 0.4.40 · Service version
0.4.41**, and the mesh agrees:

```
● macbook-daemon   100.65.12.2   relay:derp/tcp   2s ago
```

So the device recovered **seven releases ago** and has been healthy since. The
message is not merely stale — it is actively wrong, and the action it recommends
would downgrade a working install.

⚠️ Nobody reported this. It was found because a camera was pointed at the
machine. Every device that ever survived a bad update is showing it.

## Root cause, with anchors

`crates/agent-core/src/notify.rs:176`:

```rust
pub fn clear_attention_on_healthy_connect() {
    for path in all_attention_paths() {
        match read_attention_at(&path) {
            Some(info) if info.reason.as_deref() == Some(REASON_ROLLBACK) => {}
            Some(_) => { let _ = std::fs::remove_file(&path); }
            None => {}
        }
    }
}
```

Every reason clears on a healthy authenticated connect except `rollback_failed`,
and the comment above it explains why:

> `rollback_failed` persists until an operator acts (the broken-binary state
> isn't disproven by a successful connect of the rolled-back binary).

**That reasoning is correct, and it is not the case that occurs.** It reasons
about a connect from the *rolled-back* binary — the older one the device fell
back to. It says nothing about a connect from a binary **newer than the one that
failed**, which is what actually happens: the device updates again, the bad
version is gone, and the sentinel keeps asserting a crash loop in a version no
longer installed.

The sentinel cannot tell those apart, because it does not record which version
failed. `AttentionInfo` (`notify.rs:45`) is `{ path, message, reason }`, and the
version exists only inside the free-text `message` written by
`rollback_attention_msg` (`agents/meshharbord/src/main.rs:2777`).

## Key design

**Record the failing version; clear the sentinel once the device is
demonstrably running a different one.**

1. The sentinel gains a structured `Failed-version:` line beside `Reason:` —
   same footer format, same parser (`read_attention_at`), additive.
2. `clear_attention_on_healthy_connect` clears a `rollback_failed` sentinel when
   the running version differs from the recorded failed version. The connect is
   already authenticated, so "running" is not a claim — it is the binary that
   just connected.

### Legacy sentinels clear too, and the reason is not a heuristic

Every `rollback_failed` sentinel in the field today — including the one that
prompted this — predates the `Failed-version:` line. It is tempting to parse the
version back out of the message, or to give up on them.

Neither is needed. **A sentinel with no `Failed-version:` line can only have been
written by a binary older than the one that introduced the field.** The binary
executing this check *has* the field. So the writer is provably not the runner,
which is the exact fact the clear requires. An absent field is therefore
sufficient evidence on its own, and no string parsing enters the trust path.

### What must NOT change

⚠️ **A same-version connect must still keep the sentinel.** If the device rolled
back and is running the version that failed, nothing is disproven and the
original reasoning stands untouched. That is the case the `rollback_failed`
exemption was written for, and it stays.

⚠️ **This is not "clear on any connect".** The exemption exists; this narrows it
from *never* to *not while the accused version is the one running*.

## Phases

| # | Phase | Kill switch | Status |
|---|-------|-------------|--------|
| P1 | `Failed-version:` in the sentinel + version-aware clear (incl. the legacy arm) | the sentinel is advisory UI; reverting restores today's never-clear behaviour | **shipped** |
| P2 | Field-verify on the device that showed it | n/a | **blocked on a release** — the fix has to be running on that Mac before its sentinel can clear |

## Acceptance criteria

- [ ] a `rollback_failed` sentinel naming version X is CLEARED on a healthy
      connect from a version that is not X
- [ ] a `rollback_failed` sentinel naming version X is KEPT on a healthy connect
      from version X (the case the exemption exists for)
- [ ] a legacy `rollback_failed` sentinel with no `Failed-version:` line is
      cleared on a healthy connect
- [ ] every other reason still clears exactly as before, and a sentinel with no
      `Reason:` line still clears
- [ ] the companion's Attention panel goes away on the device that showed it,
      without anyone deleting a file by hand

## Out of scope

- **The macOS uid-501 self-update refusal** quoted in the message body is real
  and separate (the per-user LaunchAgent cannot run `installer -target /`; the
  root helper owns updates). It is FR-43's territory, and this FR neither fixes
  nor hides it — it stops the device claiming the failure is *current* when it
  is not.
- **Any other sentinel reason.** They already clear correctly.
- **Server-side visibility of attention state.** The sentinel is device-local by
  design.

## Open decisions

- Whether to compare versions **semantically** (running > failed) or merely for
  **difference**. Difference is the weaker claim and the safer one: a device
  running something other than the accused build is no longer running the
  accused build, whichever direction it moved. Leaning difference, because
  parsing a version to decide whether to keep warning someone is a lot of
  machinery guarding a message.

## Field-verification log
### 2026-09-01 — implemented, and the one thing it cannot prove yet

P1 is in and locked by 13 unit tests, five of them new. The decision is
extracted as `should_clear_on_healthy_connect` because
`clear_attention_on_healthy_connect_from` walks `all_attention_paths()`,
which resolves REAL profile directories — a test of the loop would write to
the developer's own sentinel.

**The lock is falsifiable.** Restoring the old `return false` for
`rollback_failed` makes
`a_rollback_sentinel_clears_only_when_the_accused_build_is_gone` fail. Checked
by making the edit, not by reading the assertion.

⚠️ **A stale build artifact briefly showed that same test failing after the
source was restored.** Worth knowing: `cargo test` reused the binary compiled
from the reverted file, so a green source read red. `touch` on the file fixed
it. A failing test immediately after an edit-revert cycle deserves a rebuild
before it is believed.

### What P2 must actually check, and why it is not a formality

The clear runs in whichever process owns the sentinel path:
`project_dirs()` resolves the CALLING process's home, and
`machine_attention_path()` is `None` off Windows. So on the macOS host that
prompted this, the file at `/Users/<user>/Library/Application Support/…` can
only be removed by the user-context agent, not by the root daemon.

That agent does hold its own server link — its Overview panel reports
`Server link: connected` — so it should reach the clear on its next healthy
connect once it is running a build with this change. **Should**, from
reading; the point of P2 is to look rather than to assume, because the
FR-43 split enrollment is actively changing which process connects.

