# FR-101: Remote-desktop session hygiene — sensitive features off by policy, the audit that exists emitted, sessions that end, the transport hardened

**Issue:** [#2093](https://github.com/jk-zhang-meta/MeshHarbor/issues/2093) · **Status:** done — every
criterion field-verified (AC1's last half, Safari, on 2026-10-17); AC8 amended by the operator on 2026-10-18
to "IPv4-only TURN, by design, documented" and verified against production's DNS · **Owner:** the agent (permission masking, the transport), the hub (policy, audit, limits),
the viewer (defaults) · **Anchors:** master `4fc8ea7bb` · **Program:**
[StarDesk teardown](../plans/stardesk-teardown-program.md), wave 1 · **Builds on:**
[security baseline](../security-baseline.md), [permissions](../permissions.md),
[FR-27](FR-27-consent-surfaces-and-desktop-companion.md)

## 1. Goal

Close the small, concrete gaps that comparing against StarDesk turned up. None of them is a feature on its
own, and each one is cheap:

1. **Sensitive features by policy.** StarDesk ships clipboard sync, file transfer and audio **off** by
   default. MeshHarbor requests clipboard and files on every session and gives no device or org a switch to
   refuse them.
2. **Audit that is defined but never written.** The clipboard and file audit kinds exist and nothing
   produces them.
3. **Sessions that end.** There is no idle timeout and no maximum duration for remote desktop, and no
   per-caller rate limit on session requests.
4. **The transport.** CBC suites are still offered, and a hand-edited `http://` server URL becomes
   plaintext signalling. (This item also said the agent's SRTP replay protection was off. It never
   was: see the correction in §2.)

## 2. Evidence (master `4fc8ea7bb`)

| What | Where | Consequence |
|---|---|---|
| The viewer asks for clipboard, files and recording on every session | `ui/src/composables/useRemoteControl.ts` L7677 (`'VIEW \| INPUT \| CLIPBOARD \| FILES \| RECORD'`) | Files on by default wherever the grant allows |
| Clipboard auto-sync defaults **on** | `useRemoteControl.ts` L3631–3641 ("Default ON — only an explicit '0' disables") | The clipboard flows unless the viewer opts out |
| The permission default, and the hub's FILES back-compat | `crates/remote_control/src/permissions.rs` L159–163; `crates/modules/fleet/src/hub.rs` L1016–1025 | Clipboard is in the default set |
| The device/org policy has no switch for clipboard or files | `AccessPolicy` (`crates/remote_control/src/models.rs` L915–948): `consent_mode`, `prompt_owner`, `input_mode`, `rc_overlay` only | An admin cannot say "no file transfer on these machines" |
| Clipboard and file audit kinds have no producer | `AuditKind` (`models.rs` L3736–3800, e.g. `ClipboardWriteToHost` at L3772); a non-test grep finds no writer | `docs/remote-control.md`'s promise to audit transfer direction is unmet |
| `EndReason::IdleTimeout` exists with no producer | `models.rs` L3673 | Sessions run until someone ends them |
| Exec has a per-(caller, device) rate limit; remote-desktop requests have none | `crates/modules/fleet/src/agent_exec.rs` L324–327 (`exec_rate_limiter`) | Only `tower_governor`'s 60/min/IP applies |
| DTLS still offers CBC suites | webrtc-dtls 0.11 default suites include `TLS_ECDHE_{ECDSA,RSA}_WITH_AES_256_CBC_SHA` (registry `cipher_suite/mod.rs` L65–68) | Legacy suites on a path that only ever needs GCM |
| ~~The agent's SRTP/SRTCP replay protection is off~~ **Wrong, corrected 2026-10-13** | No window is set at `peer.rs` L369, so `dtls_transport/mod.rs` L189 passes no option. The fallback to `srtp_no_replay_protection()` is in `Context::new` (registry `context/mod.rs` L131–141), and a session never reaches it: **`Session::new` supplies `DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW` = 64 for the remote context whenever the config has no option** (registry `session/mod.rs` L21–22, L52–70) | None. Measured in FR-16 L0's `legacy` cell: a captured SRTCP PLI delivered to the agent again, with no window set, is refused (`srtcp ssrc=0 index=1: duplicated`). P1a's window pins the default rather than switching protection on |
| Enrollment promotes `http://` to `https://`; the WS URL derivation does not | `crates/agent-core/src/enrollment.rs` L525–531 (loopback exempt); `crates/agent-core/src/config.rs` L3092 (`derive_ws_url` maps `http` → `ws`) | A config edited to `http://` signals in plaintext. The rule does not hold at every entry point |
| coturn sets ports but no listening IP | `turnserver.conf` L9–10 | Whether TURN answers on IPv6 is unverified |

## 3. Design

### 3a. Policy for clipboard, files and audio

- A device-owned **and** a tenant setting per feature: `rc_clipboard`, `rc_files`, `rc_audio`, each
  `off | ask | on`.
- **The agent enforces it** by masking `Permissions` before the session starts, the way the consent floor
  works: the stricter of device and tenant wins. The hub also strips the bits it knows will be refused, so
  the viewer can say why instead of failing later.
- The viewer greys the toggle with the reason.
- ⚠️ The masking is applied at every entry point: session start, a mid-session permission change, and a
  watcher joining.

Whether clipboard auto-sync should default to **off** is the operator's call (§6). It changes everyday UX,
and the policy switch is useful either way.

*As built, P2a: the org's half, on the server.*

| Piece | Where |
|---|---|
| The setting: `TenantSettings.rc_session { clipboard, files, audio }`, each `on` (the default, and every row older than the field), `ask` or `off`. A stored value this build does not know, or one that is not a string at all, reads as `off` and never fails the tenant document | `crates/db/src/models/tenant.rs:116` (`RcSessionPolicy`) |
| `GET /api/tenant/{tenant_id}/rc-session-policy` for any member; `PUT` with `MANAGE_TENANT`. The `PUT` is partial: a feature the body does not name keeps its value, and each named one is its own dotted `$set` (`crates/services/src/dao/tenant.rs:212`), so two admins cannot lose each other's change. Values are read strictly (`maybe` is a 400, not a silent `off`), and an unknown key is refused | `crates/modules/remote/src/session_policy.rs:85`, `:104` |
| The authz gate reads the policy from the tenant row it already loads. A row it could not read is `OrgPolicy::Unavailable` (`crates/modules/fleet/src/hub.rs:463`), never "unrestricted" | `crates/modules/remote/src/controller.rs:633` |
| The hub strips what the policy refuses before `rc:request` is built, after the legacy-grant `FILES` grandfathering. It names each refusal in `rc:session.created` (`features_refused`, feature → reason) and in the session's `session_requested` audit row (`features_stripped`). It forwards the policy to the agent in `rc:request.session_policy`, absent when it restricts nothing, so an org that sets nothing sends the same frame as before | `crates/modules/fleet/src/hub.rs:506` (`feature_grant`), called at `:1672` |
| The cross-pod relay carries it to the owner pod's hub | `crates/modules/remote/src/relay.rs:536`, `:553` |

**What `ask` means.** A feature set to `ask` survives only a session that the person at the device
approves, on a prompt that names the feature. That is the `prompt` consent mode, on an agent that
advertises `session-policy` (P2b). Every other session goes without it:

| Reason | When |
|---|---|
| `org_policy_off` | The org set `off`. It binds every controller: the device's owner, an ADMINISTRATOR and break-glass alike |
| `needs_consent` | The org set `ask`, and nobody at the device is asked: `auto` (an unattended device, the owner's own session without `prompt_owner`, break-glass), `email` and `push`, and `prompt_then_email`, whose approval may come from the owner's mail instead of the person there. Named before `device_cannot_ask`, because updating the device would not lift it |
| `device_cannot_ask` | The org set `ask` and the session prompts the person at the device, but the agent does not advertise `session-policy`. Such an agent grants whatever reaches it: its prompt shows the raw permission names at most (the Windows panel's `Permissions:` line; audio, which is no permission, not at all), and it holds no policy to check the grant against, so `ask` would mean `on`. **Every agent before P2b**, so until then `ask` behaves as `off`, with this reason |
| `policy_unavailable` | The org's row could not be read. The session goes ahead, as it did before the feature when that read failed, but without the features asked for: a database blip must not hand over what an org switched off |

- ⚠️ Audio is the request's `audio_enabled` flag, which is what the agent adds its track on. The
  `AUDIO` permission bit is read by nothing; the hub clears it along with the flag.
- The strip takes effect on every deployed agent, because the agent already enforces the grant it is
  sent: it refuses the `files` channel without `FILES` (`agents/meshharbord/src/peer.rs:1204`) and
  clipboard traffic without `CLIPBOARD` (`agents/meshharbord/src/peer.rs:10662`), and adds no audio track
  without `audio_enabled`. Until P2c the viewer does not explain the refusal.
- ⚠️ **Mid-roll.** An absent `session_policy` in the relay body comes from an origin pod older than
  the feature and reads as unrestricted: that pod applied no policy and would have granted the
  features itself, and an older owner pod ignores the field just as surely. A mixed pair of pods
  cannot promise the policy in either direction for the length of a roll; failing closed on absent
  would only take clipboard and files from every cross-pod session during each roll. A value that
  is present but unreadable fails closed.
- A change applies to sessions that start after it; a live session keeps the grant it was created
  with. The server has no mid-session permission change today, and each watcher is a session of its
  own through the same path, so session creation is the one entry point P2a has to gate.

*As built, P2b: the device's half.*

| Piece | Where |
|---|---|
| The owner's floor: `rc_clipboard`, `rc_files`, `rc_audio`, each `on` (default), `ask` or `off`. Live, read strictly when set (`maybe` is refused, where the file's reader would read it as `off`), and absent from `DesiredConfig`, so no server can switch back on what the owner switched off. Over the LocalAPI only the person at the console may set them (root counts on Unix): they govern that person's clipboard, files and audio | `crates/agent-core/src/config.rs:1644`, `config_surface.rs`; `crates/localapi/src/lib.rs:3381` |
| The masking: the org's policy (from `rc:request`) and the floor, the stricter winning (`FeaturePolicy::stricter`, `crates/remote_control/src/models.rs:1402`, shared with the hub). `off` takes the feature out; `ask` survives only when the person here will approve the session on a prompt this agent raises (`person_asked`: never under `email`, `push` or `prompt_then_email`). Applied the moment the consent mode resolves and before anything reads the grant: the stash the channels enforce, the worker's params, the prompt | `agents/meshharbord/src/session_policy.rs:128` (`mask`), `:102`; applied at `agents/meshharbord/src/signaling.rs:3290` |
| The prompt names each `ask` feature in words ("Approving also allows clipboard, file transfer and audio."), on its own line under privacy mode's, inside the native panel's two-line detail | `session_policy.rs:183` |
| `session-policy` in the caps, and the floor itself (`AgentCaps.session_policy`, `models.rs:511`, only when it restricts anything), re-announced on the heartbeat when the owner changes it | `signaling.rs:6808`, `:2131` |
| The hub reads the floor from the caps and strips what the device will refuse, naming it `device_policy_off`; when both say `off`, the org's is the one named | `crates/modules/fleet/src/hub.rs:506` (`feature_grant`), `socket.rs:243` |

- **The bypassed hub (AC4's device half).** The device holds its floor whatever the server sends. A
  request carrying `FILES` with no policy at all is masked to no `FILES` when the floor says `off`
  (`the_device_floor_holds_when_the_server_sends_no_policy`), and the channels then refuse as they
  already do. When the hub is honest, the viewer is told `device_policy_off` before it asks; P2c shows it.
- The agent's consent reply carries no grant, so the hub learns the floor only from the caps. A server
  older than P2b ignores the field and grants what the device then refuses at the channel.

*As built, P2c: the viewer.*

| Piece | Where |
|---|---|
| `rc:session.created.features_refused` read into a map: string values only, and a key or reason this build does not know is kept, so a newer server's refusal still greys its control. Each reason in words, naming whose decision it was (the organization's, the device owner's, the person at the device not being asked, an agent too old to ask, a policy that could not be read) | `ui/src/composables/useSessionFeatures.ts:43`, `:53` |
| The controls: the clipboard send and get buttons and clipboard auto-sync, file upload and browse, and drag-and-drop onto the screen or the files drawer, each disabled with the reason as its title. A drop or click that still reaches a refused feature says why instead of starting. The audio toggle's title gives the reason during a session. One snackbar at the session's start names what is off | `ui/src/views/remote/RemoteControl.vue:2219` |
| Clipboard auto-sync stands down in both directions for a session whose clipboard was refused, rather than pushing into a channel the agent refuses | `ui/src/composables/useRemoteControl.ts:5623`, `:5815` |
| The org settings card, "Remote session features": a select per feature (`on` / ask the person at the device / `off`) through P2a's route. The read is gated like the other org switches; a change names only its feature | `ui/src/components/admin/SettingsSection.vue:260`; `ui/src/stores/agents.ts:1399` |

### 3b. Write the audit that is already defined

*As first written:*

- `ClipboardWriteToHost` / `ClipboardReadFromHost` and `FileSentToHost` / `FileSentFromHost` carry
  **counts and byte totals, never content**. File events carry a size and a name hash, not the name.
- `PermissionsChanged`, `WatcherJoined` and `WatcherLeft`.
- The agent reports through the existing `rc:session.stats` channel; the hub writes the rows.

**As built (P3, 2026-10-13).** Three corrections, each found while building:

1. **The rows go to a new `transfer_activity`, not to `remote_audit`.** A transfer is something
   the device *reports*: the payload never crosses the server. The codebase keeps a host's claims
   apart from the server's decisions. `ssh_audit` is the decision and `ssh_activity` the claim;
   `remote_audit` holds the `RECORD` grant and `recording_activity` what the device then did.
   Writing claims into `remote_audit` would blur that line. The four clipboard and file
   `AuditKind`s stay defined and unwritten, with a comment saying why.
2. **`WatcherJoined` / `WatcherLeft` are obsolete, not missing.** They date from the
   single-session model. Since multi-user P3 every viewer has a session of their own and is that
   session's controller, so `usage.rs` already counts them. Writing watcher rows as well would count
   each viewer twice.
3. **`PermissionsChanged` has nothing to record.** The protocol has no mid-session permission
   change.

The device sends cumulative clipboard tallies, so a lost or repeated sample costs nothing, plus one
note per completed file, with the name hashed the moment it is noted. It sends them every 30 s on
`rc:session.stats`, and once more as the session ends, so that a session shorter than one sample
still reports. Detail, with the diagram: [`remote-control.md`](../remote-control.md) §11.3a.

⚠️ **Follow-up, found by FR-102 P9d's review (2026-10-17): the device-ended last sample on a
supervised Mac.** The signalling loop's device-end arm (`agents/meshharbord/src/signaling.rs:2342`) sends
that sample, then the terminate, on the connection's delegation channel whenever one is attached — for
every session the loop holds, the worker's own included. A worker's own session (FR-43: the GUI worker
is its own enrollment and serves its own sessions) therefore reports under the daemon's identity, and
the server drops the sample as another device's. The 30 s samples and P9d's early sample take the
peer's own sender since P9d; this one deliberately does not, because it must land before the terminate
written directly after it. A fix needs the terminate on the same queue, or a per-session delegation
marker. Open.

### 3c. Sessions that end

- **An idle timeout:** no input from the controller and no damage on screen for N minutes. It produces the
  existing `EndReason::IdleTimeout`, so no new reason is needed and older servers are unaffected.
- **A maximum duration.**
- Both are tenant settings, with a device floor. Default: off for existing tenants, a documented
  recommendation for new ones.
- **A per-(caller, device) rate limit** on session requests, checked **after** the identity gates (as exec
  does), so a refusal names who was refused.

*As built, P4b-1: the maximum session length.* The two limits are built apart because different parties
can see them. A session's length is known to the hub, which saw it go live, so the hub enforces it for
every agent and viewer already deployed. Idleness ("no input and no damage") is seen only by the agent;
that is P4b-2.

| Piece | Where |
|---|---|
| The setting: `TenantSettings.rc_limits.max_secs`, `None` (the default, and every row older than the field) for no limit. Operator decision 2: off for existing tenants | `crates/db/src/models/tenant.rs:129` |
| `GET /api/tenant/{tenant_id}/rc-session-limits` for any member; `PUT` with `MANAGE_TENANT`, one minute to one day, or `null` to clear. A body names the limits it changes (`idle_secs` too, since P4b-2) and leaves the other alone; a body naming neither, or an unknown key, is refused. The DAO `$set`s or `$unset`s each limit it names | `crates/modules/remote/src/session_policy.rs:229`, `:245`; `crates/services/src/dao/tenant.rs:178` |
| The authz gate reads it from the tenant row it already loads, and binds every controller with it, break-glass included. A row it could not read means no limit (the behaviour from before), never sessions ended on a guess. The relay carries it as `max_secs` to the owner pod; absent from an older origin pod reads as no limit | `crates/modules/remote/src/controller.rs:638`; `crates/modules/remote/src/relay.rs:151` |
| The hub arms a timer when the session goes **live** (the agent's answer), not when it was requested, because consent can take minutes. The session record's limit is *taken* then, so a renegotiation never arms a second timer. At the limit the hub ends the session as `EndReason::IdleTimeout` and names the limit `max_duration` on `rc:terminate` (`limit`) to both ends and in the `session_ended` audit row (`limit`). These are fields, not a new reason or audit kind: an older agent, viewer or pod reads them as the reason it already knows | `crates/modules/fleet/src/hub.rs:2207`, `:2262` (`terminate_with_limit`) |
| The viewer says "The session reached your organization's maximum length" (`friendlyEndReason`). `idle_timeout` is not a reason it retries, so it never reconnects around the limit; connecting again is a new session under a new timer. The org settings page gains "Remote session limits" | `ui/src/composables/useRemoteControl.ts:736`; `ui/src/components/admin/SettingsSection.vue:346` |

- The timer lives with the session on the pod that holds it. A pod that goes away takes its sessions,
  and their timers, with it.
- Not built: a per-device maximum. The org's binds every session in the org. The device's own
  limit came with P4b-2, for the idle timeout only, where its `AccessPolicy` already stored
  `auto_terminate_idle_minutes`.

*As built, P4b-2a: the idle timeout.* Only the device sees both halves of "idle". The controller's
input rides the peer-to-peer channels and the pixels never leave the device, so the agent measures the
limit and ends the session itself. The hub's part is to tell it the limit and to name the end.

| Piece | Where |
|---|---|
| **The setting.** The org's `TenantSettings.rc_limits.idle_secs` lives on the same route as the maximum: one minute to one day, `null` clears it, and a body naming one limit leaves the other alone. The device's own `AccessPolicy.auto_terminate_idle_minutes` was stored since the first access policy and read by nothing until now; `0` means no limit. The shorter of the two wins, so a device can tighten its org's limit but never loosen it | `crates/db/src/models/tenant.rs:143`; `crates/modules/remote/src/session_policy.rs:171`; `crates/remote_control/src/models.rs:1284` (`stricter_idle_limit`), `:1301` (`idle_limit_secs`) |
| **The gate.** It resolves the limit from the tenant row and the device row it already loads, and binds every controller with it, break-glass included. An unreadable tenant row leaves the device's own limit, never a guess at the org's. The relay carries it as `idle_secs` | `crates/modules/remote/src/controller.rs:645`; `crates/modules/remote/src/relay.rs:158` |
| **The hub.** It sends the limit to every agent on `rc:request` (`idle_secs`; an older agent ignores it). It tells the viewer (`rc:session.created.idle_secs`) only where the agent advertises `idle-timeout`, since a limit nothing keeps is no limit. The `session_requested` audit row carries `idle_secs` and `idle_enforced`, so a limit the org set that a device could not keep is visible | `crates/modules/fleet/src/hub.rs:1717` |
| **What counts as activity.** For the controller: input it sent (counted even when the lock screen suppresses it, and in a view-only session), the clipboard either way, and file transfer (a download's progress counts, so a long one is never ended). For the screen: a 32 × 18 grid sampled at most once a second per screen. The screen is active when at least 6 distinct cells (about 1 %) change within 30 s, so a clock or a blinking caret never is, and a scroll, a video or a line of typing is | `agents/meshharbord/src/session_idle.rs:54` (the grid), `:194` (`signatures`); `agents/meshharbord/src/session_telemetry.rs:164` (`activity`) |
| **The clock and the end.** It warns the viewer a fifth of the limit before the end (a minute at most) with `rc:idle {ends_in_ms}` on the control channel, and withdraws the warning on activity. At the limit it hands the session to the signalling loop, which ends it as the host's Disconnect does: `rc:terminate` with `idle_timeout` and `limit: "idle"` first, then the peer after the grace. The hub names `idle` only from the agent and only with `IdleTimeout` | `agents/meshharbord/src/session_idle.rs:337` (`IdleClock::tick`), `:406` (`arm`); `agents/meshharbord/src/signaling.rs:161` (`DeviceEnd`); `crates/modules/fleet/src/hub.rs:576` (`device_end_limit`) |
| **The viewer and the settings page.** The viewer says "The session ended after a period with no activity", and `idle_timeout` is not a reason it retries. The settings card gains the idle limit | `ui/src/composables/useRemoteControl.ts:746`; `ui/src/components/admin/SettingsSection.vue:371` |

- **The screen is one per process, not one per session.** On two monitors, one session's activity
  keeps the other alive. That errs toward keeping a session someone may be using, and the maximum
  length bounds it.
- **A host whose screen never stops changing never idles out** (a video wall, a seconds clock with
  animated widgets). That is by design: someone may be watching it. The maximum length is the bound
  for those.
- **On a supervised Mac, the worker keeps the limit** (`SessionParams.idle_secs`): it owns the peer, the
  input and the screen. The daemon advertises `idle-timeout` for both halves, so a worker that lags its
  daemon across an update (they are replaced independently) keeps no limit while the viewer is told one.
  That gap lasts until the worker restarts into the new build.
*As built, P4b-2b: the countdown and the device's own control.*

| Piece | Where |
|---|---|
| **The viewer's countdown.** The viewer reads `rc:idle`: a duration turned into a deadline on this browser's clock at receipt, as `rc:media-waiting` is. `null` withdraws the warning, and anything malformed is no message. A banner counts the seconds down while it stands. Any input sent from here withdraws it at once, because it is activity, and the device withdraws its own on its next look. A viewer older than P4b-2b ignores the message, and its session ends without a countdown | `ui/src/composables/useRemoteControl.ts:1506` (the parser), `:4893` (`idleEndsAt`), `:6318` (cleared by input), `:774` (`idleSecondsLeft`); `ui/src/views/remote/RemoteControl.vue:836` |
| **The device's own limit**, on its row in the device list. "Org limit only" (stored as `null`), or 5 minutes to 2 hours; a value set through the API outside the presets still shows. The shorter of it and the org's applies, so it can only tighten. Applies to the next session | `ui/src/components/admin/AgentsSection.vue:2062` (`idleMinuteItems`), `:2079` (`onIdleMinutesChange`) |

### 3d. The transport

- **CBC out.** Configure the agent's DTLS cipher suites to the two ECDHE-GCM suites. Chrome has offered GCM
  for years, so nothing that connects today loses.
- **Replay windows pinned** (they were already on, §2). `set_srtp_replay_protection_window(64)` and the SRTCP equivalent on the agent's
  `SettingEngine`.
- **`https` at every entry point.** Apply enrollment's promotion (loopback exempt) in `derive_ws_url` and at
  config load, so `ws://` can only ever mean loopback.

  **As built (P1b).** One rule, `meshharbor_remote_control::server_url::secure`
  ([`server_url.rs:47`](../../crates/remote_control/src/server_url.rs#L47)). A remote `http://` becomes
  `https://` and `ws://` becomes `wss://`; loopback is exempt
  ([`is_loopback_authority`, `:83`](../../crates/remote_control/src/server_url.rs#L83)). It runs where a
  URL to the server enters, not in `derive_ws_url`: that only maps a URL that is already secured, and the
  same URL also feeds the token renewal, the updater and the uploads, which never pass through it.

  | Entry point | Where | Before P1b |
  |---|---|---|
  | The agent's enrollment: `meshharbord enroll` / `re-enroll`, the wizard's agent role, the desktop companion | [`enrollment.rs:563`](../../crates/agent-core/src/enrollment.rs#L563) | promoted, but only a lower-case `http://` |
  | Every load of the agent config: `server_url`, `ws_url`, each `[[orgs]]` entry's | [`config.rs:3380`](../../crates/agent-core/src/config.rs#L3380) → [`secure_server_urls`, `:2430`](../../crates/agent-core/src/config.rs#L2430) | dialled as written |
  | `mh enroll` and the wizard's tunnel role | [`meshharbor-cli/src/config.rs:67`](../../agents/meshharbor-cli/src/config.rs#L67), called at [`cli.rs:1250`](../../agents/meshharbor-cli/src/cli.rs#L1250) and [`orchestrator_tunnel.rs:236`](../../agents/meshharbor-setup/src/orchestrator_tunnel.rs#L236) | the tunnel token was posted as written |
  | The tunnel CLI's config, from the file or `MESHHARBOR_TUNNEL_SERVER` | [`meshharbor-cli/src/config.rs:46`](../../agents/meshharbor-cli/src/config.rs#L46) | dialled as written |
  | `meshharbord anchor create` (FR-104) | `exec_service::origin_ok` | refuses plaintext already; unchanged |

  - ⚠️ **The guard reads a URL the way its dialler does.** reqwest parses by the WHATWG rules, which
    accept `HTTP:meshharbor.itachi.fans`, `http:\\meshharbor.itachi.fans`, surrounding whitespace and a tab inside the scheme, and
    find the host after the authority's last `@` (`http://localhost:80@evil.example` dials
    `evil.example`). The first cut matched `split_once("://")` and would have passed all of those through
    as plaintext. `the_guard_reads_a_url_as_its_dialler_does` now parses 21 plaintext spellings and 10
    loopback ones with the real `url` crate and requires the two readings to agree. A loopback spelled
    some way the guard does not read (`0x7f.1`, `2130706433`, `%6c…`) is promoted, so every doubt falls
    on the side of TLS.
  - **The escape is the device's:** `allow_plaintext_server = true` in its `config.toml`. It sits in the
    Access group of the config surface and needs a restart. The LocalAPI takes it from the console only,
    and it is in the never-pushable list beside `remote_config_enabled`, so a compromised server cannot
    talk a device down to plaintext. The tunnel CLI reads the same key, or `MESHHARBOR_TUNNEL_ALLOW_PLAINTEXT=1`
    on its environment path, where it has no file. There is no escape at enrollment: a token always
    travels over TLS.
  - **Counted first, as the split required.** The ingress logged no plaintext agent `/ws` attempt over
    about 8 h (the only one was the probe itself). Production's port 80 answers everything with a 301,
    which a WebSocket client does not follow. No deployed device could be connected over plaintext, so
    the rule can only bring such a device back.
  - ⚠️ The daemon's next save writes the promoted URL back to the file, so a lab that sets the escape
    later also writes its `http://` URL again. A downgrade to a daemon older than P1b erases
    `allow_plaintext_server` on its first save (#2078), so after updating again, set the escape once more.
  - The agent-e2e harness's `MESHHARBOR_E2E_SERVER=http://meshharbor2` was promoted at enrollment before P1b
    too (the rule dates from 2026-04-30, the harness from 2026-05-25). P1b changes nothing for it.
- **TURN over IPv6** gets a field check. If coturn does not answer on v6, add `listening-ip` for it.
  *Checked 2026-10-14, with P1b:* none of the coturn hosts the server hands out publishes an AAAA record
  (`coturn`, `coturn-1`, `coturn-us-east` and `coturn-eu-north`, all under `meshharbor.itachi.fans`; `meshharbor.itachi.fans`
  itself has none either). So no client reaches TURN over IPv6 today, whatever `listening-ip` says. An
  IPv6-only client reaches it over IPv4 through its network's NAT64/DNS64. Publishing AAAA records, and
  only then the `listening-ip` check, is an ops decision. It stays with AC8.

## 4. Phases

| P | Scope | Kill switch | Status |
|---|---|---|---|
| P0 | This spec and the claim. The red evidence: a DTLS ClientHello pcap with CBC suites; an SRTCP replay accepted in a unit test | docs only | merged. ⚠️ Its "replay accepted" red was a bare `Context`, not a session; see §2 |
| P1a | The transport: CBC out, the SRTP/SRTCP replay windows pinned (`agents/meshharbord/src/rc_transport.rs`, the vendored `set_dtls_cipher_suites`) | `MESHHARBORD_DTLS_LEGACY_SUITES=1`; `MESHHARBORD_SRTP_REPLAY_WINDOW` sizes the window, and no value turns it off | **shipped in 0.4.133.** FR-16 L0's `replay` / `legacy` / `unguarded` cells read both halves off the link in CI: DTLS red/green on the agent's real ClientHello, and replays refused on a live session. The window change is behaviour-neutral (§2). The field pcaps are §8 rows 8 and 12: CBC offered on 0.4.132, GCM only on 0.4.136 and 0.4.137, and Chromium and Firefox both pick `c02b` |
| P1b | `https` at every entry point (§3d as built). The IPv6 TURN check is a field check of coturn with no code, so it stays with AC8 | `allow_plaintext_server = true` on the device; `MESHHARBOR_TUNNEL_ALLOW_PLAINTEXT=1` on the tunnel CLI's environment path | **merged** #2226 (`8872cd185`), split from P1a (see the note below). Tests: `server_url` (the dialler-agreement test with 21 plaintext and 10 loopback spellings); the agent config's load, each `[[orgs]]` entry and the escape; enrollment; the tunnel CLI's load and enrollment; the never-pushable list. Negative controls: each of the guard's four readings removed (whitespace, the slashes, userinfo, the authority's end) fails the dialler test; the load call removed fails both config tests; the tunnel CLI's load and enrollment each fail their own. **Field-verified on 0.4.137**, the first release that carries it (AC3, §8 row 10): red on 0.4.136, green on 0.4.137, with the same untouched config on one guest |
| P2 | Policy switches and agent-side masking; viewer reasons | each setting defaults to today's behaviour (`on`) | split into P2a–P2c below |
| P2a | The org's switch (§3a as built): `TenantSettings.rc_session`, the `rc-session-policy` route, the hub's strip with a reason per feature in `rc:session.created` and the audit row, the policy forwarded to the agent and carried by the cross-pod relay | each feature defaults to `on`: an org that sets nothing sees no change, and its agents get the same `rc:request` as before | **merged** #2198 (`6e9bd587b`): unit tests in db, remote_control, fleet and remote (the remote module joins CI's unit-test step: it was in no lane); `rc_session_policy_tests`, five cells reading both the viewer's answer and the agent's frame, a cross-pod one included. Negative controls: with the hub's strip removed, four of the five fail and the route cell passes; with the relay dropping the policy, only the cross-pod cell fails |
| P2b | The device's own switch (device-owned, never pushable, so it survives a compromised server) and the agent's masking at every entry point; `session-policy` advertised, and the prompt names each `ask` feature in words (§3a as built) | `on` | **merged** #2203 (`a5919754a`): `session_policy` unit tests (8) and the hub's `feature_grant_follows_the_device_floor`; two more `rc_session_policy_tests` cells (the floor named as the device's, a heartbeat moving it both ways). Negative controls: with the agent ignoring the floor, its four floor tests fail (AC4's core among them); with the hub ignoring it, the two new cells and two hub tests fail while the P2a cells pass |
| P2c | The viewer reads `features_refused` and greys each control with its reason; the org settings card (§3a as built) | — | **merged** #2206 (`30a00d4a0`): `useSessionFeatures.spec.ts` (parsing, every reason's words, the summary) and two store cases; the whole vitest suite (1990) and `vue-tsc` pass. The Dockerfile's `ui-builder` stage fails only on master's known `EnrollmentDialog.spec.ts` error (#2205) |
| P3 | The audit producers: clipboard and file traffic as the device's claim, in `transfer_activity` (§3b as built), read at `GET …/transfer-activity/{agent_id}` | none: an older agent sends nothing, and an older server ignores the field | **merged** #2138 `d626c0252`: wire tests, agent unit tests, and `transfer_activity_tests` (kept for the granted session, dropped without `CLIPBOARD` / `FILES`, for another device or without a valid name hash; a repeated tally adds nothing). **Field-verified 2026-10-14** (AC5, field log row 3): red on agent 0.4.134, green on 0.4.135, the first release that carries it |
| P4 | Idle timeout, max duration, the request rate limit | each off by default | P4a, P4b-1, P4b-2a and P4b-2b below |
| P4a | The request ceiling: 60 `rc:session.request` a minute per (caller, device), after the authz gate (`crates/modules/remote/src/controller.rs`, `SESSION_REQUESTS_PER_MINUTE`); refusals answer `rc:error` `rate_limited` | none. **On, not off as first written:** the ceiling sits where no legitimate client reaches it (the reconnect ladder asks about a dozen times in its first minute), and a ceiling that ships off protects nothing. Changing it is a reviewed change to the constant | **merged** #2142 `b8f7054c1`: `rc_request_ceiling_tests` (the owner passes 60 and is refused on the 61st; another device is untouched; a member without the right gets `permission_denied` all 61 times). Negative controls: with the ceiling at 0 it fails on request 61; moved ahead of the authz gate it fails on the identity-first assertion |
| P4b-1 | The maximum session length (§3c as built): the org's setting and route, the hub's timer from the moment the session went live, `rc:terminate` and the `session_ended` audit row naming `max_duration`, the viewer's sentence, the settings card | none needed: nothing is limited until an org sets a limit (operator decision 2) | **merged** #2211 (`92b2461f8`): the hub's `a_session_ends_at_the_orgs_maximum_length`, `rc_session_limits_tests` (the route's rules; a live session ended at a 2 s limit, both ends told and the audit row naming it, against an org with no limit that goes on), and the store and viewer tests. Negative control: with the timer never armed, both timer tests fail and the route cell passes |
| P4b-2a | The idle timeout (§3c as built): the org's `idle_secs` on the limits route, the device's `AccessPolicy.auto_terminate_idle_minutes` (the shorter wins), the agent's measure (controller activity, and screen change judged on a sampled grid so a clock never counts), its warning on the control channel, its end as `idle_timeout` naming `limit: "idle"` through the host-Disconnect path, and the `idle-timeout` cap word, without which the viewer is told no limit | off by default | **merged** #2219 (`75f03b4d8`): the agent's clock and grid tests; the hub's idle-limit tests; `rc_idle_limit_tests`, where a real agent ends a 2 s session itself; and new `rc_session_limits_tests` cells. Negative controls: with the watcher never armed, the real-agent cell fails; with the hub never naming `idle`, the hub tests and the gate cell fail; with a one-cell threshold, the clock test fails. CI ran again on the branch merged with master before the squash. **Field-verified on 0.4.137** (AC6's idle half, §8 row 11): ended at the limit and audited, kept alive by input, and red on 0.4.136 |
| P4b-2b | The viewer's countdown for `rc:idle` (§3c as built), withdrawn by any input from here, and the device row's control for its own idle limit | — | **merged** #2230 (`4075d2796`): the `rc:idle` parser (a countdown, its withdrawal, nothing malformed) and `idleSecondsLeft`; the full vitest suite (2006) and `vue-tsc` pass |
| P5 | Docs and the field table | — | **#2235**: `remote-control.md` §11.3b (the policy switches, with the request's sequence and the reasons), and `security-baseline.md` §3–§4 (the floor no server can lift, the session limits, and a diagram of where each FR-101 audit row is written); both rows in `docs/README.md`. The transport (§4), the transfer audit (§11.3a) and the limits (§11.6) were documented with their phases. Both new diagrams render with mermaid-cli |

⚠️ **Why P1b was split from P1a (2026-10-13).** Replay windows and GCM-only DTLS
cannot cost a device its connection. Forcing `wss://` can. A config that still holds a
plaintext, non-loopback `server_url` signals over `ws://` today. That could be an
enrollment from before the promotion existed in its current home, or a hand edit. After
an auto-update such a host would dial TLS, fail, and become unreachable, with no remote
path to fix it: a self-wedge. P1b first counts the devices that would be affected,
and gives labs an explicit escape before the default flips.

## 5. Acceptance criteria

- [x] **AC1 (red first):** a pcap of the deployed agent's DTLS ClientHello lists the CBC suites. After P1 it
  lists only ECDHE-GCM, and every fleet browser still connects. **Verified** (field log rows 8, 9, 12 and
  14): both pcap halves are shown on the deployed binary (2026-10-14). Chromium and Firefox connect to
  0.4.137 and both pick `c02b` (2026-10-15). The Firefox was Playwright's, which has no OpenH264. This
  criterion asked for one *with* OpenH264 only because that Firefox could not connect at all before
  #2247 (#2231). DTLS is the same either way, since the agent is the DTLS client and its suite list does
  not depend on the browser's codecs. **Safari connects too** (2026-10-17, row 14): Safari 18.6 on
  macOS 15.7.7 to 0.4.142, DTLS 1.2 with `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`c02b`), and H.264
  decoding on a direct pair.
- [x] **AC2 (amended 2026-10-13):** a test replays an SRTCP packet into the agent's **live session**. It
  is refused under P1's policy, and the test shows it can see a replay accepted: with protection
  disabled through the setting engine, the replay is obeyed. *As first written, this criterion asked
  for "accepted on today's configuration (red)". No such red exists: webrtc-srtp's `Session::new` had
  always given sessions a 64-packet window (§2). The first red came from a bare `Context`, which no
  session builds.* **Verified** by FR-16 L0 in CI on #2130's merged head
  ([job 115548206168](https://github.com/jk-zhang-meta/MeshHarbor/actions/runs/38470382360/job/115548206168),
  Linux): `replay` 0/3 and `legacy` 0/3 refused, `unguarded` 9/9 obeyed (12 IDRs against 4).
- [x] **AC3:** a config with `server_url = "http://meshharbor.itachi.fans"` signals over `wss://` after P1, while
  `http://127.0.0.1` stays `ws://`. **Verified** 2026-10-15 (field log row 10), on one guest with the same
  untouched config. Red on 0.4.136: the agent dials `ws://meshharbor.itachi.fans/ws`, gets a 301 and stays offline.
  Green on 0.4.137: it logs that the plaintext URL "is read as TLS", dials `wss://meshharbor.itachi.fans/ws` and comes
  online, and its next save writes `https://` back to the file. With `http://127.0.0.1:3000` it still dials
  `ws://127.0.0.1:3000/ws`, with no warning.
- [x] **AC4:** a device with `rc_files = off` refuses file transfer, the viewer shows why, and the agent
  refuses it even when the hub was bypassed (an integration test sending the bit anyway). **Verified**
  2026-10-14 (field log row 7): red on agent 0.4.132, green on 0.4.136. The green half carries the reason
  in the session's frame, in the audit row and in the viewer's words. ⚠️ The hub-bypass clause is met by
  the agent's own unit test, not by an integration test as first written:
  `session_policy::the_device_floor_holds_when_the_server_sends_no_policy` hands the agent a grant
  carrying FILES with no policy, as a bypassed hub would, and the device's `off` takes it out. With the
  floor ignored, P2b's negative control fails it. An integration test cannot bypass a real hub without a
  test-only server path, and the floor is applied by the agent alone.
- [x] **AC5:** a clipboard write and a file transfer each produce an audit row with direction, count and
  bytes, and **no content**. A test asserts no payload bytes reach the row. **Verified** 2026-10-14. The CI
  half is `transfer_activity_tests` (#2138). The field half (row 3) went red on agent 0.4.134 and green on
  0.4.135, with the production viewer and the production server. On 0.4.134 the same push and upload left
  no rows. On 0.4.135 they left `clipboard_to_host` 1 × 28 bytes and `file_to_host` 1 × 4020 bytes, with
  the name's SHA-256, and neither the clipboard text, the file's bytes nor its name appeared anywhere in the
  response.
- [x] **AC6:** an idle session ends after the configured time with `EndReason::IdleTimeout` and an audit
  row. A session past its maximum duration ends the same way. **Verified.** Maximum length: field
  2026-10-14 (row 5), `idle_timeout` with `limit: max_duration` at 60.0 s, audited. Idle: field 2026-10-15
  on 0.4.137 (row 11), with the device's own limit at 1 minute. The viewer is told `idle_secs: 60` and
  warned at 50.2 s, and the session ends as `idle_timeout` with `limit: idle` at 60.0 s, audited, the same
  on two runs. Input every 20 s keeps a session alive past 100 s. Red on 0.4.136: `idle_secs: null` and no
  end, so the same spec fails.
- [x] **AC7:** a caller hammering session requests at one device is refused after the limit with a
  rate-limit reason, and an unauthenticated caller is refused by identity first. **Verified** (#2142
  `b8f7054c1`): `rc_request_ceiling_tests` in CI's integration lane
  ([job 115569893051](https://github.com/jk-zhang-meta/MeshHarbor/actions/runs/38476959531/job/115569893051),
  569 passed). The owner is refused `rate_limited` on request 61 of 60, another device is untouched,
  and a member without the right gets `permission_denied` all 61 times, never `rate_limited`.
- [x] **AC8 (amended 2026-10-18, the operator's decision):** TURN's address family is settled and
  documented: **IPv4-only, by design**. *First written as "TURN over IPv6 is answered, or `listening-ip` is
  fixed and then answered". Production's coturn runs as Kubernetes pods behind the hosts' IPv4 DNAT. Either
  reading meant restarting production TURN, and dropping every relayed session, for an IPv6-only audience
  nothing showed. The operator chose to settle and document the IPv4-only design instead.* **Verified**
  (§8 row 15): every TURN host the server hands out (`coturn.meshharbor.itachi.fans` and `coturn-1..3.meshharbor.itachi.fans`, from
  `MESHHARBOR__TURN__URL` and `…__WORKER_URLS`) answers A records and no AAAA, and `meshharbor.itachi.fans` itself has no
  AAAA either. A client on an IPv6-only network therefore reaches TURN the way it already reaches the site:
  through its network's NAT64/DNS64. Documented in `deployment.md` (relay infrastructure).
- [x] **AC9:** **Docs:** `docs/security-baseline.md` and `docs/remote-control.md` describe the policy switches,
  the audit rows (with a mermaid diagram of where they are written), the timeouts and the transport
  settings. Linked from `docs/README.md`. **Done** (#2235, P5):
  - the policy switches: `remote-control.md` §11.3b, and the floor in `security-baseline.md` §4;
  - the audit rows: §4's diagram of who writes each row, plus the sequences in §11.3a, §11.3b and §11.6;
  - the timeouts: §11.6, and `security-baseline.md` §3;
  - the transport: `security-baseline.md` §4's tables, and §11.1;
  - both rows in `docs/README.md`.

## 6. Decisions

**All three were decided by the operator on 2026-10-14, as recommended.** Each entry keeps what was
weighed.

1. **Clipboard auto-sync's default.** Recommended: keep it **on** for existing users, add the policy switch,
   and show the state in the viewer. Turning it off changes a daily workflow, which is a product decision.
   **Decided: as recommended.** The default stays on; P2 adds the switch, and the viewer shows the state.
2. **Idle timeout defaults.** Recommended: off for existing tenants, a 30-minute recommendation shown on the
   tenant settings page. **Decided: as recommended.**
3. **File-name privacy in audit.** Recommended: a hash, not the name. The audit records that a transfer
   happened, not what the file was called. **Decided: as recommended**, and P3 built it that way
   (`name_sha256`).

## 7. Out of scope

- 2FA / WebAuthn and user-session revocation (open Known Issues).
- DTLS 1.3 (not in webrtc-dtls 0.11).
- Recording, whose rules (FR-85) are unchanged.

## 8. Field-verification log

| # | Date | Cell | Result |
|---|---|---|---|
| 1 | 2026-10-13 | **CI, not field.** FR-16 L0 on a vnet: the production `AgentPeer` answering a webrtc-rs controller, with a tap on the link (`agents/meshharbord/tests/l4_latency.rs`) | **DTLS, read from the agent's real ClientHello.** Hardened: version `fefd` (1.2), suites `c02b c02f`, SRTP profiles `0007 0008 0001 0002`, the server chose `c02b`. With `MESHHARBORD_DTLS_LEGACY_SUITES=1`: `c02b c00a c02f c014`, the CBC pair back. Every default cell offers exactly the GCM pair. **SRTCP replay:** the controller's first PLI, captured on the link and delivered to the agent again 600 ms after each keyframe. Refused with P1a's policy (0/3, 4 IDRs). Refused with no window set, as every session ran before P1a (0/3, 4 IDRs, `srtcp ssrc=0 index=1: duplicated` in the agent's log). Obeyed with protection disabled through the engine, the negative control: 9/9, 11 IDRs, each answer triggering the next replay. Windows dev box, unoptimised build. The CI runner (Linux) ran a first cut that replayed only after the encoder's own keyframes: 0/3, 0/3 and 2/2. An obeyed replay restarts the encoder's period, so only two fit, exactly the assertion's floor; hence the chained trigger |
| 2 | 2026-10-13 | **The wrong turn** | P0's red for the replay half was a unit test on a bare `srtp::Context` built without options, which falls back to no protection. The agent never builds one: `Session::new` substitutes a 64-packet window first. So the agent was never open to SRTCP replay, and P1a's window is a pin. Found by building the instrument the AC asked for: the negative control expected to accept (window 0) refused. **Lesson: a red taken one layer below the product's real call path is not a red for the product** |
| 3 | 2026-10-14 | **AC5, red then green.** The production viewer, driven from a LAN neighbour, against vmtest Win11 guests on the production server. It pushes its own clipboard (a 28-byte marker) with the toolbar button, uploads one 4020-byte file through the file input, disconnects (the device's last sample), then reads `GET …/transfer-activity/{agent_id}`. Red: a `--type system` guest pinned to agent 0.4.134. Green: an attended guest on 0.4.135 | **Red (0.4.134):** "Clipboard sent to remote" shown and the upload started, then **no rows**, three attempts alike. The agent before P3 sends no `transfers`. **Green (0.4.135):** `clipboard_to_host` count 1, 28 bytes; `file_to_host` count 1, 4020 bytes, `name_sha256` equal to the SHA-256 of the file's name; both rows on the session's id, in place about 2.5 s after the disconnect. The response contains neither the clipboard marker, nor the file's bytes, nor its name |
| 4 | 2026-10-14 | **P2a/P2c, red then green.** The production server, probed from the vmtest harness host as the vmtest org's admin. Then the production viewer, driven there by Playwright, against `vmtest-anchor` (agent 0.4.48). The oracle is the server's own frames on the viewer's `/ws` and the session's audit rows, with the viewer's words as the surface | **Red (20:44Z, `hosted-20261014-cc63c4d`, 0.4.135):** `GET …/rc-session-policy` and `…/rc-session-limits` 404. **Green (after the roll to `hosted-20261014-b4e2263`, 0.4.136):** both 200 with the defaults at 20:50Z. With the org's clipboard set to `off`, a new session came back with `features_refused: {"clipboard":"org_policy_off"}`. The `session_requested` row has `features_stripped` with the same value, and the viewer's snackbar reads "Off for this session: the clipboard. Hover a greyed control to see why." The hub strips it even for an agent from long before P2. The setting was restored in a `finally` and re-read: `on` |
| 5 | 2026-10-14 | **P4b-1, green**, the same harness on the same roll. The org's `max_secs` is set to 60, then a session goes to a 0.4.135 Linux device whose stream holds | Live, then `rc:terminate` with `idle_timeout` and `limit: max_duration`, **60.0 s after the agent's answer**. The viewer shows the "maximum length" message, and the `session_ended` row names `max_duration`. Restored in a `finally` and re-read: `max_secs: null`. This is AC6's maximum-length half; its idle half waits for P4b-2a and an agent release |
| 6 | 2026-10-14 | **The wrong turn** | The first P4b-1 attempt targeted the 0.4.48 headless anchor. Its media never connected, so the viewer hung up after 10.1 s (`controller_hangup`) and would have reconnected under a fresh timer. The maximum length can only be shown on a device whose stream holds |
| 7 | 2026-10-14 | **AC4, red then green on one guest.** A kept vmtest Ubuntu system guest and the production viewer (Playwright, from the vmtest harness host), with the server's frames and the session's audit row as the oracle. No org setting changed. Red: the guest downgraded to agent 0.4.132 (from before P2b). Green: 0.4.136, twice (as provisioned, and on a fresh enrollment after the red half) | **Red (0.4.132):** `mh config set rc_files off` is refused (`unknown or non-editable config key`). The key written at the top of the file is dropped by the daemon's own save. The session's `features_refused` is `null`, the viewer shows nothing off, and the audit row's `features_stripped` is `null`. **Green (0.4.136):** `rc_files = off` set live, then `features_refused` and `features_stripped` both `{"files":"device_policy_off"}`, and the viewer reads "Off for this session: file transfer. Hover a greyed control to see why." Every green session went live |
| 8 | 2026-10-14 | **AC1, the pcap halves.** The same sessions, with a UDP capture on the guest from before the connect. The DTLS hellos were read raw, from TURN ChannelData, or from Send/Data indications | **Red (0.4.132):** the agent's ClientHello offers `c02b c00a c02f c014`, with the CBC pair. **Green (0.4.136):** `c02b c02f`, in both captured sessions. Chromium chose `c02b` every time. That suite is WebRTC's mandatory-to-implement suite (RFC 8827 §6.5). "Every fleet browser still connects" is shown for Chromium only: see row 9 |
| 9 | 2026-10-14 | **Wrong turns and side findings** | (1) The first capture missed the handshake. tcpdump, started by a backgrounded `sudo` over SSH, began 4.6 s into the session, and the session had already left its first pair, a relayed one where the handshake ran. Re-run with the capture as a transient unit that returns only once tcpdump runs. (2) **Playwright's Firefox never reached DTLS.** Its offer carries no H.264 (no OpenH264 plugin), the agent pins H.264, and `create_answer` fails, before any cipher suite is in play. Filed as #2231. (3) Playwright's WebKit on Linux stayed at "Requesting session…" (that build is not Safari). AC1 still owes a Firefox-with-OpenH264 and a Safari session |
| 10 | 2026-10-15 | **AC3, red then green on one guest.** A kept vmtest Ubuntu system guest, re-enrolled non-ephemeral (so a restart does not unenroll it) with self-update off, and one `/etc/meshharbor/config.toml` throughout. Red: agent 0.4.136. Green: agent-v0.4.137's `.deb`, checked against its `.sha256`, installed over it. The oracle is the agent's journal, read by the daemon's systemd invocation, and the device row's online state | **Red (0.4.136, 10:55–11:01Z):** with `server_url = "http://meshharbor.itachi.fans"` the agent dials `ws://meshharbor.itachi.fans/ws`, gets `HTTP error: 301 Moved Permanently` after every backoff, and stays offline; the file stays `http://`. **Green (0.4.137, 14:10Z), the file untouched:** `a plaintext server URL in the config is read as TLS; set allow_plaintext_server = true to keep plaintext (a lab without TLS)`, then `connecting to signaling server (role=agent) server=wss://meshharbor.itachi.fans/ws` and the hello 0.17 s later; online. The daemon's next save writes `https://meshharbor.itachi.fans` back to the file. **Loopback (0.4.137):** `http://127.0.0.1:3000` dials `ws://127.0.0.1:3000/ws` on every attempt, with no warning. Put back to `https://meshharbor.itachi.fans`, the device was online again |
| 11 | 2026-10-15 | **AC6's idle half, green then red**, the same guest. The production viewer (Playwright, Chromium) and server, with the server's frames on the viewer's `/ws` and the session's audit rows as the oracle. The device's own `access_policy.auto_terminate_idle_minutes` is set to 1, so no other device in the shared org is touched, and restored in a `finally` | **Green (0.4.137):** `rc:session.created` carries `idle_secs: 60`. The viewer's warning shows 50.2 s after the agent's answer, then `rc:terminate` with `idle_timeout` and `limit: idle` at 60.0 s, and the `session_ended` row names the same. Two runs (14:12Z and 14:21Z) gave the same result. **The control:** the next session, with a pointer move over the stage every 20 s, is still live after 100 s. This guest has no input path ("no X display, no uinput"), so the moves are counted, not injected. That is the agent's rule (`note_input_seen`): a controller who is present is activity. **Red (0.4.136, the agent put back on the same guest):** `idle_secs: null`, because without the `idle-timeout` word the viewer is told no limit. No warning and no end in 3.5 minutes, and the spec fails on its `idle_timeout` assertion |
| 12 | 2026-10-15 | **AC1's Firefox half, and #2231's field proof.** The same guest on 0.4.137. Playwright 1.62's Firefox (no OpenH264), then Chromium, each under a UDP capture that starts before the connect | Both went live. **Firefox:** the agent logs `RTP video track takes a codec the offer carries; the DataChannel carries the video pump_codec=h264 track_codec=vp8` and answers. The session runs on the VP9 DataChannel. The agent offers `c02b c02f`, and Firefox's ServerHello picks `c02b` (relayed, over TURN ChannelData). On 0.4.136 the same Firefox never reached DTLS (row 9). **Chromium:** the same offer, and `c02b` picked (direct). Safari is still owed |
| 13 | 2026-10-15 | **Wrong turns** | (1) **The control's first run failed, and the harness was at fault.** On the DataChannel paths the viewer hides its `<video>`, the first child of the stage. A `video, canvas` locator picked it, got no bounding box and moved nothing, so the control idled out at 60 s like the untouched session. Re-run over the stage (`.video-frame`), it held. (2) The green's first journal read used a 60 s window that opened after the restart's lines, and found nothing. Re-read by the daemon's invocation id. (3) The "read as TLS" warning is logged twice per start, 51 ms apart. Harmless; not chased |
| 14 | 2026-10-17 | **AC1's Safari half.** Safari 18.6 on macOS 15.7.7, in a throwaway clone of the vmtest tart golden on the operator's MacBook, driven by `safaridriver` (WebDriver, from a standard-library client), with `purestat.ai` blocked in the VM's `/etc/hosts`. Production's viewer, nothing served into the page, against a fresh vmtest Win11 `--type system` guest on the released 0.4.142 (`vmtest-w-ins-sys-224044`). The page's `RTCPeerConnection` was wrapped before Connect so its `getStats()` could be read | **Safari connects, on an ECDHE-GCM suite.** "connected" one second after Connect. The transport read `dtlsState: connected`, `dtlsCipher: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`c02b`) and `tlsVersion: FEFD` (DTLS 1.2), with Safari the DTLS server (the agent is the client, as for the others). Media: H.264 at 1280×800, 167 frames decoded in the first 12 s of a static desktop, the `<video>` clock advancing, and all five data channels open. The pair was srflx to srflx over UDP, 41 ms round trip. Safari's own screenshot shows the guest's desktop in the viewer. The SRTP profile Safari chose was `AES_CM_128_HMAC_SHA1_80`; that is not this criterion's (it is about the DTLS suites), and is recorded only. **Wrong turn:** the first run clicked Connect through WebDriver, and the click never returned (and wedged `safaridriver` until the VM was deleted). The likely cause, not observed directly: a WebDriver click is a trusted gesture, and inside one Safari answers the viewer's clipboard read with its native "Paste" callout, which nobody can answer in an automated session. The second run clicked Connect from a script, which carries no gesture (WebRTC does not need one), and connected at once. The guest was destroyed by name afterwards and its row removed |
| 15 | 2026-10-18 | **AC8, as amended: TURN's address family on production.** The TURN URLs production hands out, read from the deploy repo's `configmap-meshharbor2-config.yaml` (`MESHHARBOR__TURN__URL` = `turn:coturn.meshharbor.itachi.fans:3478`, `MESHHARBOR__TURN__WORKER_URLS` = `coturn-1..3.meshharbor.itachi.fans`). Each hostname resolved for A and AAAA over DNS-over-HTTPS (Cloudflare) | **IPv4 only, as designed.** `coturn.meshharbor.itachi.fans`: A `94.130.141.74`, `5.9.157.221`, `5.9.157.226`; AAAA NOERROR with no answer (the zone's SOA only). `coturn-1`, `-2`, `-3`: one A record each (`94.130.141.74`, `5.9.157.226`, `5.9.157.221`), and no AAAA. `meshharbor.itachi.fans` itself: A only. The operator settled AC8 as "IPv4-only by design, documented" rather than restart production TURN (2026-10-18), and `deployment.md` now says so |

## 9. Related

- [FR-100](FR-100-controller-identity.md): the identity binding that ships beside this.
- [FR-85](FR-85-hq-screen-recording.md): recording's rules, which this does not change.
- The program: [`docs/plans/stardesk-teardown-program.md`](../plans/stardesk-teardown-program.md).
