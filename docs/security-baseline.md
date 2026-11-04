# Security baseline

The controls that hold the product's security properties up, and **why each one
is shaped the way it is**. Most were written after a real defect; the reasoning
is the load-bearing part, because nearly every one of them reads as an
over-complication to someone who did not see the failure.

> **Scope.** This is the *server and web* baseline. The device-side gates —
> exec, SSH, remote config, peer relays — are default-deny ladders documented
> with their features: [fleet-rpc.md](fleet-rpc.md), [meshharbor-ssh.md](meshharbor-ssh.md),
> [remote-config.md](remote-config.md), [peer-relays.md](peer-relays.md).
> The permission bit catalogue is [permissions.md](permissions.md).

```mermaid
flowchart TB
    subgraph edge["Edge"]
        CORS["CORS · rate limit · security headers · CSP"]
    end
    subgraph ident["Identity — who is this?"]
        JWT["JWT: one audience per credential, cross-audience rejected"]
        COOK["Session cookie — HttpOnly, Secure in prod"]
        EMAIL["Email ownership — the unique index is a RESERVATION"]
    end
    subgraph authz["Authorization — may they?"]
        MEMB["Tenant membership"]
        OBJ["Object-level scoping — resolve WITHIN the tenant"]
        PERM["Permission bits + managed-role reconcile"]
    end
    subgraph plane["Data-plane guards"]
        AGENT["Agent token → row status-checked on every use"]
        CEIL["Per-(caller, device) exec/SSH ceilings"]
        SSRF["Push endpoint SSRF validation"]
        CONTENT["Upload sniffing · message HTML allowlist"]
    end
    edge --> ident --> authz --> plane
```

---

## 1 · Identity and sessions

| Control | Shape |
|---|---|
| Access token | 7 d (`MESHHARBOR__JWT__*`) |
| Refresh token | 30 d |
| Hashing | Argon2 |
| Audiences | `Access` · `Refresh` · `Enrollment` (single-use, 10 min) · `Agent` (1 y) |

`verify_agent_token` rejects a user JWT and vice-versa; locked by tests in
`crates/services/src/auth/mod.rs::tests`.

**Cookies carry `Secure` in production** (`app.environment == "production"`;
plain http in dev so the localhost flow still works). The cookie *is* a full API
credential — the auth extractor accepts it — so it must never travel in
cleartext.

**JWT default secret**: with `app.environment=production` the server **refuses to
boot** on the built-in default secret. Development keeps a loud warning.

### The browser no longer holds tokens (closed 2026-08-25, re-verified 2026-08-26)

Browser sessions used to hand JS **both** tokens — access (7 d) + refresh (30 d)
in `localStorage` — and shipped the access token in URL **query strings**
(`/oauth/callback?token=`, `/ws?token=`) that nginx logged in plaintext. Any XSS
stole 30 days of re-mintable access that survived logout.

Closed by the cookie-only session work (#680/#682/#690/#691). Current state,
verified against the tree rather than from memory:

- the only `localStorage` use left is a boolean `SIGNED_IN` hint documented as
  *not* a credential (`ui/src/api/session.ts`), plus a one-shot purge of the
  legacy token keys;
- `ui/src/stores/ws.ts` no longer puts `token=` on the WS dial;
- `oauth_callback` returns the token in the **URL fragment**, which browsers
  never send to a server, so it cannot reach an access log or a `Referer`.

⚠️ Two transitional shims remain and can be dropped now both halves have rolled:
the server still appends `#token=` for cached older bundles, and
`OAuthCallbackView.vue`'s comments still describe accepting a query-string form
the code no longer reads.

### Open: user sessions are irrevocable

`logout` only clears the cookie, there is **no password-change flow at all** (no
route exists), and nothing checks a `token_epoch` (the identifier appears nowhere
in the tree). A stolen access token stays valid for its full 7 days, and
disabling or deleting a user does not end their live sessions. Refresh tokens are
not rotated, so reuse is undetectable.

**Fix** = a `token_epoch` in the claims, checked on verify.

⚠️ The **agent** half of this is fixed. `agent_log.rs` / `agent_crash.rs` no
longer parse the bearer themselves: both go through
`crates/api/src/extractors/agent.rs::AuthAgent`, which loads the row
(`find_in_tenant`) and refuses via `refusal_reason`.
⚠️ A lookup **failure is deliberately 500, not 401** — a Mongo blip must not tell
a healthy fleet its credentials were revoked, which would turn a database wobble
into an enrollment storm.
⚠️ **Deletion wins over status**: the cascade tombstones the row without
necessarily rewriting `status`, so an Online-looking tombstone still refuses.
Verified in the field 2026-08-30, when a throwaway device's agent JWT was
surfaced in a daemon log line and the device had already been deleted.

---

## 2 · Email ownership — the invariant that closes the nOAuth class

The invariant in `find_or_create_by_oauth` is that **`users.email` holds an
address only if that account PROVED it**. It is a UNIQUE index, so it is a
*reservation*, not a contact field, and it is what account-linking keys off.

Three rules implement it. All three are load-bearing:

1. An **unverified** provider assertion takes a `.invalid` placeholder (RFC 2606)
   with the claim recorded in the non-indexed `unverified_email` — so a hostile
   Entra tenant cannot even *reserve* an address it does not own, let alone link
   into one.
2. Linking checks the **target** account is verified too — otherwise an attacker
   registers `victim@corp` with a password, never activates, and collects the
   victim's later Google sign-in, after which the activation mail *that lands in
   the victim's own inbox* hands over a password login.
3. A proven identity **evicts** an unproven claim instead of inheriting it. Safe
   only because an unverified account cannot have been signed into (password
   login refuses it; any verified provider identity would have made it verified).

On top of those, **step 2c** refuses an *unverified* identity whose asserted
address already belongs to someone (#610). That one is a **UX policy, not a
security control**: it arrived as a mechanical necessity (the create used to
collide on email and blame the username) and the placeholder removed the
collision, so it could now mint a parallel account and simply chooses not to,
because that account would be invisible to whoever owns the address.

> Deleting 2c costs UX. Deleting any of the three above costs security.

⚠️ Do **not** "simplify" this back to a one-sided `email_verified` check — that
was the state between #360 and this fix, and it left both the reservation and the
unactivated-signup paths open. Locked by 4 unit tests on the placeholders + 4
integration tests in `oauth_tests`.
⚠️ #610 and #613 fixed the same defect with different designs, in parallel
sessions, and git auto-merged them cleanly — verify the result on the buildhost
lane, because CI does not run this crate.
⚠️ **Microsoft is the only provider that is *always* unverified** (its Graph
`mail`/UPN are tenant-settable); its `id` (the `oid`) stays trusted and is the
provider-identity key.

### OAuth CSRF

`oauth_redirect` binds its random `state` to the browser in a short-lived
`HttpOnly` `oauth_state` cookie, and `oauth_callback` **requires** the query
`state` to equal it (double-submit), clearing it one-shot.

Before this the state was minted and thrown away with the callback validating
nothing, so an attacker could feed a victim a pre-obtained `code` and silently
sign them into the **attacker's** account (login CSRF): everything the victim
then wrote landed in the attacker's account.

⚠️ Any test driving `/api/oauth/callback/*` directly must now send the cookie.

---

## 3 · Authorization

### Object-level tenant scoping (closes a CRITICAL cross-tenant break, 2026-08-23)

**`is_member(tid)` is NOT an authorization check for anything keyed by id.**

Any user can create a tenant for free (`routes/tenant::create` is gated only by
`AuthUser`), so a caller can *always* satisfy `is_member` for a tenant they own
and then pass **another** tenant's `room_id` / `message_id`. The older
collaboration handlers did exactly that, and the DAO reads (`find_in_room`,
`find_pinned`, `find_thread_replies`, `find_by_room`, `list_members`,
`list_participants`) filter by the bare id with **no `tenant_id`**.

That exposed every org's chat history, bulk xlsx export, room rosters, recordings
and live call state to any authenticated account, and allowed injecting
`@everyone` messages into another org's channel.

**The invariant now: resolve the object WITHIN the tenant before touching it** —
`helpers::require_room_in_tenant` / `require_message_in_tenant`. They check
membership *and* `find_by_id_in_tenant`, so a foreign id 404s and leaks neither
content nor existence.

⚠️ A handler keyed by `message_id` **must** use the message guard, not the room
one — the two ids are decoupled, so a caller can pass their own room with a
foreign message. This is why `reaction::add/remove` fan out to `message.room_id`,
not the path room.
⚠️ **Never re-fetch with a bare `find_by_id` after a tenant-scoped write**:
`message::update` did, and returned another tenant's content in the response even
though the write itself was correctly scoped.
⚠️ `room::join` additionally requires `is_open` — it previously had **no checks at
all**, so anyone could join any private room in any org and receive its WS
fan-out. `room::update`/`delete` now require `MANAGE_CHANNELS` (they were
member-only, so any guest could archive or cascade-delete a channel).

### A 403 is an answer, not an expired credential (FR-82)

Full treatment in [permissions.md](permissions.md). The two rules that bind new
code:

- **A 403 never ends a session, on any method.** The only 403 with a navigation
  is `not_a_member` (`ApiError::NotAMember` ⇒ `error: "not_a_member"`, a
  server-sent **code** — never a message-string sniff, because chat's
  `Forbidden("Not a member of this room")` is the same shape and must not evict
  anyone from their org), and it leaves the *tenant*, not the product.
- ⚠️⚠️ **The default direction is the guarantee**: an unclassified 403 does
  nothing but throw, so a newly-added gated route is inert on the client by
  construction.

- **A system-managed role is reconciled, not frozen at its birthday.** One
  `role::MANAGED_ROLES` table, reconciled by `TenantDao::reconcile_managed_roles`
  under the existing `startup_maintenance` lease.
  ⚠️⚠️ **Additive (`stored | definition`), never a replace** — a managed mask *is*
  editable, so overwriting would silently revoke an org's own grant.
  ⚠️⚠️ `EXEC_DEVICE`/`SSH_DEVICE` are in no row below the `ADMINISTRATOR` bypass,
  and `no_managed_role_below_administrator_seeds_a_root_shell` enforces it: the
  reconcile grants what the table says to **every existing org**, so
  `DEFAULT_ADMIN |= EXEC_DEVICE` — a one-token edit that reads as tidying — would
  open exec-as-SYSTEM deployment-wide at the next boot, with no migration to
  review and no admin action to audit.

### Per-(caller, device) ceilings on exec and SSH

`crates/api/src/rate_limit.rs`, wired into `agent_exec::authorize` and
`agent_ssh::decide`. `exec_limits`/`ssh_limits::RATE_LIMIT_PER_MINUTE` and the
`RateLimited` deny reasons existed but had **no production readers** — the
constants were dead and the variant was built only in tests. The HTTP
`tower_governor` is per-IP and never saw the device-originated
`rc:rpc.request` / `rc:ssh.request` WS legs, so those had no ceiling at all.

⚠️ Enforcement sits **after** the identity gates on purpose: a refusal is then
attributable and lands in `exec_audit`/`ssh_audit` like any other.
⚠️ It also protects the **target** — the device's pending-grant table holds 16 and
evicts the oldest, so an unthrottled caller could burst a legitimate caller's
un-redeemed grant out of existence.

**Remote-desktop session requests got the same ceiling in FR-101 P4a**
(`crates/modules/remote/src/controller.rs`, `SESSION_REQUESTS_PER_MINUTE` = 60
per (caller, device)). `rc:session.request` rides the controller's `/ws`, which the
per-IP governor never sees. Without a ceiling, a signed-in caller could put a
consent prompt in front of the person at a device as fast as the socket carries
frames.

- The check sits **after** the authz gate, so a caller without the right to ask is
  refused `permission_denied` every time and never spends a slot.
- A refusal is `rc:error` `rate_limited`, which the viewer does not retry.
- No legitimate client comes near 60: the viewer's reconnect ladder asks about a
  dozen times in its first minute.

**A session can be bounded in length and in idleness** (FR-101 P4b,
[remote-control.md](remote-control.md) §11.6). Both limits are off by default and
set per org. The hub keeps the maximum length from the moment a session goes live.
The idle limit is kept by the device, the only party that sees both the
controller's input and the screen, and a device's own `auto_terminate_idle_minutes`
can only shorten the org's. Both end the session as `idle_timeout` and name the
limit (`max_duration` or `idle`) in `rc:terminate` and in the `session_ended` audit
row. The hub honours `idle` from the agent only.

### The SSH request route checks membership before the device lookup

`agent_ssh::member_tenant`, mirroring `agent_exec`. Without it a non-member could
distinguish "agent exists" (200 + refusal) from "no such agent" (404) across
tenants, write attacker-timed rows into another org's `ssh_audit`, and read
whether that org had `remote_ssh_enabled`.

---

## 4 · The device plane

**A device's credentials renew themselves, and a removal ends every one it held**
(FR-103, [`device-credentials.md`](device-credentials.md)). An agent or tunnel-client
token lives a year. The device renews it 180 days early, and a device off across its
expiry renews within a 90-day grace that only the renew routes honour; every other
route enforces `exp`.
- Renewal does not rotate: the old token stays valid until its own `exp`, so a lost
  answer, or a copy that missed the change, cannot cut a device off.
- What ends a credential is **removal**, not the calendar. Each token carries its
  row's `token_gen`, removing the device increments it in the same atomic update
  that tombstones the row, and all five verification sites compare the two.
  Re-enrolling the same machine revives the row, but never its old tokens.
- ⚠️ The deleted/quarantined check stays FIRST at each site, so a removed device is
  still told it was removed (and stops), rather than seeing a bare 401 it would
  retry forever.
- A device **connected** at its removal is told on the socket it holds, at once
  (#2267). Before, the kick only took it out of the hub, and it kept that socket,
  unaware, until something else dropped it. Nothing could act through it, since
  every action re-checks the row, but the device's own status still read
  "connected".

**A WG public key cannot be claimed by two live nodes in a network** —
`overlay_nodes::wg_key_taken_by_other`, checked in `ws::overlay` join,
**fail-closed**.

The key is client-supplied but used as an **addressing** key (DERP authorizes
registration against it; WireGuard keys peers by it) and nothing proves
possession of the private half, so a second enrolled device could advertise a
peer's key and black-hole its DERP traffic (registration is last-writer-wins).

Live-scoped so tombstones do not block a joiner; `machine_id`-scoped so a device
rotating its **own** key is unaffected. That rotation is an admin action from the
device grid — an *order* the device answers with a locally minted key, never a key
the server chose or saw; the device's re-join under the new key is what the server
verifies: [`overlay-key-rotation.md`](overlay-key-rotation.md) (FR-40).

**The LocalAPI's ACL is the local trust boundary.** The daemon's local control
endpoint carries administrative verbs: exec, SSH grants, config, routes, restart. On
Windows it is a named pipe whose security descriptor admits `SYSTEM`,
`Administrators` and the interactive user. On Unix a root daemon's socket is
`/var/run/meshharbor/meshharbor.sock`, 0700 / 0600, root only. Per-verb checks sit on top:
the recording verbs require the console user (FR-85) and an update hold requires
root (FR-90).

⚠️ **One deliberate carve-out: the person socket (FR-27 P11, #1911; FR-97 P2g).** A
Linux system install's companion runs as the desktop user and could not reach the root
socket. That left the person at the screen with no "being viewed" banner, no
Disconnect, and on Wayland no consent prompt. The root daemon therefore also serves
`/run/user/<uid>/meshharbor.sock`:
- it belongs to the user of the **active** graphical session only;
- it is 0600 and theirs because it is **made as them**: the bind and the `chmod` run on a
  thread switched to their filesystem ids (`setfsuid`/`setfsgid`). Their own directory
  lets them swap the path between any two root calls, and `chmod`/`chown` follow
  symlinks, so a root `chown` of that path could be raced into handing them
  `/etc/shadow`. The daemon therefore never runs a root path operation there;
- `SO_PEERCRED` is checked against that user or root on every connection;
- it serves exactly `Status`, `RcSessions`, `RcDisconnect`, `ConsentPending`,
  `ConsentDecide` and `RecordStatus`; `KeepBusyStatus`, `KeepBusyOff` and
  `KeepBusyOn` (FR-92 P10, the start gated again on the peer); since FR-97 P2g,
  `Devices` and `Mesh`; and since P2h, `Peers`, served through `person_view`.

`Devices` and `Mesh` were the first widening for a read rather than a safety control,
and they are bounded the same way the companion's page is everywhere else. They only
read. The server shapes the answer by **this machine's** overlay ACL (`agent_self.rs`),
so the person can search, sort and page the set but never widen it. The rows carry no
machine ids, keys or owner ids. Windows already serves the same verbs to its
interactive users.

`Peers` (P2h) is the live state of the links to those same devices: online, direct or
relayed and over what, round trip, last seen. The person socket serves it through
`localapi::person_view`, which drops everything only an administrator debugging a path
needs. That is the endpoints of either end and of a relay (`relay_local`, `relay_dst`,
`relay_server`), the carrier snapshot (`debug`), the path decision (`why`) and the
prober's measurements (`probes`). Those name other devices' public and LAN addresses,
which the overlay addresses already on the Devices page do not.

**A Mac's root half serves one too (FR-97 P2g).** Only root can hold a utun, so a
two-half Mac (FR-43) is on the private network through its root half alone, and the
per-user half that the companion talks to has no node. The root half therefore serves
the console user a person socket at `/var/run/meshharbor-person/<uid>.sock`, and the
per-user half asks it for `Devices` and `Mesh`. The bind is not the Linux one, because
the directory is not the person's:
- `/var/run/meshharbor-person` must be a real directory (not a link), owned by root, and
  writable by nobody else (`root_only_dir`, checked on every bind). Nobody but root
  can create, swap or link an entry there, so root may bind and then hand the socket
  over (`lchown` to the person, then 0600). In a directory the person owns, that is
  exactly the race the Linux bind avoids. macOS has no per-thread filesystem ids to
  borrow in any case;
- nothing is accepted until that hand-over is done, and `getpeereid` is checked
  against that user or root on every connection, whatever the mode was in between;
- the person is the console user (`/dev/console`'s owner), never the login window;
- the per-user half believes an answer only from a socket **root** serves
  (`connect_unix_served_by_root`: the server's uid, from the kernel). The directory
  already keeps everyone else out; this is the second lock, because the answer is shown
  to the person as the machine's own.

The allowlist (`localapi::person_may`) is an exhaustive match with no `_` arm, so a
new verb cannot reach it by default. Widening it is a security change and needs
review like one. The root socket itself is unchanged. Kill switch:
`MESHHARBORD_PERSON_SOCKET=0`.

**A remote-desktop session's media transport is hardened past webrtc-rs' defaults**
(FR-101 P1, `agents/meshharbord/src/rc_transport.rs`, applied in `AgentPeer::new`):

| Setting | Default now | Why | Switch back |
|---|---|---|---|
| DTLS cipher suites | the two ECDHE-AES-128-GCM-SHA256 suites | webrtc-dtls' default list still offers ECDHE-AES-256-CBC-SHA; every supported browser negotiates GCM | `MESHHARBORD_DTLS_LEGACY_SUITES=1` |
| SRTP + SRTCP replay window | 64, **pinned**, not switched on | webrtc-srtp's `Session::new` already gives the remote context a 64-packet window when its config has none, so sessions refused replays before FR-101 too. Setting it explicitly keeps it 64 should a release change that default | none: `MESHHARBORD_SRTP_REPLAY_WINDOW=N` sizes it, and `0` leaves the library's 64 |

> [!NOTE]
> **Corrected 2026-10-13: replay protection was never off.** FR-101's evidence said
> webrtc-srtp 0.14 had no replay window unless one was set. That read the fallback in
> `Context::new`, and a session never reaches it, because `Session::new` supplies a
> window first. FR-16 L0's replay cells (`agents/meshharbord/tests/l4_latency.rs`) capture
> the controller's SRTCP PLI on the link and deliver it to the agent again, into a live
> session:
>
> | Cell | Result |
> |---|---|
> | this policy | refused |
> | no window set, as before FR-101 | refused |
> | protection disabled through the setting engine | obeyed: one keyframe per replay |
>
> The third cell is the negative control. No production setting disables the
> protection, and none ever did. The same cells read the agent's real ClientHello off
> the link: only `c02b c02f` by default, `c00a` and `c014` back with the switch.

The suite list needs a setter upstream does not have. It is a one-field patch to the
vendored webrtc crate (`SettingEngine::set_dtls_cipher_suites`, noted in the workspace
`Cargo.toml`). Tunnel and overlay peers build their own engines and are unchanged.

**A device reaches its server over TLS, whatever its config says** (FR-101 P1b,
`crates/remote_control/src/server_url.rs`). Enrollment always rewrote `http://` to
`https://`. But a `server_url` that reached a config some other way, by a hand edit or an
enrollment from before the rule, was dialled as written. That meant a plaintext control
WebSocket, and plaintext HTTP for the token renewal, the updater and the uploads, with
the device's credential on every request. Now one rule holds wherever a server URL
enters: a remote `http://` is read as `https://`, and `ws://` as `wss://`.

| Entry point | A remote plaintext URL | Before |
|---|---|---|
| The agent's enrollment: `meshharbord enroll` and `re-enroll`, the wizard's agent role, the desktop companion | promoted | promoted, but only when spelled `http://` in lower case |
| Every load of the agent's config: `server_url`, `ws_url`, and each `[[orgs]]` entry's | promoted, with a warning naming the field | dialled as written |
| `mh enroll`, the wizard's tunnel role | promoted | **the tunnel enrollment token was posted in plaintext** |
| The tunnel CLI's config, from the file or `MESHHARBOR_TUNNEL_SERVER` | promoted | dialled as written |
| `meshharbord anchor create` (FR-104) | refused, unchanged: the claim's answer is the command SYSTEM runs | refused |

- **Loopback is exempt** (`localhost`, `127.0.0.0/8`, `::1`). It has no off-host path to
  defend, and dev, test and CI servers run plaintext there.
- ⚠️ **The guard reads a URL the way its dialler does.** reqwest parses by the WHATWG
  rules, which accept `HTTP:meshharbor.itachi.fans`, `http:\\meshharbor.itachi.fans`, surrounding whitespace and
  a tab inside the scheme. They also put the host after the authority's last `@`, so
  `http://localhost:80@evil.example` dials `evil.example`. A guard stricter than its
  dialler is a guard with a hole. A unit test therefore parses every spelling with the
  real `url` crate and checks that the two agree.
- **The escape belongs to the device.** A lab whose server has no TLS sets
  `allow_plaintext_server = true` in the device's own `config.toml`. The LocalAPI accepts
  that key only from the console, and it is structurally absent from `DesiredConfig`, so
  a compromised server cannot talk a fleet down to plaintext. The tunnel CLI reads the
  same key, or `MESHHARBOR_TUNNEL_ALLOW_PLAINTEXT=1` on its environment path. There is no
  escape at enrollment: a token always travels over TLS.
- **Counted before the default changed.** The ingress logged no plaintext agent `/ws`
  attempt over about eight hours. Production's port 80 answers everything with a 301, and
  a WebSocket client does not follow it. No deployed device could have been connected
  over plaintext, so the rule can only bring such a device back.

**Clipboard, files and audio follow a policy, and the device's own floor survives a
compromised server** (FR-101 P2, [remote-control.md](remote-control.md) §11.3b). An org
(`rc-session-policy`) and each device's owner (`rc_clipboard`, `rc_files`, `rc_audio`) can
each switch a feature to `on`, `ask` or `off`, and the stricter wins.
- The device's floor can be set over the LocalAPI only from the console, and it is
  absent from `DesiredConfig`, so no server can switch on what the owner switched off.
  The agent masks the grant itself, whatever the hub sends: a request carrying `FILES`
  with no policy, as from a bypassed hub, loses `FILES` on a device set to `off`.
- The hub strips the refused bits before the request and names each refusal:
  `features_refused` to the viewer, `features_stripped` in the `session_requested`
  audit row. The viewer can therefore say whose decision it was.
- `ask` holds only for a session the person at the device approves on a prompt that
  names the feature. Every other path drops the feature (`needs_consent`).
- A tenant row the gate could not read withholds the features (`policy_unavailable`).
  A database blip must not hand over what an org switched off.

The audit rows FR-101 writes, and who writes each one:

```mermaid
flowchart LR
    subgraph hub["hub (the server's decisions)"]
        REQ["session_requested:<br/>features_stripped, idle_secs"]
        END["session_ended:<br/>reason, limit (max_duration / idle)"]
    end
    subgraph dev["meshharbord (the device's claims)"]
        TR["clipboard + file tallies<br/>on rc:session.stats"]
    end
    REQ --> RA[("remote_audit")]
    END --> RA
    TR -->|"kept only for a granted session"| TA[("transfer_activity")]
```

**Clipboard and file traffic is audited as the device's claim** (FR-101 P3,
`crates/modules/remote/src/agent_socket.rs`, [remote-control.md](remote-control.md) §11.3a).
The payload travels peer to peer, so the server cannot observe a transfer. The device reports
counts, bytes and a SHA-256 of each file name on `rc:session.stats`. The hub keeps them in
`transfer_activity` only for a session of that device whose grant allowed the traffic:
`CLIPBOARD` for the clipboard, `FILES` for files.

- **Never content, never a name.** A name hash that is not 64 lowercase hex digits is
  dropped, so a host cannot store a name in its place.
- ⚠️ **Kept apart from `remote_audit`**, which holds the server's own decisions, as
  `recording_activity` and `ssh_activity` are. An empty result is not proof that nothing
  crossed: a compromised host can stay silent.

**Privacy mode is audited the same way** (FR-99 P1d, [privacy-mode.md](privacy-mode.md#what-is-recorded)).
The server decides the `PRIVACY` grant and writes it, or the strip and its reason, into
`session_requested`. The curtain itself is drawn on the host, at a request that travels peer to
peer, so the device reports each curtain up, each take-down with its reason, and each refusal on
`rc:privacy.activity`. The hub keeps a report in `privacy_activity` only for a session of that device
whose grant held `PRIVACY`.

- A process killed with a curtain up cannot report it. The OS takes the curtain down with the
  process, so the screen is uncovered, but nothing reaches the server. Each curtain is therefore
  written to a ledger file before it goes up. The next process to start reports every entry it finds
  as `off {worker_exit}`, and the stored session row decides that report after the session ended.
- A reason must be a short code. Free text from a host that may be compromised is dropped, and the
  row is kept without it.

**An admin's lock ask is the server's decision** (FR-99 P3b,
[privacy-mode.md](privacy-mode.md#an-admin-can-ask-for-stricter-p3b)). `session_requested` records
what the device's access policy asked of the session's end (`lock_on_end`) and whether the device
honours an ask (`lock_enforced`). The ask can only make the owner's own `lock_on_end` stricter, and
only an install that can lift the lock remotely takes one, so it can never cost an operator remote
access to a per-user install.

**A session's DTLS keys are bound to keys the two ends hold, not to the signalling path** (FR-100,
[remote-control.md](remote-control.md) §11.4a). The SDP fingerprints are the only thing tying each side's DTLS
certificate to an identity, and the hub rebuilds every offer and answer frame around them. So a hostile hub,
its Redis, or a TLS-inspecting box on a signalling leg could otherwise stand in for either end.

| Who signs | With what | Checked by | Shipped |
|---|---|---|---|
| The device, its answer | a P-256 key per enrollment, made on the device; the private half in `<config dir>/peer-auth/<tenant>.json` with the config's protection (0600 on Unix), never sent | the browser, **before** it applies the answer; the key is pinned per (user, device) on first use | key + signature 0.4.145 (P1a, P1b); the browser's check P2a |
| The browser, its offer | a P-256 key per user, made in the browser, non-extractable, kept in IndexedDB | the device, which remembers each browser key per user in `<tenant>.controllers.json` | the signature P2b; the device's check 0.4.146 (P1c) |

- **The browser fails closed.** A different key, or a signature that does not verify, ends the attempt
  before any media or input flows, and only the person's click trusts a changed key.
- **The device refuses nothing yet.** `peer_auth = audit` judges, remembers and records. `enforce` (P3) is
  refused by name at `config set` until the controller prompts exist: before them it would refuse every
  session to the device, which is a self-wedge. The policy is device-owned, console-only over the LocalAPI,
  and never pushable (`no_peer_auth_key_is_server_pushable_via_desired_config`).
- ⚠️ **Not stopped yet.** An attacker in the signalling path who strips the nonce or the signatures gets an
  **Unverified** session, not a refusal, until P3. And whoever serves the viewer's JavaScript can make the
  browser's key sign anything (FR-100 §1).
- ⚠️ **The verdict on `session_started` is the device's word**, kept on the server's row on purpose (§11.4a):
  the hub checks the word, never the judgement behind it.

---

## 5 · Network-facing surfaces

### Web Push endpoints are SSRF-validated at subscribe time

`routes/push.rs::validate_push_endpoint`: https only, and every resolved address
must be globally routable — loopback, RFC1918, `169.254` metadata, CGNAT-and-overlay
`100.64/10`, ULA, link-local v6 and v4-mapped forms all refused; unresolvable
hosts refused.

The endpoint is browser-supplied and the **server POSTs to it from inside the
cluster** on every notification fan-out, so without this any user had a blind
SSRF + internal port-scan primitive.

⚠️ This is subscribe-time only — DNS can still rebind before send.

### CORS

Unset `cors_origins` allows **only the frontend's own origin** (it was `Any`
until 2026-07-28). An explicit `"*"` keeps permissive mode with a startup
warning. The restrictive branch enumerates methods/headers because
`allow_credentials(true)` + wildcard is rejected by tower-http at request time.

### Rate limiting

`tower_governor`, 60 req/min per IP.

### Security headers and CSP (`files/nginx-pod.conf`)

`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy`; HSTS + CSP added 2026-07-28.

**The CSP allowlist is load-bearing and non-obvious** (corrected 2026-07-29, #252):

```
script-src  'self' https://purestat.ai
connect-src 'self' wss: https: http://127.0.0.1:* http://localhost:*
```

| Entry | Why it must stay |
|---|---|
| `https://purestat.ai` | the site's own analytics, loaded in `index.html` |
| `http://127.0.0.1:*` / `http://localhost:*` | **required**: the remote-control viewer probes the local agent's loopback-TURN relay (`http://127.0.0.1:4798x/rc-local-turn`) and clipboard bridge (`rc-clipboard`, port bases 41989 + 47989) |

⚠️ The initial CSP (#242) omitted both and broke analytics + the RC loopback-relay
path **in prod** — the CSP validation had only exercised dashboard / auth /
websocket, never the RC viewer.
⚠️ **When touching CSP, re-scan `ui/` for external *and* loopback endpoints**
(`grep -rhoE "https?://…"`) and exercise the remote-control page, not just the
main SPA.

---

## 6 · Content the product accepts

### Uploads are sniffed, not trusted (fixed 2026-08-25)

File upload stored the client-supplied `content-type` verbatim.
`crate::media_type::resolve` now sniffs the bytes (`infer`) and stores what they
**actually** are; the claim is passed in only to be ignored, so the call sites
read as "we had a claim and did not use it". Both upload handlers go through it.

⚠️ The fallback for signature-less content is a **narrow extension map that
structurally cannot produce `image/*` or `text/html`** — those are exactly the
types worth lying about, so they must be proven by magic bytes; a `.png` name
alone gets `application/octet-stream`. A table-level test enforces that, because
adding `("svg", "image/svg+xml")` later would look reasonable in review and would
reintroduce the whole defect.
⚠️ It is **not** a whitelist of what a client may claim — a whitelist still trusts
the claim.
⚠️ **Correction to the 2026-08-23 re-rating**, which partly rested on "the UI only
ever renders `<a href=…>` (no iframe, no `<img>`)": that is **false**.
`MessageBubble.vue` renders `<v-img :src="att.url">` for any attachment whose type
starts with `image/`. It still was not an XSS (an SVG in `<img>` cannot run
script, and `openAttachment` is `window.open` → a top-level navigation, which
honours `Content-Disposition: attachment`) — but the reasoning was wrong, and the
render decision is now made on a sniffed type instead of a claimed one.
`integration.rs` also steers a recognition backend with this string.

### Message HTML

The sanitizer allowlist (`ui/src/composables/useMarkdown.ts`) deliberately
**excludes `style`** — author-controlled inline CSS let one chat message paint a
full-viewport `position:fixed` overlay inside the trusted origin (credential
phishing that no framing header stops) and fire a `background:url()` beacon at
every viewer. The mention preprocessor HTML-escapes its label/id, so that
string-concatenation step is not relying on DOMPurify's allowlist staying exactly
as it is.

⚠️ Treat `ALLOWED_TAGS` / `ALLOWED_ATTR` as a **security control**: it is the only
XSS boundary for message content.

### Downloads

`Content-Disposition` filenames are sanitized + RFC 5987 encoded on the file
download route (2026-05-23).

---

## 7 · Publishing identity — an allowlist at four layers

This repo is **public**, and two surfaces leak *who* rather than *what*, both
invisible to the machine-name guards:

- a commit's **author/committer email** — metadata, in no blob and no message, so
  `check_shapes.py` walks straight past it;
- a **GitHub account login** on an issue, comment, review or release — never
  touches git at all.

Found by audit: a second GitHub account — a corp one, whose *login alone* named an
employer — had authored one issue and three comments across three days spanning
eleven, plus 520 commits carrying a corp mailbox as their author address. Nothing
failed, nothing warned.

| Layer | Catches | Blind to |
|---|---|---|
| `.githooks/pre-commit` (`--pending`, pure bash+git so it runs where python does not) | the commit about to be made | pushes that skip hooks |
| `.githooks/pre-push` | **survives `--no-verify`** and a clone that never set `core.hooksPath` | GitHub-side writes |
| CI job **No foreign commit identity** | anything that reached a branch | account logins |
| `PreToolUse` hook `.claude/hooks/gh-account-guard.sh` | GitHub **writes** by the active `gh` account (reads always pass — auditing the wrong account is legitimate, and is what found this) | commits |

⚠️ **Allowlist, never a denylist.** A denylist would have to write the unwanted
addresses into a public file, publishing exactly what it removes, and only finds
mistakes someone already thought of. `.githooks/allowed-identities.txt` names only
already-public identities, and the selftest fails on a wildcard or a bare-domain
entry.
⚠️ **`gh auth switch` is GLOBAL** — it re-identifies every concurrent session from
a shared config, and `gh issue comment` prints a URL, not an identity, so the
mistake is invisible from inside the session making it. The hook refuses it
outright; `scripts/gh-scoped-config.sh` builds a config the other account is not
*in*.
⚠️ **`--require-commits` in CI is load-bearing**: an empty range otherwise answers
"all known" over zero commits — the same shape as a `cargo test` filter matching
no test.
⚠️ **Neither leak is recoverable downstream.** A commit identity can only be
*rewritten* (renumbering every SHA above it, and the old objects stay reachable
through `refs/pull/*`); an issue/comment author cannot be changed at all — only
delete-and-recreate, which dangles every reference to its number, including one
already baked into a merged commit subject.
⚠️ **The one hole no local layer closes**: a merge made through the GitHub web UI
is committed *on GitHub* from the email set on the **account**, after every hook
and PR check has passed.
⚠️ **A ruleset cannot close it here** — the whole metadata-rule family
(`commit_author_email_pattern`, `committer_email_pattern`,
`commit_message_pattern`, `branch_name_pattern`) is organisation-and-paid-plan
only and is refused with HTTP 422 on this user-owned repo, in `active` enforcement
as well (`evaluate` is separately Enterprise-only). Measured 2026-09-06 — do not
plan around it.

What covers it is the CI job's **push-to-master** run
(`github.event.before..github.sha`), which turns master red within a minute —
detection, not prevention. ⚠️ Its fallback is load-bearing and was exercised on
day one: after a force-push `event.before` names a commit that no longer exists,
so it falls back to `<sha>~1..<sha>` instead of erroring or silently scanning
nothing.

The actual fix for the account is GitHub Settings → Emails.

---

## 8 · Secrets and dependencies

- TURN `static-auth-secret` was rotated out of the repo on 2026-05-23 — the
  committed `turnserver.conf` carries a `CHANGE-ME` placeholder; the live value
  lives in the operator's `MESHHARBOR__TURN__SHARED_SECRET` env.
- **No git hooks for secrets**: there is no gitleaks/trufflehog scanner in CI.
  *(Open, [LOW], 2026-03-10.)*

### Dependency-uplift pass (2026-07-29)

**Rust** — cleared 4 advisories via precise semver-compatible lockfile bumps
(crossbeam-epoch 0.9.18→0.9.20 RUSTSEC-2026-0204, memmap2 0.9.10→0.9.11
RUSTSEC-2024-0429, quinn-proto 0.11.14→0.11.16 RUSTSEC-2026-0185, spin 0.9.8→0.9.9
yanked).

Deferred — each needs a **breaking direct-dep bump** and none is reachable in our
usage:

| Advisory | Why unreached |
|---|---|
| **rsa 0.7.2** Marvin timing ← web-push/jwt-simple | VAPID uses EC (ES256), not RSA-decrypt, so the timing oracle is not reachable |
| **lopdf 0.26.0** stack overflow ← genpdf (at its latest 0.2.0, upstream-blocked) | genpdf only *generates* PDFs, never parses untrusted input |
| **idna 0.5.0** punycode ← validator 0.18 | latest is 0.21, 3 breaking minors |
| **quick-xml 0.38.4** | transitive `^0.38` pin |

**JS** — the only runtime-reachable high is markdown-it→linkify-it (client-side
ReDoS on crafted message links), but the fix is only in linkify-it 6.x which
markdown-it 14 cannot import (`default` export removed → build break), so it is
ecosystem-blocked until markdown-it adopts 6.x. All other JS highs
(jsdom→undici, @vue/test-utils→js-cookie/minimatch, vue-router→rollup) are
dev/build tooling, never shipped in the prod bundle.

Re-run: `bun audit` (ui) + `cargo audit` (buildhost, `~/.cargo/bin`).

---

## 9 · Open gaps

| Sev | Since | Gap |
|---|---|---|
| MEDIUM | 2026-08-23 | **User sessions are irrevocable** — no `token_epoch`, no password-change route, no refresh rotation (§1) |
| LOW | 2026-03-10 | No secret scanner in CI, no pre-commit lint hooks (§8) |
| — | 2026-07-29 | Four Rust advisories + one JS advisory deferred as unreachable (§8) |

Device-side and updater gaps are tracked with their features:
[installation.md](installation.md) (updater trust chain),
[fr/README.md](fr/README.md) (everything in flight).
