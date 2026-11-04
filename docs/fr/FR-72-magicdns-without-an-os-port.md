# FR-72 — One MagicDNS resolver per daemon

**Issue:** [#1382](https://github.com/gjovanov/roomler-ai/issues/1382) · **Status:** P1 + P2 + P6 shipped and field-verified — **MagicDNS now resolves on the enforced-DNS host too**; P5 parked, P3 (#1363) open · **Opened:** 2026-09-05

> ⚠️ **Re-aimed 2026-09-05, same day, after the verification overturned the
> original premise.** This FR opened as *"MagicDNS without an OS port"* — the
> theory that a third party owning `0.0.0.0:53` was killing the feature, to be
> fixed by intercepting DNS below the OS the way roomler SSH intercepts `:22`.
> That theory was wrong in an instructive way and the history is kept below,
> because the wrong turn is the most useful part of the record.

## Goal

MagicDNS resolves on every enrolled host, for as long as the daemon runs — not
only until the first WebSocket reconnect, and not only until the first time
something else briefly holds the port.

## Phases

| # | Phase | Status | Kill switch |
|---|---|---|---|
| P1 | Keep the resolver's `JoinHandle` and abort it in the runtime teardown | **shipped 0.4.71** (#1397) | — (a task that was already meant to stop) |
| P2 | Retry a failed bind; steer the OS when the bind lands late; await the aborted task | **shipped 0.4.73** (#1414), field-verified | — (retry is unconditional; the pre-P2 behaviour is "give up", not a safer state) |
| P3 | Reporting: make `magicdns active` mean *answering* | open (#1363) | — |
| P4 | Docs: [`docs/magicdns.md`](../magicdns.md) in house style with diagrams, linked from `docs/README.md` | **shipped** | — |
| P5 | **Write the NRPT rule into the Group-Policy store where the local store is inert** (Tailscale's `writeAsGP`) | **PARKED** — necessary but not sufficient; the host that motivated it is blocked one layer higher | detect-and-fall-back; a host whose local rule works must keep using it |
| P6 | **A resolution ladder, with the hosts file as its last rung** | **shipped 0.4.76** (#1437), **field-verified** — the goal is met on the enforced-DNS host | `MESHHARBORD_MAGICDNS_HOSTS`, default OFF |

### P6 — the rung that is not on the DNS path

P5 could not win because the blocker is not *which store the rule lives in* — it
is that the host's own DNS packets never reach the resolver at all. The hosts
file is not on the DNS path, which is the entire reason it survives.

So the answer is a **ladder**, chosen by measurement rather than assumed — the
rule the carrier cascade already follows:

1. the **OS split-DNS steer** — preferred: dynamic, whole-zone, nothing on disk
2. **probe whether it actually reaches us**
3. **hosts-file entries** when it does not — and **climb back** when DNS returns

🔑 **The probe is the load-bearing part.** `dns::PROBE_LABEL`
(`_roomler-probe.<magic domain>`) is answered by our resolver and by nothing
else, so resolving it *through the OS* succeeds exactly when the steer reaches
us. ⚠️ The fallback must never write that name: it would then answer its own
probe, and the ladder could never climb back — a check that cannot fail.

⚠️ **The hazard is a stale entry, not the write.** Overlay addresses are
recycled, so a line left behind can route to a *different machine* — the same
class as pooling an address before its tombstone. Hence: a delimited block that
preserves every foreign line byte for byte; an unterminated block (killed
mid-write) **discarded, never adopted**; and the block cleared on teardown, on
climbing back, **and at construction** — the boot reconciler for whatever a dead
process left. ⚠️ **FQDNs only** — a bare `mars` would shadow a real corporate
host.

⚠️ **Known gap before the default flip**: `roomler config set magicdns_hosts` is
**refused** — the key is in the config file and the env bridge but not in the S2
config surface, so a fleet operator cannot flip it remotely. A feature that
cannot be switched on from the dashboard is not yet usable at fleet scale.

### P5 — why it exists

On a GPO-managed Windows host the local NRPT store is **ignored**, so every
other part of the feature can be perfectly healthy and no query ever reaches the
resolver. Measured on 0.4.73, on the host that opened this FR:

```
Get-NetUDPEndpoint 53               ->  <self overlay ip>  by roomlerd     ← bound, correct address
Get-DnsClientNrptRule   (local)     ->  .<magic domain> -> <self ip>       ← we wrote it
Get-DnsClientNrptPolicy -Effective  ->  0 rules                            ← nothing honours it
Resolve-DnsName <peer>.<domain>     ->  NO ANSWER   (out-of-zone control: ok)
```

Both halves are measured on that same host: a **GP-store** rule takes the
effective table 0 → 1; the **local** rule read 0 across repeated checks and a
clean reboot.

> ⚠️ **Correction, measured after the GP experiment was reverted.** With my
> experimental key removed and the policy refreshed, the effective table now
> shows **the daemon's own LOCAL rule**, matching its current address. So the
> local store is **not inert** — on this host a locally-written rule is *not
> effective until a policy refresh*, which is a different and much cheaper
> problem.
>
> That weakens P5 further: if a refresh is what a local rule needs, the fix is to
> **trigger one after writing**, not to write the Group-Policy store at all — no
> SYSTEM-level registry writer, and none of its revert hazard. It also explains
> the intermittency, since the daemon rewrites the rule on every reconnect while
> the next scheduled refresh may be up to ~90 min away.
>
> ⚠️ This does **not** touch the enforced-DNS finding below, which was measured
> independently and still holds with the local rule effective.

⚠️ `Version` must be **1**. With `2` — what `Add-DnsClientNrptRule` writes into
the local store — a GP rule is not parsed at all.

### 🚨 …and it still does not resolve. The blocker is above us.

With that GP rule effective and correct, names still did not resolve. A **raw
UDP DNS query** — the one instrument that could see past `Resolve-DnsName` —
found why:

| query, same moment | result |
|---|---|
| **from a peer** → that host's `:53` | **ANSWERS**, correct A + AAAA |
| **the host itself** → its OWN `:53` | **REFUSED (rcode 5)** |
| the host → `1.1.1.1`, `8.8.8.8` | **timeout** (dropped) |
| the host's configured DNS | corporate `10.130.x.x` |

`roomlerd` holds that socket and our resolver **never returns REFUSED** — it
answers in-zone from the map and forwards out-of-zone. So the host's own DNS
packets never reach it: a corporate DNS-enforcement layer intercepts local DNS
egress, dropping queries to public resolvers and refusing them to any
non-approved address — **the host's own overlay address included**.

🔑 The proof is that the *same resolver, at the same moment*, answers a peer and
refuses its own host. No choice of NRPT store changes that.

### Why P5 is parked rather than built

It is **necessary** for GPO-managed hosts in general, and it demonstrably
**cannot fix the host that motivated it**. With no host where it can be shown to
help, building a registry writer that runs as **SYSTEM on every enrolled
machine** — carrying a revert hazard the daemon cannot discharge, since it
writes the *local* store and so could never remove a stale GP rule — is the
wrong trade. Parked with its measurements, buildable the moment a host appears
where it is the only thing in the way.

⚠️ **A correction to my own earlier note here**: "a GP rule plus `gpupdate` took
the effective table 0 → 1, so it works" reported a *registry state* as if it
were a *resolution outcome*. It goes effective; the name still does not resolve.
**Effective ≠ answers** — the same trap as `active` ≠ answers (#1363), one layer
down.

⚠️ Design constraints, in the order they will bite:

1. **Detect, don't assume.** Writing GP unconditionally means re-asserting
   against every policy refresh on hosts that never needed it. `detectWriteAsGP`
   gates on whether unowned rules remain.
2. **The revert path is the risk, not the write.** A GP rule that outlives the
   daemon steers a domain at a resolver that no longer exists — host-wide, since
   the NRPT is registry-global. `DnsOsGuard`'s `Drop` must reach the GP store,
   and a boot reconciler must heal what a hard exit left behind. This is the
   same "never self-wedge" rule the route guards follow.
3. `nrptMaxDomainsPerRule = 50` is **domains per rule**, not a cap on rules.

## The bug, part 1 — we collided with ourselves (P1)

`OverlayRuntime::run` is scoped to **one WS session**. It spawned the resolver
with `tokio::spawn(dns::run(...))` and **discarded the JoinHandle**, while
`dns::run` serves until its socket errors. So the task outlived the runtime that
created it and kept `<self overlay ip>:53` bound. Every reconnect then spawned
another resolver, which lost the bind **to its own dead predecessor**.

Field-measured, two starts fourteen seconds apart inside one daemon lifetime:

```
19:52:48  INFO magicdns: resolver up               bind=<self>:53
19:53:02  WARN magicdns: bind failed; resolver off bind=<self>:53  AddressAlreadyInUse
```

Three consequences, all observed:

1. **MagicDNS dies at the first reconnect** and stays dead until the process
   restarts. On a host whose overlay churns — a corp VPN reaping routes, say —
   reconnects are frequent, so this is the normal state there, not a rare race.
2. **`roomler status` reports whichever runtime's flag it reads**, so the same
   host showed `resolver DOWN` and `active` hours apart. That intermittency was
   the most misleading symptom (see #1363).
3. **The survivor answers from the DEAD session's name map**, so names NXDOMAIN
   while the port looks healthy — bound, owned by `roomlerd`, serving nothing
   useful.

## The bug, part 2 — a failed bind was never retried (P2)

P1 was real and insufficient. `dns::run` logged a failed bind and **returned**,
so **one momentary conflict disabled MagicDNS for the daemon's whole lifetime**,
with nothing scheduled to try again. Measured on the dev box on 0.4.71 — a
daemon restart racing its own dying predecessor and losing on **both** orgs:

```
20:57:13  INFO magicdns: resolver up               bind=<a>:53   (org A)
20:57:13  INFO magicdns: resolver up               bind=<b>:53   (org B)
21:03:17  WARN magicdns: bind failed; resolver off bind=<b>:53   AddressAlreadyInUse
21:03:18  WARN magicdns: bind failed; resolver off bind=<a>:53   AddressAlreadyInUse
```

**Five hours dead** — and a probe minutes later bound the same address on the
first try, plain *and* with `SO_REUSEADDR`. Nothing held it any more; nothing
asked.

🔑 **The tell that separates P2 from P1**: every healthy cycle in that log has an
`OS split-DNS reverted` (teardown) line ~25 s before the next `resolver up`. The
failing one has **none** — it is a *process restart*, not a WS reconnect, which
is precisely the case P1's teardown abort cannot cover.

### Why the retry alone would not have been enough

The runtime decides **once, at bring-up**, whether to steer the OS, and
deliberately withholds the steer when the resolver did not bind — steering at a
dead `:53` blackholes the magic domain host-wide, since NRPT is registry-global.
So a resolver that bound on a later attempt would serve a resolver **nobody was
pointed at**: bound, healthy, and useless. The report is therefore a `watch`
rather than a `oneshot`, and the runtime installs the steer when it flips.

⚠️ One-way on purpose: it installs the steer late, never revokes it. The guard's
`Drop` already reverts on teardown, and a flapping bind must not repeatedly
rewrite a host-global registry key.

### And a third, smaller defect found while reading P1 back

`JoinHandle::abort()` only **requests** cancellation — the socket is released
when the task is next polled and dropped, which is not guaranteed to happen
before the next session's resolver binds. P1's own comment claimed *"the socket
is released when the task drops, so the successor binds cleanly"*, a property it
did not establish. The teardown now awaits the aborted task, bounded to 1 s so a
wedged task cannot stall a reconnect.

## ⚠️ Why it looked like a port-ownership problem, and was not

The original premise came from one measurement, read wrongly:

```
bind <self>:53                 -> AddressAlreadyInUse (10048)
bind <self>:53 + SO_REUSEADDR  -> AddressAlreadyInUse (10048)
```

`0.0.0.0:53` was held by a Windows service at the time, so that was blamed. It
was not the cause: **the probe was colliding with `roomlerd`'s own resolver.**

Re-measured properly during P2, on a host where Internet Connection Sharing
(`SharedAccess`) holds `0.0.0.0:53` and nothing of ours held the port:

```
plain bind          -> OK
bind + SO_REUSEADDR -> OK
```

So a wildcard squatter never blocked us, confirmed twice from opposite
directions.

🔑 The lesson worth keeping: *"another process owns the port"* and *"we own the
port twice"* produce the identical `AddressAlreadyInUse`, and only the owning
PID tells them apart. Check the owner before designing around the error.

## ⚠️ Probes that lied — and the criteria they corrupted

Three separate measurements in this arc produced confident, wrong conclusions.
They are recorded because two of them had been written into this document's own
acceptance criteria, where they could never have passed:

1. **`Resolve-DnsName … -Server <own overlay ip>` returns NO ANSWER even on a
   host where MagicDNS demonstrably works.** It was an acceptance criterion here
   and is now struck. Everything built on it — including a suspicion that our own
   WFP filters were dropping inbound UDP/53 — was unsupported.
2. **"Zero `magicdns` lines today" was log rotation**, not a dead code path: the
   log rolls at midnight and the resolver had simply not restarted since.
3. **`nslookup` does not honour the NRPT** (see #1363's history) and reports
   NXDOMAIN where resolution works.

🔑 The generalisation, paid for repeatedly here: **prove the probe on a
known-good host before trusting a negative.** One command against a healthy host
would have caught each of these before it reached a conclusion.

## Rejected, with the measurement that rejected it

| approach | why not |
|---|---|
| **SplitTun UDP interception** (the original P1–P3) | Solves third-party port ownership, which does not happen here — re-confirmed in P2 by binding successfully alongside the wildcard holder. Real engineering against a problem we do not have, in the packet path of every overlay host. |
| **An alternate port** (the first instinct, and the FR's original title) | NRPT nameservers carry no port: `Add-DnsClientNrptRule -NameServers 'ip:port'` **silently stores an empty list**. Measured. |
| ~~**Writing the Group-Policy NRPT store** (Tailscale's `writeAsGP`)~~ | ⚠️ **REJECTION WITHDRAWN 2026-09-06 — this is now P5.** It was rejected as "works, but not needed: the local rule works there too". The second half is **false on the host that motivated this FR**, measured on 0.4.73: the local rule is written correctly and the effective table holds **0 rules**, before *and* after a completed `gpupdate`. See P5. |
| **A DNS-manager fallback ladder** | Designed for a policy environment we then failed to reproduce. Local NRPT works on the host that motivated it. Revisit only with a host where it demonstrably does not. |

⚠️ An earlier root cause — *"an empty policy NRPT table suppresses local rules"* —
was recorded here as **refuted**, on the grounds that the broken host's local
rule became effective after a policy refresh. ⚠️ **That refutation is itself
withdrawn.** Re-measured on the same host on 0.4.73: the local rule is present
and correct, `gpupdate /target:computer` runs to completion, and the effective
table stays **empty**. The mechanism is real; what was wrong was the sentence it
was written in, and the rejection that leaned on it.

🔑 The generalisation worth keeping: **the unmanaged dev box does not model a
GPO-managed one.** Local NRPT rules take effect immediately on the former and
are inert on the latter, and this arc generalised the wrong way round three
separate times.

## Acceptance criteria

- [x] A second resolver cannot bind while the first holds the port, and can once
      it is aborted (unit, P1).
- [x] A resolver that loses the bind **retries and takes the port once it frees**
      (unit, P2, confirm-RED verified: with the backoff pushed past the test's
      window the assertion fails while the P1 assertions still pass).
- [x] On a real host, a resolver whose first bind fails **recovers unaided**, and
      the OS steer follows the late bind — proven by *provoking* the conflict,
      with a second org's resolver unheld as an in-run control.
- [x] After recovery, `Resolve-DnsName <peer>.<suffix>` answers with the peer's
      overlay address and the NRPT rule is in the effective table.
- [x] No regression on a host that was already healthy (the control org bound and
      steered normally throughout the provoked run).
- [x] **P4 — docs**: [`docs/magicdns.md`](../magicdns.md) written in house style
      (mermaid bring-up sequence + query flowchart, `file:line` anchors,
      callouts) and linked from `docs/README.md`'s map and table. It carries the
      diagnostics table naming the three instruments that lie here, so the next
      reader does not re-pay for them.
- [x] The corp laptop that opened this FR is **fully diagnosed**: a corporate
      DNS-enforcement layer refuses the host's own DNS packets to any
      non-approved resolver, its overlay address included, so MagicDNS *by OS
      steer* is unreachable there by the host's design.
- [x] **…and it resolves anyway.** P6's hosts rung closes it: on 0.4.76 that
      host answers `<peer>.<magic domain>` with the peer's overlay v4 + v6 and
      pings it by name, where the same host answered nothing on every previous
      build. Verified failing first (switch off ⇒ zero entries, NO ANSWER).
- [x] **Cleanup verified in both directions** — switch off + restart removes the
      block, restores the file's original 21 lines and leaves every foreign line
      intact; switching back on re-establishes resolution. The removal path is
      the one that matters, so it was tested rather than inferred.

### ⚠️ Two criteria struck, because they were wrong

- ~~*"The port … answers a direct query (`Resolve-DnsName … -Server <overlay ip>`)"*~~
  — that probe returns NO ANSWER on known-good hosts. It could never have passed
  and would have sent a reader hunting a non-existent fault.
- ~~*"Exactly **one** `magicdns: resolver up` per daemon lifetime"*~~ — with P1
  fixed, each WS session legitimately starts one. The meaningful signal is
  **zero** `bind failed` that stay failed, not a count of successful starts.

## Open

- **#1363** — `roomler status` said `active` over a resolver that had lost its
  own bind race. ⚠️ Verifying the NRPT effective table would **not** have caught
  this; the check has to be *does our resolver answer*. Still open, and P2 adds a
  state it must now express: *retrying* is neither `active` nor a permanent
  `DOWN`.
- Whether the same spawn-and-forget shape exists elsewhere in `run()`. The
  teardown aborts four tasks explicitly, which is exactly the pattern that hides
  a fifth — and P2 showed the abort itself was not awaited, so "listed in the
  teardown" is not the same as "stopped before the successor starts".

## Out of scope

Interception, the GP store, and the fallback ladder — all recorded above with
the measurement that ruled each one out, so a future reader does not re-derive
them. Overlay IPv6 / AAAA behaviour is #1342's.

## Field-verification log

| date | build | host | result |
|---|---|---|---|
| 2026-09-05 | 0.4.66 | corp laptop | Baseline, **bind-lost arm**: `resolver DOWN`, no resolution |
| 2026-09-05 | 0.4.66 | same host | **bind-won arm**: `active`, NRPT rule effective and correct, still no resolution — resolver bound but not answering |
| 2026-09-05 | 0.4.66 | same host | Root cause (P1): two `magicdns` starts 14 s apart in one lifetime, second `AddressAlreadyInUse`. GP-store experiment run and fully reverted (test key removed, task unregistered, policy refreshed) |
| 2026-09-05 | 0.4.71 | corp laptop | P1 shipped: `bind failed` 3 → 0, one `resolver up` per lifetime. ⚠️ Goal still unmet — resolver bound and answering nothing |
| 2026-09-06 | 0.4.71 | dev box | **P2 root cause**: both orgs' resolvers failed to bind at a restart and never retried — 5 h dead, port free for nearly all of it |
| 2026-09-06 | 0.4.71 | dev box | ICS holds `0.0.0.0:53`; a specific bind succeeds anyway, plain and with `SO_REUSEADDR` ⇒ the wildcard-squatter theory refuted a second time |
| 2026-09-06 | 0.4.73 | dev box | ⚠️ Passive read is **not** evidence: host healthy, retry counter **0** — both binds won first try, exactly as an unfixed build would look |
| 2026-09-06 | 0.4.73 | dev box | **P2 PASS, provoked**: port held across a restart ⇒ `bind failed; retrying`; released ⇒ `resolver up` 21 s later, `resolver bound late - steering the OS now`, NRPT installed, names resolve. Second org unheld throughout as the in-run control |
| 2026-09-06 | 0.4.73 | corp laptop | Resolver bound on the correct address, local NRPT rule written — **effective table holds 0 rules**, `gpupdate` completed and changed nothing, query NO ANSWER with a passing out-of-zone control ⇒ **P5**, and the GP-store rejection withdrawn |
| 2026-09-06 | 0.4.73 | corp laptop | A GP rule goes effective (0 → 1) and still does not resolve. **Raw UDP** finds why: a peer gets correct answers from that host's `:53` while the host itself gets **REFUSED (rcode 5, RA=0)** — which our resolver never emits ⇒ enforced corporate DNS, above anything we control |
| 2026-09-06 | 0.4.76 | corp laptop | **P6 PASS.** Failed first with the switch off (0 entries, NO ANSWER); with it on, names resolve to overlay v4 + v6 and ping by name replies. Log shows the ladder: steer installed → probe fails → 17 entries written. Block well-formed (1 BEGIN / 1 END, 34 lines, all FQDN) |
| 2026-09-06 | 0.4.76 | corp laptop | **Cleanup PASS.** Switch off + restart ⇒ block gone, file back to its original 21 lines, foreign lines intact, resolution back to baseline; switched on again and re-verified |
