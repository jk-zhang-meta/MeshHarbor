# FR-37 — The e2e suite runs outside the cluster, so it cannot test media (and keeps breaking on the seam)

> **CLOSED 2026-08-29** — issue #928 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#928](https://github.com/gjovanov/roomler-ai/issues/928)
> **Renumbered from FR-36.** #929 (Wayland capture) landed that number on
> master first, and the shared ledger caught the clash **in the rebase —
> before anything of mine was published**, which is exactly what the
> one-table protocol exists to do. The unlanded claim takes the next free N;
> no repair rule was needed, because nothing had to be un-published.

**Status:** P1 **in progress** — three of the blockers are measured and two
are solved; the specs are still red on a fourth. Nothing shipped yet.

## Goal

Make the browser lane able to exercise a **call**: two participants, real
mediasoup RTP, screen share. Today every conference spec fails, the call
surface has no automated coverage at all, and the workarounds for running
outside the cluster are themselves a recurring source of breakage.

## Why it fails today — measured, not assumed

The suite runs a Playwright container on the build host and reaches the stack
through `kubectl port-forward`. That forwards **one TCP port**. Media does not
use it.

```
e2e roomler2 pod:  podIP 10.244.3.196   node k8s-worker-3 (10.10.30.11)
                   hostNetwork: <unset>          ← unlike prod, which sets it
mars -> 10.10.30.11 :  reachable, dev wg0 src 10.10.0.1
mars -> 10.244.3.196:  via 94.130.141.65 dev eth0   ← i.e. out the DEFAULT ROUTE.
                                                      No route to the pod network.
```

So the browser cannot send a single RTP packet to the SFU: the pod's address
is on the CNI network, which the build host has no route to. The failure is
**not** the mediasoup RTC range being blocked by a firewall — nothing was ever
going to arrive. ⚠️ I assumed DNAT was needed and it is not; the browser is
simply in the wrong network.

The e2e configmap also sets no `MESHHARBOR__MEDIASOUP__ANNOUNCED_IP` at all (only
`NUM_WORKERS: 1`), so whatever it announces, no one outside the cluster can
route to it.

### The seam bites in other ways too

- **2026-08-29**: every WebSocket handshake in the suite was refused with 403
  for ~a week, because cookie auth checks `Origin` against `frontend_url` and
  the port-forward origin (`127.0.0.1:18080`) is not the stack's own. Patched
  by pointing `frontend_url` at the forward — a workaround for the seam.
- `scripts/e2e-nightly.sh` carries ~60 lines of **self-healing port-forward
  supervisor** because a bare `kubectl port-forward` both dies and, worse,
  stays alive while silently forwarding nothing.

Every one of those disappears if the browser runs inside the cluster.

## Key design — move the browser, not the packets

Run the suite as a **Job in the `roomler-ai-e2e` namespace**:

- the browser reaches `http://roomler2` (the Service) directly — same origin as
  `frontend_url`, so the cookie/WS origin check passes with no override, and my
  2026-08-29 `frontend_url` patch is **reverted** as part of this;
- RTP goes pod-to-pod on the CNI network, which is what a real call does;
- Mailpit is an in-cluster Service, so email specs keep working;
- no port-forwards at all, so the supervisor and its failure modes go away.

Getting the specs in: an `initContainer` that clones the repo at the tag under
test into an `emptyDir`, then the Playwright container runs from it. Nothing is
baked into an image, so a spec change needs no image build.

⚠️ **Do NOT instead give the e2e pod `hostNetwork: true`.** It would make the
node IP reachable from mars and look like a fix, but it binds host ports on a
shared worker and drags in the announced-IP mapping prod needs — trading a test
seam for a production-shaped hazard on a node that also runs real workloads.

## Phases

| # | phase | kill switch |
|---|---|---|
| P1 | Job manifest + initContainer clone; prove one conference spec passes in-cluster | the existing host-side path stays until this is green |
| P2 | ✅ done differently: a **sidecar in the app pod**, not a Job — a Job cannot share the app's network namespace, and that namespace is the whole point | revert the script; the overlay change is two files |
| P3 | ✅ done — the conference entries are gone | — |
| ~~P4~~ | ~~the in-pod run is much slower~~ — **retracted, it is nearly 3× FASTER**: the full sweep takes **6.5 min** against 17.8 min on the host. The mid-run sample that suggested otherwise was measuring `npm i` | — |

## Acceptance criteria

- [x] A two-participant conference spec passes **in-cluster**, with real RTP —
      not skipped, not stubbed (`conference.spec.ts` 4/4, `conference-multi.spec.ts`
      5/5 on 2026-08-29)
- [x] The suite runs with **zero** `kubectl port-forward` invocations
- [x] `MESHHARBOR__APP__FRONTEND_URL` matches the browser's real origin
      (`http://127.0.0.1`, the sidecar's view) and the WS authenticates.
      ⚠️ NOT the service name, as this criterion originally assumed — the
      browser is in the pod, so the app is localhost to it
- [x] `e2e-expected-failures.txt` loses the conference entries; anything still
      failing is either fixed or re-justified in writing
- [ ] The nightly writes its usual `LATEST` line from the new path

## Open decisions

- **Where does the Job's result go?** The nightly currently parses stdout on
  the build host. Simplest is `kubectl logs --follow` on the Job; the parsing
  is unchanged.
- **rc-vp9-444** needs an agent, not a browser — it stays an expected failure
  and should say so explicitly rather than riding along with the conference
  entries.

## Out of scope

- Prod's media path (already field-proven; see FR-4).
- Running this in GitHub Actions — it needs the cluster.

## Field-verification log

**2026-08-29 — P1 probe run.** Everything below was measured against the live
e2e stack; the stack was left exactly as found.

1. **The runner works in-cluster.** The Playwright image schedules and runs in
   `roomler-ai-e2e`; from it, `http://roomler2/health` → 200,
   `http://mailpit:8025` → 200, and `registry.npmjs.org` → 200, so `npm i` in
   an initContainer is viable. No image build needed.

2. **🔑 A service URL is NOT a secure context, so there is no media API at
   all.** Running against `http://roomler2`:

   ```
   navigator.mediaDevices → undefined
   TypeError: Cannot read properties of undefined (reading 'getUserMedia')
   ```

   ⚠️ This is invisible from the host-side lane, which reaches the app on
   `http://127.0.0.1:18080` and gets the **localhost exemption**. Two specs
   (view loads, subject renders) passed here, so the failure looks like a
   product bug until you check for the API's existence.

   ⚠️ `--unsafely-treat-insecure-origin-as-secure` does **not** rescue it:
   Chrome requires `--user-data-dir` alongside it, and Playwright rejects that
   argument in `launch()` ("Pass userDataDir to launchPersistentContext").

3. **🔑 The fix is to put the browser in the app pod's own network
   namespace** — an ephemeral container with `--target=roomler2`. Then the app
   is `http://127.0.0.1`, which IS a secure context, and:

   ```
   getUserMedia({audio,video}) → ok, tracks live
   enumerateDevices → fake_device_0 + fake audio in/out
   getUserMedia({video:{deviceId:{exact:…}}}) → ok      (the shape the app uses)
   ```

   It also makes the SFU trivially reachable: with no `announced_ip` set, the
   server resolves **`127.0.0.1`** and hands out host candidates on
   `127.0.0.1:40742` — the same namespace the browser is in. No routes, no
   NAT, no announced-IP mapping.

   ⚠️ `frontend_url` must then be `http://127.0.0.1` (no port) for the WS
   origin check — the port is part of an Origin, so the host-side lane's
   `http://127.0.0.1:18080` does not match. The two modes cannot share one
   value, and `cors_origins` cannot be set from a configmap at all (no
   `list_separator` ⇒ boot crash), so P2 must flip it as it switches lanes.

4. **The fourth blocker was a PRODUCT BUG, and it is fixed (#940).** With
   media healthy, `conference.spec.ts` + `conference-multi.spec.ts` ran **2
   passed / 9 failed**, and the server log showed why the tile never appears:

   ```
   media:join … room_exists=true
   transports created …
   media:join transport_created ICE diagnostics … announced_ip=127.0.0.1
   participant media closed          ← 15 s later, no connect_transport, no produce
   ```

   The client stopped between `transport_created` and `produce`, with **no
   console error**, healthy `getUserMedia`, and working `enumerateDevices`.

   🔑 **Found by polling for the snackbar instead of reading the DOM once.**
   The error was reported — and had already faded before any screenshot:

   ```
   Failed to join call: Failed to construct 'RTCPeerConnection':
   '' is not a valid URL.
   ```

   `turn.url` is an `Option<String>`, and this stack has it as `Some("")`.
   `expand_turn_url("")` returned `[""]`, so the server advertised an ICE
   server with an empty URL and the browser refused the whole peer connection.
   **Nobody could join a call, in any browser.** Fixed in #940 (blank ⇒ no TURN
   server, at three layers), and re-run against the fixed image:

   | | before #940 | after |
   |---|---|---|
   | `conference.spec.ts` | 0/4 | **4/4** |
   | `conference-multi.spec.ts` | 0/5 | **5/5** |
   | `conference-chat.spec.ts` | 0/2 | 0/2 — the in-call CHAT panel, a separate issue |

   ⚠️ So `scripts/e2e-expected-failures.txt` has blamed unforwarded RTC ports
   for months, I blamed missing routes this morning, and the actual cause was a
   blank config value that made calls unjoinable for **any** deployment that
   left it empty. Three diagnoses, two of them confidently wrong, and only the
   one that came from making the failure reproducible was right.

**2026-08-30 — P2 + P3 done.** The browser is now the `pwrunner` sidecar in the
app pod (deploy repo `af89db7`), and `scripts/e2e-nightly.sh` execs into it.

| spec | 2026-08-29 morning | now |
|---|---|---|
| `conference.spec.ts` | 0/4 | **4/4** |
| `conference-multi.spec.ts` | 0/5 | **5/5** |
| `conference-chat.spec.ts` | 0/2 | **2/2** |
| `conference-list.spec.ts` | — | green |

**19/19.** `conference-chat` needed its own locator fix: `getByText('Chat')`
matched FOUR elements, because the fixture's own org and room are named
"Chat Org" and "Chat Meeting" — the same over-broad-locator class as the
morning's batch.

⚠️ **P4 was wrong and is retracted.** Mid-run I read 44/170 in ~20 min and
recorded a wall-clock regression. The finished sweep says the opposite:

```
20260829-2259 OK (2failed 3skipped 165passed(6.5m)) tag=v20260830-078ebef47b2a
```

**6.5 minutes against 17.8**, and 165 passed against 154. The sample I
extrapolated from was mostly `npm i` inside a fresh sidecar, which happens once
and before any test runs. 🔑 A rate read from the first minutes of a run that
begins with a fixed setup cost is not a rate.

**Final state of the lane**: the only failures left are the two `rc-vp9-444`
specs, which need an agent built with that feature lane and are legitimately
baselined. Even the Google-OAuth redirect case — baselined since July because
containerised Chromium intercepted `accounts.google.com` — now passes.

⚠️ The design note above said "run it as a Job". A Job cannot share the app's
**network namespace**, and that namespace is the entire mechanism — so it is a
sidecar instead. Recorded because the spec argued for the wrong container
shape and only the probe showed why.

**Stack restored**: probe pod deleted, `frontend_url` back to
`http://127.0.0.1:18080` so the existing nightly keeps working tonight.
