# FR-57: An arm64 self-host image

> **CLOSED 2026-09-01** — issue #1161 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#1161](https://github.com/jk-zhang-meta/MeshHarbor/issues/1161) ·
Status: **P1 proven; P2/P3 in this PR** (2026-09-01) · Follows
[FR-42](FR-42-selfhost-verified-on-a-clean-box.md) (#967), which shipped the
amd64 image and put arm64 explicitly out of scope.

## Goal

`docker compose … pull` should work on a Raspberry Pi, an Apple Silicon Mac and
an ARM VPS — the three machines the self-hosting audience most often has spare.
Today those hosts fall through to a source build, which is the 20-minute path
the published image exists to remove.

## Why now, and not in FR-42

FR-42 ruled arm64 out for a reason that was correct at the time: cross-building
mediasoup and the Rust tree under QEMU takes hours, and **an arm64 image nobody
has run is a worse promise than no arm64 image**. That reason is about QEMU, not
about arm64 — GitHub's `ubuntu-24.04-arm` runners build natively, at roughly
amd64 speed, and can run the same smoke test on the architecture they built for.

The pull request that makes this urgent is external: it is the first thing
r/selfhosted asks, because that room runs Pis and Apple Silicon.

## Key design

**One job per architecture, each on its own native runner, joined by a
manifest.**

```
build (matrix: amd64 on ubuntu-latest, arm64 on ubuntu-24.04-arm)
  → build, smoke-test ON THAT ARCH, push BY DIGEST
merge
  → docker buildx imagetools create  → one multi-arch tag
```

⚠️ **Each arch smoke-tests on its own runner, natively.** An arm64 image checked
under QEMU emulation proves the bytes exist, not that they run — and "it builds"
was never the bar here: FR-42's smoke test exists because an image that starts
and serves nothing is worse than no image, since whoever pulls it did not read
the source.

⚠️ **Push by digest, then assemble.** Two jobs cannot both push the same tag —
the second silently wins and the manifest names one architecture. Digest push +
`imagetools create` is the shape that makes the tag a *list* rather than a race.

⚠️ **The amd64 path must not regress.** It is published, documented and measured
at 88 s. If arm64 fails, amd64 still publishes: the merge step tolerates a
missing arch and says which one is missing, rather than failing the whole run
and leaving the tag unmoved.

### What is genuinely unknown

The Dockerfile is arch-neutral and the runtime image ships only
`meshharbor-api`, `derp-relay` and the built UI — **no agent media stack**
(`openh264`, `scrap`, `enigo` are agent-only). So the risk is concentrated in
three dependencies that carry architecture-specific build machinery:

- **`mediasoup-sys`** — C++ built through meson/ninja, with a vendored openssl,
  libsrtp, usrsctp and abseil. The most likely place to break.
- **the vendored `webrtc` tree** and its ICE/SRTP crates.
- **`ring`** — assembly per target.

None of these is known to fail on aarch64; none has been tried here. **The first
build is the experiment**, and this FR is written so that a failure is a
recorded result rather than a silent gap.

## Phases

| # | Phase | Kill switch | Status |
|---|-------|-------------|--------|
| P1 | Matrix the publish workflow by arch; smoke-test natively; join by manifest | drop the arm64 matrix entry — amd64 publishes exactly as today | **shipped, dry-run proven** |
| P2 | Publish a real multi-arch tag and pull it on an arm64 host | do not move `latest` | planned |
| P3 | Docs stop saying amd64-only | n/a | planned |

## Acceptance criteria

- [ ] `docker manifest inspect ghcr.io/jk-zhang-meta/meshharbor:<tag>` lists **both**
      `linux/amd64` and `linux/arm64`
- [ ] the arm64 image is smoke-tested **on an arm64 runner** — `/health` 200 and
      the SPA served, not merely built
- [ ] an actual arm64 host pulls and runs it (`fedora-arm` is on the fleet)
- [ ] the amd64 timings do not regress from FR-42's measured 88 s
- [ ] `README.md` and `docs/self-hosting.md` no longer say amd64-only
- [ ] a failing arm64 build does not block the amd64 publish, and says so

## Out of scope

- **armv7 / 32-bit.** The Rust tree and mediasoup on 32-bit ARM is a different
  problem, and the audience asking is on 64-bit.
- **The agent binaries.** `release-agent.yml` already builds its own targets;
  this FR is only the server image.
- **Windows containers.**

## Open decisions

- Whether to keep publishing a **per-arch tag** (`:v0.4.43-arm64`) alongside the
  manifest. It helps debugging a specific arch and costs nothing; it also
  invites someone to pin one by accident. Leaning: push by digest only, and let
  the manifest be the single name anyone uses.

## Field-verification log
### 2026-09-01 — the experiment ran, and arm64 was never the hard part

Dispatched as a **dry run from the branch**, so an unproven workflow never
reached master. Both architectures built and both smoke-tested on their own
native runner:

| arch | build + smoke | health | SPA |
|---|---|---|---|
| amd64 | 20m23s | healthy after 20s | `GET / -> 200` |
| **arm64** | **15m33s** | healthy after 20s | `GET / -> 200` |

🔑 **arm64 built FASTER than amd64** on GitHub's `ubuntu-24.04-arm` runners.
Every reason to defer this was about QEMU, and none of them survived contact
with a native runner: `mediasoup-sys`, the vendored webrtc tree and `ring` —
the three dependencies this spec named as the risk — all built on aarch64
with no change at all. The risk was zero, and the only way to find that out
was to run it.

⚠️ The `Manifest` job correctly **skipped** on the dry run. It is gated on
`!inputs.dry_run`, so a verification pass cannot move a published tag.

⚠️ The tag-vs-binary drift fired again, and is now a routine observation
rather than a surprise: dispatched `v0.4.43`, built a binary reporting
**0.4.45**, because master moved twice during the run.

