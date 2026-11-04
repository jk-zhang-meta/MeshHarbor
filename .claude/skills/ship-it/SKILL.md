---
name: ship-it
description: How roomler releases and deploys — the hosted server image (Actions builds, GHCR serves, a dispatch promotes), the agent release lane (MSI/.deb/.pkg, code signing, GPG sidecars, the updater's trust chain), the break-glass build-host path, and the couplings that silently freeze the whole fleet's updates when they drift. Load BEFORE cutting an agent-v*/setup-v* tag, promoting or rolling back a server image, touching release-agent.yml / hosted-image.yml / promote.yml / the Dockerfile / the wxs installer, or changing a version number or signing step. FR-73 / FR-7.
---

# Shipping: the server image and the agent release

Reference docs: **[`docs/deployment.md`](../../../docs/deployment.md)** (server) and
**[`docs/installation.md`](../../../docs/installation.md)** +
**[`docs/code-signing.md`](../../../docs/code-signing.md)** (agent). This file is
the set of couplings that fail *silently*.

## 1 · Build ≠ deploy

The hosted image is built by GitHub Actions on **every merge to `master`** that
can change it (`hosted-image.yml`: `crates/**`, `ui/**`, `files/**`, `config/**`,
the two installer scripts, the Dockerfile, `Cargo.*`), smoke-booted with Mongo +
Redis, attested, and pushed as
`ghcr.io/gjovanov/roomler-ai:hosted-<YYYYMMDD>-<sha7>` plus the moving `hosted`
pointer.

**Nothing rolls until someone promotes.**

```bash
gh run list --workflow hosted-image.yml --limit 3        # find the image a merge produced
gh workflow run promote.yml -f tag=hosted-20260905-5ef0030   # empty tag = whatever `hosted` points at
# then FIELD-VERIFY from the fleet — see §5
```

⚠️ The lane **never writes `latest`** — that is the self-host `full` image (no
`saas`), owned by `publish-selfhost-image.yml`.
⚠️ `promote` runs in the **`release` environment**, whose secret
`DEPLOY_REPO_TOKEN` it uses after proving write access with a dry-run push. **An
environment secret is invisible to a job that does not declare the environment,
and the symptom is the job's "not set" branch, not an error.** Without it the job
prints the exact manual bump.
⚠️ It refuses anything that is not an existing `hosted-*` tag, and refuses while
the deploy repo's `newName` is not `ghcr.io/gjovanov/roomler-ai`.
⚠️ The e2e lane (`scripts/e2e-nightly.sh`, `e2e-run.sh`) reads the registry from
the deploy repo's `newName` — a bare tag is resolved against it; a full reference
containing `/` pins anything.

ArgoCD reconciles the deploy repo's `master` with **Automated + selfHeal +
prune** and a webhook: a push rolls out within ~5 s. The cluster pulls from GHCR
with **no pull secret** (the package is public; `regcred` is vestigial).

## 2 · The couplings that freeze the fleet

These do not error. They make every device quietly stop updating.

| Coupling | What drift does |
|---|---|
| `msi_product_version_for` (in `roomlerd`) **vs** the "Derive the MSI ProductVersion" step in `release-agent.yml` — the same `MAJOR.MINOR.RC` mapping, **twice** | Change one and **every agent refuses every update**: a silent fleet-wide freeze, not an error. Re-check with `cargo test -p meshharbord --lib -- --ignored real_published_msi` |
| The GPG sidecar job | Non-Windows `download_asset` **requires** `<asset-url>.asc` and refuses fail-closed. A release whose GPG job skipped freezes every Linux/macOS agent. `release-agent.yml` now hard-fails on a tag when `GPG_PRIVATE_KEY` is absent (graceful skip only on a branch dispatch), plus a post-signing assertion that every `.deb`/`.pkg`/`.msi` got a sidecar |
| The version scheme (rolling `0.4.<counter>`) | Six coupled MSI-mapping copies. Agents ≤ rc.483 **refuse** 0.4.x MSIs |
| Asset ORDER in a release | A frozen agent's picker takes the **first** `.deb` matching its arch, and `/api/agent/latest-release` forwards GitHub's order. Publishing the Linux companion `.deb` into the agent release froze every pre-0.4.16 Linux agent — they apt-installed the companion *as* their daemon update. Fixed server-side (`agent_release::order_assets_daemon_first`) **because a frozen agent cannot receive an agent-side fix** |

⚠️ **A tag can publish nothing.** Always check `gh release view <tag>` assets
before believing a release shipped; re-cut on a **fresh** number rather than
re-pushing a tag.
⚠️ `agent-v*` tags are a lineage **separate from master** — `git tag --contains
<master-sha>` misdates a fix. Test with `merge-base --is-ancestor` on the tag
lineage.

## 3 · The updater's trust chain

The updater runs what it downloads **as the daemon identity — SYSTEM on Windows,
root under systemd**. The manifest's SHA-256 is *not* a tamper anchor: the digest
arrives in the same manifest, from the same origin, as the `browser_download_url`.

| Platform | Anchor |
|---|---|
| Windows | `code_signature::verify_publisher` — `WinVerifyTrust` **plus** an assert that the signer contains `G ROX LTD`. ⚠️ **Both halves are load-bearing**: `WinVerifyTrust` alone proves only that *someone Windows trusts* signed it |
| Linux / macOS | `pgp_verify.rs` — the release signing subkey's ed25519 point is **pinned in the binary**; the `.asc` sidecar is **required** |
| Rollback | `artifact_version::verify_artifact_version` — the MSI's own `ProductVersion` (inside the signed envelope) must equal the tag the manifest claimed. Without it, a tampered manifest advertising a high tag while pointing at a genuinely-signed **older** build passed every check and downgraded the fleet |

⚠️ The version binding is deliberately `Unsupported` (not a refusal) for
`.deb`/`.pkg`: with no signature to anchor it, a version check there compares a
claim against a claim while reading like a control.
⚠️ Still open: the **manifest itself is unsigned** (version+url+hash not attested
as a unit), and the tunnel CLI's separate `self-update` does not share
`download_asset`, so it is not pinned — and it fails **open** when the manifest
carries no digest.

### Signing rules that break quietly

- Every azure-signing job **must** carry `environment: release` — the tenant
  rejects wildcard tag-subject federated credentials.
- MSI **payload** (`meshharbord.exe`, `meshharbor-shim.exe`) is signed **before**
  `cargo wix` harvests; third-party DLLs (wintun, VC-CRT) are staged **after**
  signing and must keep their original signers (CI asserts).
- **Nothing after payload signing may `cargo build`** — a relink strips
  signatures.
- VERSIONINFO comes from `build.rs` + `embed_resource::compile_for`. **Never**
  winres/winresource — its link-lib leaks a second `RT_VERSION` into the Tauri
  EXEs.
- Rehearse with `signing_mode=local` dispatches, **never** with throwaway
  `agent-v*` tags.
- macOS is all-or-nothing on six `APPLE_*` secrets.
- ⚠️ **There is no canary channel.** The updater (`pick_latest_release`) and
  `/api/agent/latest-release` skip drafts only; a PRE-release is accepted. So
  publishing ANY `agent-v*` release, even one marked pre-release, reaches the
  whole fleet. A canary is a `workflow_dispatch` with `publish_release=false`
  from a branch that changes the feature line. Its signed artifact is
  installed by hand, with auto-update off on that host.
  ⚠️ By hand on a **SystemContext** host (every corporate laptop in the fleet),
  an MSI built before #1727 needs `ENABLE_SYSTEM_CONTEXT=1` on the command line.
  Without it, the install switches SystemContext off and the device goes
  offline; CORPLAP-2 did on 2026-09-26. To rescue it, run
  `roomlerd enable-system-context`. From #1727 on, leaving the property out
  keeps the host's mode.
- 🔒 **`0.4.106` is RESERVED** for the FR-85 Windows canary (branch
  `fr85-canary-0.4.106`, never merged; the operator, 2026-09-26). **Never tag
  `agent-v0.4.106`: the next fleet release is `0.4.107`.** A fleet build and a
  canary that share a version cannot upgrade into each other: the MSI's
  `MajorUpgrade` refuses the same version, and the updater calls it
  "up to date".
- 🔒 **`0.4.109` is RESERVED** for the FR-85 **macOS** canary (branch
  `fr85-canary-0.4.109`, never merged; `recording` in the macOS build line
  only; reserved 2026-09-27, after 0.4.108). **Never tag `agent-v0.4.109`:
  the next fleet release is `0.4.110`.** A canary takes the NEXT number, never
  one past it: re-enabling `auto_update` on the canary host must carry it to
  the very next fleet release. A canary numbered above a fleet release cut
  later from a newer master strands the host (the updater only moves up), and
  the version order stops matching source age. The macOS canary PASSED on
  2026-09-27 and stays installed on the supervised MacBook. Its update helper
  was left intact, so `0.4.110` replaces it when it publishes.
- 📜 **The LGPL offer must describe what the tag ships.** release-agent's
  FR-24 gate refuses a tag while the `…corresponding-source.inputs.txt` on
  `vendored-ffmpeg-9.0.1` disagrees with the checkout's FFmpeg patches, vcpkg
  baseline, or vendor recipe (`vendor-ffmpeg-windows.yml`,
  `vendor-ffmpeg-macos.yml`, which carry the configure options; checked since
  FR-85 P4c). After any change to one of them, dispatch `lgpl-source-offer.yml`
  on master **before** tagging. `0.4.110` is the first tag that needs it: P4c
  changed the recipe and brought the recorder into `full`.

## 4 · Break-glass: the build-host path

For a GitHub outage, or a fix that must not wait for a runner. Build, push to the
build host's registry, then set **both** `newName: registry.roomler.ai/roomler-ai`
**and** `newTag` in the deploy repo (`promote` refuses until `newName` is switched
back to GHCR). Full recipe: [`docs/deployment.md`](../../../docs/deployment.md).

⚠️ **First `cd ui && bun docs/dates.ts --write`** in a clone with full history (FR-87).
The image has no `.git`, so the docs' `<lastmod>` and "Last updated" dates come from
that manifest. Skip it and the image ships with no dates: honest, but a regression.

⚠️ **Always `docker system prune -af && docker builder prune -f` after a
build-host deploy.** Every deploy bakes a fresh multi-stage image plus
intermediate layers and build cache; without pruning they pile up until the build
host's root FS fills (2026-07-12: `/` hit 100 % from ~13 GB of stale build images,
mid-deploy). `-a` drops images not backed by a *running* container, so the mongo +
registry containers are untouched; **no `--volumes`**, so mongo data is safe.
⚠️ `registry-retention.sh` (weekly, Sun 04:00) keeps at most 2 tags per repo. Run
it manually if the registry is fat — the blob store is the registry's own storage
and `docker system prune` never touches it.
⚠️ **Never touch `/var/lib/libvirt`** (the running k8s VM disks) or the active
container data volumes. The fattest safe reclaimables are the *other* projects'
Rust `target/` dirs on the build host.

## 5 · CI green ≠ done

Networking and remote-desktop changes are proven on the **real fleet** after every
roll — the workflow only proves the public `/health` kept answering:

```bash
# pods on the new image · online-agent count · an RC session ·
# an overlay pair · a tunnel forward
roomler exec <device> '<cmd>'      # ⚠️ argv is re-split: Windows targets need ONE quoted arg, ";" never "&&"
roomler peers
```

⚠️ An exec sweep is a **biased sample** — it only reaches devices that are
online. Query the server for the denominator.
⚠️ `roomler exec` on a host that restarts its own service answers "no answer
within 45 s" — the command ran.

## 6 · The wizard ships in lockstep (FR-84 S1)

`/api/setup/{windows,linux,macos}` — the landing page's download button and the
admin UI's install link — serve the **newest `setup-v*` release**
(`setup_release.rs::pick_release_for`). Nothing cut one between `setup-v0.4.48`
(2026-09-02) and `agent-v0.4.102`: 54 agent releases shipped while every new
install downloaded a three-week-old wizard, and `/api/setup/macos` answered 404
the whole time. A lane a human has to remember is a lane that drifts.

So **every `agent-v<V>` release also publishes `setup-v<V>`, at the same
commit**: `release-agent.yml`'s `dispatch-setup-release` job (after `release`,
so it can never block the agent) tags `setup-v<V>` at the built commit and
dispatches `release-setup.yml --ref setup-v<V>`. Two GitHub rules shape it: a
tag pushed with `GITHUB_TOKEN` triggers **no** workflow, and `workflow_dispatch`
is the documented exception — hence the explicit dispatch. The wizard lane
builds all three platforms (macOS is no longer skippable), publishes the
release on that tag, and opens/closes a "meshharbor-setup release failed" issue
like the agent lane's seed alert.

⚠️ **#2013 — never send `target_commitish` for a tag that already exists.**
GitHub refuses a release (create *or* update) whose `target_commitish` adds or
changes anything under `.github/workflows` relative to master, because that
needs a `workflows` permission `GITHUB_TOKEN` cannot hold. The 403 reads
"Resource not accessible by integration" although the job has
`contents: write`. `setup-v0.4.128` never published for this reason: master
changed one line of `ci.yml` 13 minutes after its commit. The lane now sends it
only when the release must create the tag. A run on a tag executes the workflow
**as it stood at that tag**, so a pre-fix tag cannot be re-published: release
the next version.

```bash
# Verify a lockstep roll — both must hold
git ls-remote origin 'refs/tags/setup-v<V>^{}' 'refs/tags/agent-v<V>^{}'   # the SAME commit (the release's targetCommitish now reads `master`)
gh release view setup-v<V> --json assets   # 3 platforms + sidecars
for p in windows linux macos; do curl -sI https://roomler.ai/api/setup/$p | grep -i content-disposition; done   # every filename carries <V>

# Re-run after a failure (the tag already exists at the agent commit; idempotent)
gh workflow run release-setup.yml --ref setup-v<V> -f version=<V> -f publish_release=true
```

⚠️ **Never re-cut a wizard under a number that already shipped.** The resolver
serves by number, so the bytes behind one download URL would change underneath
everyone who already fetched them — bump the version and release again. The
lockstep job refuses a `setup-v<V>` that exists at a *different* commit for the
same reason.
⚠️ The kill switch is the repo variable **`SETUP_LOCKSTEP=false`** (skips the
job; nothing else changes). With it set, a wizard release is a human pushing a
`setup-v*` tag again — and the drift above is the failure mode you are opting
back into.
⚠️ `/api/setup/*` is served from the same per-pod release cache as the agent
feed; the wizard lane's `refresh-release-cache` busts it, and the 15 min TTL is
the backstop.
