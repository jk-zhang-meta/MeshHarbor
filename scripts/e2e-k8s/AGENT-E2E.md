# agent-e2e harness — bring-up runbook

Phase 1 of the agent + tunnel test-pipeline expansion. Adds a Linux
agent Pod to the existing `meshharbor-e2e` overlay so Phase 2's
browser-driven remote-control specs can pick an enrolled agent
without operator setup.

## What ships in this chunk (1B)

- **`Dockerfile.agent-e2e`** — multi-stage build of `meshharbord`
  with `--features synthetic-frame-source,openh264-encoder,clipboard`.
  Runtime is debian:trixie-slim + curl + ca-certificates + libssl3 +
  libgcc-s1 (~80 MiB final image).
- **`scripts/e2e-k8s/overlay-template/`**:
  - `job-agent-e2e-seed.yaml` — one-shot Job creating the e2e admin
    user + tenant. `ttlSecondsAfterFinished: 0` so re-apply replaces.
  - `secret-agent-e2e-bootstrap.yaml` — admin creds + tenant_id
    consumed by the StatefulSet. **Ships with a placeholder
    `tenant_id: 000…0` that MUST be rebaked after the first seed.**
  - `service-agent-e2e.yaml` — headless Service for predictable Pod
    DNS (`agent-e2e-0.agent-e2e.meshharbor-e2e.svc.cluster.local`).
  - `statefulset-agent-e2e.yaml` — 3-replica StatefulSet of the
    synthetic-frame agents, one per recording state (FR-114):
    `agent-e2e-0` records but is not opted in, `agent-e2e-1` is opted
    in to remote recording, `agent-e2e-2` has no recorder.
  - `kustomization.yaml` — extended to include the 4 new files plus
    the new image rewrite (`jk-zhang-meta/meshharbord-e2e` →
    `<internal-registry>/meshharbord-e2e:latest`).

## Bring-up steps (FR-114: run on mars, the build host)

### 1. Build + push the agent-e2e image, under a DATED tag

```bash
cd <a clean meshharbor checkout at master>
TAG="agent-e2e-$(date -u +%Y%m%d)-$(git rev-parse --short=7 HEAD)"
docker build -f Dockerfile.agent-e2e -t "registry.meshharbor.itachi.fans/meshharbord-e2e:$TAG" .
docker push "registry.meshharbor.itachi.fans/meshharbord-e2e:$TAG"   # mars is logged in to it
```

Never `latest`: the overlay pins the tag, so a night's agent is a known
build. Image size sanity-check: ~150 MiB with `recording` (FR-114 measured
147 MiB on 2026-10-19; it was ~80–100 MiB before FR-85). If it's >200 MiB something
pulled in scrap-capture transitively — re-check the
`--no-default-features` + feature list in `Dockerfile.agent-e2e`.

### 2. Add the harness to the deploy repo's overlay, then apply

⚠️ **The deploy repo's `k8s/overlays/e2e` is the live truth and has moved on
from `overlay-template/`** (the meshharbor2 Deployment's `pwrunner` sidecar, the
config, the secrets). `install-overlay.sh` therefore copies only files the
deploy copy lacks and REPORTS the ones that differ. It never overwrites, and
it pins each image's tag by name. Run it against your OWN deploy checkout,
never a shared one with someone's uncommitted work:

```bash
AGENT_E2E_TAG="$TAG" DEPLOY_REPO=<your deploy worktree> \
  bash scripts/e2e-k8s/install-overlay.sh
# It WARNS for each agent-e2e resource the kept kustomization.yaml does not
# list: add the four files under `resources:` and the `jk-zhang-meta/meshharbord-e2e`
# entry under `images:` by hand, commit, open a deploy-repo PR.
kubectl diff -k <your deploy worktree>/k8s/overlays/e2e/   # read it FIRST
kubectl apply -k <your deploy worktree>/k8s/overlays/e2e/
```

The diff should name only the agent-e2e objects. Anything else (meshharbor2's
config, its secrets, the `pwrunner` sidecar) is drift between the deploy copy
and the cluster: stop and find out who changed which side before applying. A
full apply resets the e2e meshharbor2 to the overlay's image pin; the nightly
sets it to prod's image again on its next run.

To apply the harness ALONE (what FR-114 did on 2026-10-19, when the diff also
named minio and meshharbor2), list just the four files in a throwaway
kustomization next to copies of them, with the overlay's `namespace`,
`commonLabels` and `jk-zhang-meta/meshharbord-e2e` image entry, so the labels and
selectors match a later full apply:

```bash
mkdir -p ~/agent-e2e-only && cd ~/agent-e2e-only
cp <deploy>/k8s/overlays/e2e/{secret-agent-e2e-bootstrap,job-agent-e2e-seed,service-agent-e2e,statefulset-agent-e2e}.yaml .
# kustomization.yaml: namespace meshharbor-e2e; those four under resources:;
# the images: entry; commonLabels env: e2e + app.kubernetes.io/instance: meshharbor-e2e
kubectl diff -k .     # only the agent objects
kubectl -n meshharbor-e2e delete statefulset agent-e2e --ignore-not-found   # a fresh apply
kubectl apply -k .
```

### 3. Nothing to rebake

The seed Job registers the admin and the `agent-e2e` tenant (idempotent; the
e2e server auto-verifies). The agents, the seed and the nightly each find the
tenant **by its slug** through `GET /api/tenant`, so a wiped e2e DB needs no
hand edit: a fresh tenant gets a fresh id and everyone still finds it.

```bash
kubectl -n meshharbor-e2e logs job/agent-e2e-seed | tail -3
# → [seed] OK — admin + tenant ready; tenant_id=<24-hex-chars>
```

### 4. Verify the agents are online

```bash
kubectl -n meshharbor-e2e wait --for=condition=Ready --timeout=300s \
  pod -l app=agent-e2e
kubectl -n meshharbor-e2e logs agent-e2e-0 | grep -E '\[bootstrap\] (minting|config written)'
```

The nightly (`scripts/e2e-nightly.sh`, §3b) then finds the tenant the same
way and passes `E2E_AGENT_E2E_TENANT_ID` to its runs. Without the
StatefulSet it says so in its log, and the six specs skip as before.

## What does NOT ship in this chunk

- **Chunk 1C — Rust integration test driver** (`crates/tests/agent_e2e/`)
  that drives `rc:session.request` from a controller-role WS client
  and asserts ICE-connected + ≥1 SCTP exchange. Comes next iteration.
- **`scripts/e2e-k8s.sh` extension** that orchestrates the agent
  bring-up automatically (so an operator can run a single command to
  spin up API + agents + Playwright). Comes with Chunk 1C.
- **Phase 2** (browser-driven remote smoke), **Phase 3** (file-DC),
  **Phase 5** (tunnel) — all depend on Chunk 1C being done.

## Known gotchas

- **Enrollment needs TLS or LOOPBACK** (FR-114, measured 2026-10-19). An
  enrollment token travels over TLS: `meshharbord enroll` promotes a remote
  `http://` to `https://` (`normalize_server_url`,
  `crates/agent-core/src/enrollment.rs`; FR-101 P1b, no plaintext escape), and
  `https://meshharbor2` times out on a server that serves plain HTTP. So each agent
  pod carries a `server-proxy` sidecar (socat, `127.0.0.1:18080 → meshharbor2:80`),
  and `MESHHARBOR_E2E_SERVER` points at it. Loopback is exempt, so signalling and
  the WebSocket ride the proxy; media is WebRTC, pod to pod.
- **`meshharbord enroll` writes `record_remote_enabled = false` at the config's
  root.** The opt-in therefore REPLACES that line (`Dockerfile.agent-e2e`'s
  bootstrap). A second copy is a duplicate TOML key, and the daemon refuses
  the whole config (measured: a crash loop).
- **A crash-looping agent pod stalls a rolling update**: an OrderedReady
  StatefulSet will not roll past a pod that is not Ready, and it recreates a
  deleted pod at the OLD revision. Recover with a fresh apply: delete the
  StatefulSet (the kill switch), then apply.
- **A wiped e2e DB** (`mongodb-0` is an emptyDir; a recreated pod loses it)
  takes the admin and the tenant with it. Each agent's row is gone, so each
  agent exits, and its bootstrap then fails at the login until the seed has
  run again. Re-apply the harness: the seed Job (TTL 0) runs again, and each
  agent recovers on its next restart. Until then the nightly logs "its tenant
  did not resolve", and the seven tests skip.
- **The agents' config is `emptyDir`**: each pod restart enrolls a fresh device
  (a new row; the old one goes offline) with a fresh FR-100 device key. The
  specs pick an online agent, and a fresh Playwright context is always "first
  use" for a pinned key.

- **Pod DNS name vs `machine_name`**: the agent's `rc:agent.hello`
  payload includes `machine_name` = `$HOSTNAME` (the Pod's hostname,
  e.g. `agent-e2e-0`). Tests resolve a Pod's current `agent_id` via
  `GET /api/tenant/<tid>/agent?name=agent-e2e-0` because `agent_id`
  is regenerated on every `enroll` call (each Pod restart mints a
  new id; deterministic `machine_id` derivation would carry across
  restarts but isn't wired here — Pods are ephemeral).
- **Resource limits**: 500m CPU per agent Pod is enough for synthetic
  frames at 15 fps + openh264 encode. If you bump fps in the
  synthetic backend, raise the CPU limit accordingly.
- **No input feature**: `--features enigo-input` isn't compiled in,
  so any test that drives mouse/keyboard against the agent will get
  silently dropped. Phase 2 covers input via an alternative image
  (Xvfb sidecar) or a Windows agent.
