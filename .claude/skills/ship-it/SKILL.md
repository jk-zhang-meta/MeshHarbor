---
name: ship-it
description: Guide MeshHarbor's manual local release preparation, package signing, updater trust checks and deployment boundaries. Use before changing a release version, preparing agent/setup/tunnel artifacts, modifying signing or installer recipes, or planning an explicitly authorized image promotion or rollback. This project permanently uses no CI or automatic tag-triggered releases.
---

# Manual release preparation

Read [local builds](../../../docs/local-build.md),
[code signing](../../../docs/code-signing.md),
[installation](../../../docs/installation.md) and
[deployment](../../../docs/deployment.md). The
[historical source index](../../../docs/local-build.md#historical-workflow-sources)
points to retired Git sources, not an executable release pipeline.

## Authority and evidence

- Never create or dispatch a CI workflow. A merge or tag builds/publishes nothing.
- The owner chose unsigned Windows/Linux local artifacts and signed macOS
  artifacts. Follow that decision without adding Windows/GPG signing gates.
  This local preparation does not publish, deploy, install on the fleet or clean
  other resources; it does not change existing updater trust checks.
- Use the smallest relevant native checks and verify terminal results at the
  exact source revision. A successful build does not prove a deployment or the
  real-network acceptance bar. Field verification needs its own host authority.
- Keep artifacts/caches outside synchronized source; do not put credentials in
  argv, logs, repository files or review bundles. Existing credential provisioning
  scripts are separate external operations, not automatic build prerequisites.

## Release invariants

1. Build the platform's exact features and stage verified native dependencies;
   workspace/default-feature checks do not cover a feature-gated backend.
2. Match MSI ProductVersion to `artifact_version::msi_product_version_for`.
   Keep the existing rolling-version/RC mapping and VERSIONINFO; do not
   introduce a second resource compiler. A mismatched MSI silently freezes updates.
3. Current Windows outputs are unsigned. Preserve vendor DLL bytes/signatures
   and package the built payload with `cargo wix --no-build`. Historical signed
   distributions signed payloads before packaging and verified `G ROX LTD`;
   those are not current local build prerequisites. On Windows use pkg-config
   and clear `FFMPEG_DIR`, which would bypass transitive libvpl dependencies.
4. macOS requires complete Apple prerequisites, inside-out signing, hardened
   runtime, correct entitlements, notarization, stapling and Gatekeeper checks;
   missing inputs must block an official signed release. Re-extract and verify
   the packaged app. Local test certificates must not be published.
5. Current Linux outputs are unsigned; do not add a GPG step to this local
   build. Existing Linux/macOS updater `.asc` verification remains unchanged,
   so these local outputs are not claimed compatible with signed auto-update.
   A manifest SHA alone is not a trust anchor. Preserve version metadata and
   platform-specific verifier behavior.
6. Keep daemon assets ahead of companion packages in the release ordering;
   old agents can install the first matching `.deb`. Preserve
   `agent_release::order_assets_daemon_first` and existing consumer asset names.
7. Check LGPL source-offer inputs against the actual vendor build: upstream
   source, both patch sets, baseline, complete recipes and their hashes. The
   offline assembler does not establish binary provenance or publish an offer.
   Never release a changed vendor tree against an old offer manifest.
8. Agent/setup artifacts for version V must be deliberately prepared from the
   same commit. There is no automatic setup dispatch or release-cache refresh.
   Never change bytes behind an already-shipped version; use a fresh version.
9. A public `agent-v*` pre-release can update the whole fleet; it is not a canary.
   Rehearse only with unpublished artifacts on specifically authorized hosts.
   Historical reserved versions `0.4.106` and `0.4.109` must not be reused.
10. SystemContext installation state matters: preserve the MSI property behavior
    and avoid disabling an existing host's SystemContext during a test upgrade.

## Images and deployment

Prepare docs dates from a full-history checkout before an image build:
`cd ui && bun docs/dates.ts --write`. `Dockerfile` uses hosted `PROFILE=full
SAAS=1`; selfhost uses `SAAS=0`. Keep hosted and selfhost image identities separate.

An explicitly authorized deployment must pin the intended image digest/version,
record its source and verification, and separately review the deploy-repository
change and rollback. GitOps/ArgoCD may act immediately on a deploy-repo push.
Do not infer deployment authority from a request to build or remove CI.
Never automatically prune Docker images, caches, registry tags or other projects'
resources. Retired automation details remain in FR history and Git R3
`3c48d7e7e9d5c682d2e3056070be24b97669f2e5`.

## Verification boundaries

Check actual asset names, arch, version, applicable signatures, hashes and source
mapping and retained source-offer availability before claiming a release exists.
For an authorized fleet rollout, verify service health, device denominator and
relevant RC/overlay/tunnel behavior; an online-only exec sweep is a biased sample.
An exec timeout while a host restarts its service is not proof the command failed.
No signing, publication, deployment or fleet test is performed by this skill
merely being loaded.
