# Managed GeoIP refresh (local candidate, not installed)

This directory supplies one daily native systemd timer and an app-only refresh
operation. It reuses the reviewed `scripts/fetch-geoip.sh` without modifying it.
The fetcher's successful exit can mean no database; the wrapper separately
requires a real candidate, matching provenance and the production image's
`/usr/local/bin/meshharbor-geoip-check` JSON/exit status. The checker uses the
canonical 120-day policy. A previous accepted release's recorded epoch prevents
fallback to older monthly data. No image build, Compose change or deployment is
performed by these files.

## Observable contract and deployment prerequisites

Failure before activation must preserve the current symlink and running app.
An unchanged validated digest must not restart. A changed accepted digest must
activate one complete release atomically, restart the captured app container ID
and observe a changed start identity, Docker health and bounded HTTP readiness.
Failed activation must restore the prior symlink and verify a second scoped
restart; the operation still exits nonzero. An uncooperative concurrent target
change prevents touching the unexpected container and emits a critical recovery
failure rather than claiming rollback.

Installation is a separately reviewed deployment operation. Before enabling:

1. Preserve a tested app/image/config rollback and check there are no existing
   unowned units or destination files. Install `refresh.sh` as root-owned mode
   0755 `/usr/local/libexec/meshharbor-geoip-refresh`, and an exact reviewed copy
   of `scripts/fetch-geoip.sh` as `/usr/local/libexec/meshharbor-fetch-geoip`.
   The app image must include the actual Rust metadata validator.
2. Install the example's five-key config as root:root mode 0600 at
   `/etc/meshharbor/geoip-refresh.conf`. It is strictly parsed, never sourced;
   unknown keys, duplicate keys and shell expressions fail. The exact existing
   container name and loopback health URL are allowlisted. Do not put secrets
   in this file. The service does not need an EnvironmentFile.
3. Initialize root-owned `/opt/meshharbor/geoip-refresh/data` and
   `releases/<actual-sha256>/` with one accepted MMDB, matching provenance and
   `build_epoch` containing only the validator's positive decimal epoch.
   Verify bytes/metadata using the same validator. The epoch manifest is
   authoritative only because this bootstrap is reviewed and root-controlled;
   it lets a later refresh replace an expired previously accepted database.
   Bundle files should be 0444, release directories 0555. `current` must be a
   relative symlink `releases/<sha256>`. The updater does not bootstrap silently.
4. Through the app's reviewed Compose replacement, read-only bind **the stable
   data parent directory**, not a single MMDB or resolved release, to
   `/usr/share/roomler/geoip-managed`, and set
   `ROOMLER__STATS__GEOIP_MMDB=/usr/share/roomler/geoip-managed/current/dbip-country-lite.mmdb`.
   The initial mount/env change has its own app replacement/rollback gates.
5. Precreate `/opt/meshharbor/.app-update.lock` root-owned mode 0600. Both manual
   app deployment and this refresh must acquire this exact lock. The updater
   checks container ID/image/start time/mount/env before downloading, under the
   lock and immediately before activation. It never uses Compose-down or prune.
6. Install the supplied unit/timer under `/etc/systemd/system` only after exact
   artifact review. Verify one scheduled invocation and real loaded-reader
   metadata/digest, authenticated management, inventory and representative
   regional business paths before claiming production automatic updating.

The validator container has no network, read-only root/candidate mount, no
capabilities, no new privileges and bounded CPU/memory/PIDs; it runs as nobody.
Downloads use the fetcher's TLS, timeout and size bounds. The oneshot is limited
to 12 minutes, with three minutes for recovery on stop. Readiness polling is at
most 30 attempts, two-second sleeps and two-second HTTP calls. Every exit removes
only this invocation's exact unpromoted candidate directory. Promoted immutable
releases (including an activation failure) and old bundles are kept; no automatic
accumulated-release cleanup is included.

`journalctl -u meshharbor-geoip-refresh.service` and the existing startup/daily
GeoIP WARNs are local logs, **not externally delivered notifications**. Docker
health and HTTP readiness do not alone prove the actual app reader loaded the
new epoch; that real reader/business oracle remains a deployment gate.

## Local checks

Run `python3 scripts/geoip-refresh/test_refresh.py` as root in a disposable local
runtime. It uses the real fetch script with stub curl and Docker and small
generated compressed fixtures. It never contacts a real daemon or network.
Checks include success, unchanged no-op, missing file despite fetch exit zero,
bad/empty metadata JSON, epoch downgrade, target drift, mount/config refusal,
failed readiness rollback and restart failure recovery. Also run `bash -n` on
the wrapper and `systemd-analyze verify` on the units where available. This
fixture suite does not substitute for actual MMDB checker tests or deployment.
