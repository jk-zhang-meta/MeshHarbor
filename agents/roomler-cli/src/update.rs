// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `roomler self-update` — check the server's tunnel latest-release, download
//! the newer artifact through the configured center installer proxy (corp-AV
//! friendly, same origin as the manifest), verify it, and replace the running
//! executable.
//!
//! Mirrors `roomlerd self-update`, minus the MSI / Windows-service / UAC
//! machinery: the tunnel ships as a plain binary in an archive.
//!
//! ## What is checked (FR-97 P6b)
//!
//! The artifact's detached `.asc` must verify against the release key pinned
//! in this binary ([`pgp_verify`]), on every OS. The manifest's SHA-256 is
//! checked too, but it comes from the same server as the download, so it
//! proves transport, not origin. Before P6b it was the only check, and a
//! manifest without a digest skipped it. The `.asc` is fetched from the
//! asset's own release URL, restricted to the configured center prefix. The
//! pinned key must still have made a signature that verifies.
//!
//! A signature proves who built the bytes, not which release they are, so a
//! server could offer an older signed artifact under a newer version. Where
//! the artifact names its own version, from inside the signed bytes, the
//! update refuses one that is not the version it was offered as: the
//! tarball's one top-level dir, and the `.deb`'s control `Version`. The
//! Windows zip names no version inside, so there the offer stands once the
//! signature does.
//!
//! ## What is installed, by OS
//!
//! | Host | Artifact | Install |
//! |---|---|---|
//! | Windows | the `.zip` | its `roomler.exe` replaces the running exe |
//! | macOS, and Linux where no package owns this binary | the `.tar.gz` | its `roomler` is written beside the running binary and renamed over it, so the swap is atomic |
//! | Linux where dpkg owns this binary (`install.sh`'s Debian path) | the `.deb` | `dpkg -i`, so dpkg's database keeps naming the version on disk |
//!
//! A binary in a root-owned directory needs root to replace, and `dpkg -i`
//! always does: the command says to re-run under `sudo`.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tunnel_core::pgp_verify;

use crate::config::TunnelConfig;

/// This build's version (the workspace `version`, e.g. `0.4.149`).
const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// This build's platform, in the installer proxy's terms (the api's
/// `normalise_platform`). A catch-all keeps the CLI COMPILING on a target the
/// server has no artifact for (e.g. a source build on another arch) instead
/// of failing to build at all; there `self-update` says so.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const PLATFORM: &str = "windows-x86_64";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const PLATFORM: &str = "linux-x86_64";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const PLATFORM: &str = "linux-aarch64";
#[cfg(target_os = "macos")]
const PLATFORM: &str = "macos";
#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "macos",
)))]
const PLATFORM: &str = "unknown";

#[derive(serde::Deserialize)]
struct ReleaseAsset {
    name: String,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    browser_download_url: Option<String>,
}

#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

/// The form of the release this host installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The Windows `.zip`.
    Zip,
    /// A `.tar.gz`: macOS, and Linux where no package owns this binary.
    Tarball,
    /// The Linux `.deb`, where dpkg owns this binary.
    Deb,
}

/// Which release artifact a platform and kind install: the proxy's token, and
/// the target triple and extension that name the asset in the release. The
/// pair matches the server's own picker (`pick_installer_asset`), so the
/// manifest entry this reads the digest and the `.asc` URL from is the file
/// the proxy serves. `None` where the release carries no such artifact.
fn artifact_for(platform: &str, kind: Kind) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match (platform, kind) {
        ("windows-x86_64", Kind::Zip) => ("windows-x86_64", "x86_64-pc-windows-msvc", ".zip"),
        ("linux-x86_64", Kind::Tarball) => ("linux-x86_64", "x86_64-unknown-linux-gnu", ".tar.gz"),
        ("linux-x86_64", Kind::Deb) => ("linux-deb", "x86_64-unknown-linux-gnu", ".deb"),
        ("linux-aarch64", Kind::Tarball) => {
            ("linux-aarch64", "aarch64-unknown-linux-gnu", ".tar.gz")
        }
        ("linux-aarch64", Kind::Deb) => ("linux-deb-aarch64", "aarch64-unknown-linux-gnu", ".deb"),
        ("macos", Kind::Tarball) => ("macos", "universal-apple-darwin", ".tar.gz"),
        _ => return None,
    })
}

/// The manifest's asset for a triple and extension, by the server picker's
/// rule: the name contains the triple and ends in the extension, so the
/// `.sha256` and `.asc` sidecars never match.
fn manifest_asset<'a>(
    assets: &'a [ReleaseAsset],
    triple: &str,
    ext: &str,
) -> Option<&'a ReleaseAsset> {
    assets.iter().find(|a| {
        let name = a.name.to_ascii_lowercase();
        name.contains(triple) && name.ends_with(ext)
    })
}

/// Same URL boundary as the daemon updater: configured HTTPS center + path prefix.
fn checked_update_url(raw: &str) -> Result<reqwest::Url> {
    let path = raw.split('?').next().unwrap_or(raw);
    if path.contains('\\') || raw.chars().any(|c| c.is_control()) {
        bail!("update URL contains an ambiguous path");
    }
    let lower = path.to_ascii_lowercase();
    for escape in ["%2e", "%2f", "%5c", "%25", "%00", "%0a", "%0d"] {
        if lower.contains(escape) {
            bail!("update URL contains an encoded path separator/traversal");
        }
    }
    let raw_path = path.split_once("://").and_then(|(_, s)| s.split_once('/'));
    if raw_path.is_some_and(|(_, p)| p.split('/').any(|s| s == "." || s == "..")) {
        bail!("update URL contains a dot segment");
    }
    let url = reqwest::Url::parse(raw)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.host_str().is_some_and(|h| h.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("CLI updates require HTTPS without userinfo or fragment");
    }
    Ok(url)
}

fn update_base(raw: &str) -> Result<reqwest::Url> {
    let mut center = checked_update_url(raw)?;
    if center.query().is_some() {
        bail!("update center must not contain a query");
    }
    center.set_path(&format!("{}/", center.path().trim_end_matches('/')));
    Ok(center)
}

fn signature_url(center: &reqwest::Url, raw: &str) -> Result<reqwest::Url> {
    let mut asset = checked_update_url(raw)?;
    if asset.origin() != center.origin() || !asset.path().starts_with(center.path()) {
        bail!("signature asset URL is outside the configured center prefix");
    }
    asset.set_path(&format!("{}.asc", asset.path()));
    Ok(asset)
}

/// Entry point for the `self-update` subcommand.
pub async fn self_update(cfg: &TunnelConfig, check_only: bool) -> Result<()> {
    let boundary = update_base(&cfg.server_url)?;
    let base = boundary.as_str().trim_end_matches('/');
    let http = reqwest::Client::builder()
        .user_agent(concat!("roomler-cli/", env!("CARGO_PKG_VERSION")))
        // Fail closed on redirects, including signature redirects to upstream.
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            attempt.error("CLI updates require direct configured-center responses")
        }))
        .build()
        .context("build http client")?;

    // 1) Latest release (public endpoint — no auth).
    let releases: Vec<Release> = http
        .get(format!("{base}/api/tunnel/latest-release"))
        .send()
        .await
        .context("GET /api/tunnel/latest-release")?
        .error_for_status()
        .context("latest-release HTTP status")?
        .json()
        .await
        .context("parse latest-release")?;
    let latest = releases
        .first()
        .context("server returned no tunnel releases")?;
    let latest_ver = latest
        .tag_name
        .trim_start_matches("tunnel-v")
        .trim_start_matches('v');
    println!("roomler: current {CURRENT}, latest {latest_ver}");

    if !is_newer(latest_ver, CURRENT) {
        println!("Already up to date.");
        return Ok(());
    }
    if check_only {
        println!(
            "Update available: {CURRENT} -> {latest_ver} (run `self-update` without --check to install)."
        );
        return Ok(());
    }

    // 2) What this host installs, and that release's asset for it.
    let exe = this_binary()?;
    let kind = kind_here(&exe)?;
    if kind == Kind::Deb {
        // Before the download: there is no point fetching what cannot be installed.
        deb_needs_root()?;
    }
    let Some((token, triple, ext)) = artifact_for(PLATFORM, kind) else {
        bail!(
            "no release artifact is built for this platform ({PLATFORM}); install {latest_ver} by hand from {base}/api/tunnel/installer/{PLATFORM}?version={latest_ver}"
        );
    };
    let asset = manifest_asset(&latest.assets, triple, ext)
        .with_context(|| format!("release {} has no {triple}{ext} artifact", latest.tag_name))?;

    // 3) Download through the configured center (same origin as the manifest;
    //    corporate AV trusts it over a raw github.com pull), pinned to the
    //    version the manifest offered, so a release published in between
    //    cannot swap the bytes under the check.
    println!("Downloading {} ...", asset.name);
    let bytes = http
        .get(format!(
            "{base}/api/tunnel/installer/{token}?version={latest_ver}"
        ))
        .send()
        .await
        .context("download the release artifact")?
        .error_for_status()
        .context("artifact HTTP status")?
        .bytes()
        .await
        .context("read the artifact bytes")?;

    // 4) Verify: the manifest's digest when it has one, then the pinned key.
    if let Some(expected) = asset.digest.as_deref() {
        verify_sha256(&bytes, expected)?;
        println!("SHA-256 matches the manifest.");
    }
    let url = asset.browser_download_url.as_deref().with_context(|| {
        format!(
            "the manifest names no release URL for {}, so its signature cannot be fetched; refusing to install it",
            asset.name
        )
    })?;
    let asc_url = signature_url(&boundary, url)
        .context("signature must be served by the configured center")?;
    let asc = http
        .get(asc_url.clone())
        .send()
        .await
        .with_context(|| format!("fetching {asc_url}"))?
        .error_for_status()
        .with_context(|| {
            format!(
                "{}.asc is missing from the release; refusing to install an unsigned artifact",
                asset.name
            )
        })?
        .text()
        .await
        .context("reading the .asc")?;
    pgp_verify::verify_release_artifact(&bytes, &asc).with_context(|| {
        format!(
            "{} does not verify against the pinned release key",
            asset.name
        )
    })?;
    println!("Signature verified against the pinned release key.");

    // 5) Install.
    match kind {
        Kind::Zip => {
            let new_exe = extract_windows_exe(&bytes)?;
            replace_self(&exe, &new_exe)?;
        }
        Kind::Tarball => {
            let dir = tarball_dir(latest_ver, triple);
            let new_exe = extract_tarball_binary(&bytes, &dir)?;
            replace_self(&exe, &new_exe)?;
        }
        Kind::Deb => install_deb(&bytes, latest_ver)?,
    }
    println!("Updated to {latest_ver}. Restart roomler to run the new version.");
    Ok(())
}

/// The running binary. On Linux and macOS, symlinks resolved: a swap replaces
/// the file, never a link that points at it (macOS reports the path as
/// invoked). Windows keeps `current_exe()` as it was before P6b: canonicalizing
/// there yields a `\\?\` path and can fail on some volumes, for nothing gained.
fn this_binary() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("resolve the running binary")?;
    if cfg!(windows) {
        return Ok(exe);
    }
    std::fs::canonicalize(&exe).with_context(|| format!("resolve {}", exe.display()))
}

/// The form of the release this host installs. On Linux, the package that
/// owns the running binary decides: dpkg's own `.deb` keeps dpkg's record
/// true; a binary another package owns is not ours to replace.
fn kind_here(exe: &std::path::Path) -> Result<Kind> {
    if cfg!(windows) {
        return Ok(Kind::Zip);
    }
    if !cfg!(target_os = "linux") {
        return Ok(Kind::Tarball);
    }
    match std::process::Command::new("dpkg-query")
        .arg("-S")
        .arg(exe)
        .output()
    {
        // No dpkg at all (Fedora, Arch …): the tarball.
        Err(_) => Ok(Kind::Tarball),
        // dpkg knows no package with this file.
        Ok(out) if !out.status.success() => Ok(Kind::Tarball),
        Ok(out) => kind_for_owner(
            dpkg_owner(&String::from_utf8_lossy(&out.stdout), exe).as_deref(),
            exe,
        ),
    }
}

/// What the package that owns the binary means for the install: our own
/// package, under either name, takes its `.deb`; no package, the tarball; any
/// other package is not ours to replace.
fn kind_for_owner(owner: Option<&str>, exe: &std::path::Path) -> Result<Kind> {
    match owner {
        Some(DEB_PACKAGE | DEB_PACKAGE_BEFORE_RENAME) => Ok(Kind::Deb),
        Some(other) => bail!(
            "{} belongs to the package `{other}`, not `{DEB_PACKAGE}`; update it through that package",
            exe.display()
        ),
        None => Ok(Kind::Tarball),
    }
}

/// The `.deb`'s package name (`[package.metadata.deb] name`).
const DEB_PACKAGE: &str = "roomler-cli";
// RETIRED-NAME-ANCHOR(4): the package's name before FR-21 P2b renamed the crate.
// A host that installed a tunnel .deb before then (rc.266 and older) has its
// binary owned by this name. It is ours: the new .deb declares `replaces` and
// `provides` for it, so `dpkg -i` takes the file over (the CLI's Cargo.toml).
const DEB_PACKAGE_BEFORE_RENAME: &str = "roomler-tunnel";

/// The package that owns `path`, from `dpkg-query -S <path>` output: lines
/// of `<pkg>[, <pkg>…]: <path>`, plus `diversion by …` lines, which name no
/// owner. A path several packages share is reported as its first, which is
/// then not ours unless it is.
fn dpkg_owner(output: &str, path: &std::path::Path) -> Option<String> {
    let want = path.to_string_lossy();
    output.lines().find_map(|line| {
        if line.starts_with("diversion by ") {
            return None;
        }
        let (pkgs, file) = line.split_once(": ")?;
        if file.trim() != want {
            return None;
        }
        let first = pkgs.split(',').next()?.trim();
        // `pkg:arch` on a multiarch host.
        Some(first.split(':').next().unwrap_or(first).to_string())
    })
}

/// True when `latest` strictly outranks `current` — a real ordered compare
/// (mirrors the agent updater's `parse_version` tuple: final ranks above
/// every rc of the same core, `0.4.0 > 0.3.0-rc.482`). The old "different
/// string ⇒ update" fallback meant a stale manifest could DOWNGRADE a final
/// build; with the 0.4.x scheme finals are the common case, so the
/// comparator has to actually order them. Unparseable versions compare as
/// not-newer, so a malformed manifest can't force anything.
fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// `(major, minor, patch, pre_rank)`; `pre_rank` = the rc number for
/// `-rc.N`, `u64::MAX` for a final (or an unknown pre-release label, so a
/// forward-compat tag never ranks below an rc).
fn parse_version(v: &str) -> Option<(u64, u64, u64, u64)> {
    let s = v.trim_start_matches("tunnel-").trim_start_matches('v');
    let (core, pre) = match s.find('-') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut it = core.split('.');
    let major: u64 = it.next()?.parse().ok()?;
    let minor: u64 = it.next()?.parse().ok()?;
    let patch: u64 = it.next()?.parse().ok()?;
    let pre_rank = match pre {
        None => u64::MAX,
        Some(p) => p
            .strip_prefix("rc.")
            .and_then(|n| n.parse().ok())
            .unwrap_or(u64::MAX),
    };
    Some((major, minor, patch, pre_rank))
}

/// Verify `bytes` hash matches `expected` (`sha256:<hex>` or a bare `<hex>`).
fn verify_sha256(bytes: &[u8], expected: &str) -> Result<()> {
    let want = expected
        .trim()
        .trim_start_matches("sha256:")
        .to_ascii_lowercase();
    let mut h = Sha256::new();
    h.update(bytes);
    let got = hex::encode(h.finalize());
    if got != want {
        bail!("SHA-256 mismatch: expected {want}, got {got}");
    }
    Ok(())
}

// RETIRED-NAME-ANCHOR-BEGIN
// Reads a PUBLISHED artifact's layout: `release-tunnel.yml` names every tunnel
// asset, and the dir inside its tarball, `roomler-tunnel-<version>-<triple>`.
// Release asset names are frozen by FR-21 D6.
/// The one top-level dir of a release tarball (`release-tunnel.yml` tars
/// `roomler-tunnel-<version>-<triple>/`). It is inside the signed bytes, so
/// it names the version from the artifact itself.
fn tarball_dir(version: &str, triple: &str) -> String {
    format!("roomler-tunnel-{version}-{triple}")
}
// RETIRED-NAME-ANCHOR-END

/// The `roomler` binary from a release tarball, read in memory: nothing is
/// extracted to disk, so no directory is ever created or chowned, as root or
/// otherwise. The binary must sit at `<dir>/roomler`, where `dir` names the
/// version the artifact was offered as; an archive of another version, or one
/// with no such entry, is refused.
#[cfg(unix)]
fn extract_tarball_binary(tgz: &[u8], dir: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let want = format!("{dir}/roomler");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tgz));
    for entry in archive.entries().context("read the release tarball")? {
        let mut entry = entry.context("read a tarball entry")?;
        let path = entry.path().context("read a tarball entry's path")?;
        let path = path.to_string_lossy();
        let path = path.trim_start_matches("./");
        if path == want && entry.header().entry_type().is_file() {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry
                .read_to_end(&mut buf)
                .context("read roomler from the tarball")?;
            return Ok(buf);
        }
    }
    bail!(
        "the tarball has no `{want}`: it is not the release it was offered as, or not a tunnel CLI archive; refusing it"
    )
}

#[cfg(not(unix))]
fn extract_tarball_binary(_tgz: &[u8], _dir: &str) -> Result<Vec<u8>> {
    bail!("a tarball installs only on Linux and macOS")
}

/// Pull the CLI exe out of the release zip. P3d Slice B renamed the OUTPUT
// RETIRED-NAME-ANCHOR-BEGIN
// Reads a PUBLISHED archive. The retired entry name is an input this must
// keep accepting: a fleet host running the previous CLI looks for exactly
// that name, and dropping the arm strands it on its current version.
/// binary `roomler-tunnel.exe` -> `roomler.exe`, but the CI ships BOTH names
/// in the zip and a deployed (pre-rename) fleet self-updater may still be
/// extracting `roomler-tunnel.exe`, so accept EITHER source entry. The on-disk
/// replace target ([`replace_self`]) is driven by `current_exe()`, so whatever
/// the running binary is named stays named — only the zip SOURCE entry name
/// widens here.
fn extract_windows_exe(zip_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("open release zip")?;
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).context("read zip entry")?;
        let name = f.name();
        if name.ends_with("roomler.exe") || name.ends_with("roomler-tunnel.exe") {
            let mut buf = Vec::with_capacity(f.size() as usize);
            std::io::Read::read_to_end(&mut f, &mut buf).context("read exe from zip")?;
            return Ok(buf);
        }
    }
    bail!("neither roomler.exe nor roomler-tunnel.exe found in the release archive");
    // RETIRED-NAME-ANCHOR-END
}

/// Replace the running executable with `new_exe` bytes. Windows lets a running
/// image be RENAMED (not deleted), so move the current exe aside to `.old`, then
/// write the new bytes at the original path. The `.old` is cleared on the next
/// update. Rolls back on a write failure so the tool is never left binary-less.
#[cfg(windows)]
fn replace_self(cur: &std::path::Path, new_exe: &[u8]) -> Result<()> {
    let old = cur.with_extension("old");
    let _ = std::fs::remove_file(&old); // clear any prior `.old`
    std::fs::rename(cur, &old).context("move running exe aside")?;
    if let Err(e) = std::fs::write(cur, new_exe) {
        let _ = std::fs::rename(&old, cur); // roll back
        return Err(e).context("write new exe");
    }
    Ok(())
}

/// Replace the running binary on Linux and macOS: the new bytes go to a
/// file beside it, created fresh (never one already there, so a planted link
/// cannot redirect the write), synced, made `0755`, then `rename(2)`d over the
/// old one. The rename is atomic, so a failure at any step leaves the old
/// binary where it was; the running process keeps its own inode.
#[cfg(unix)]
fn replace_self(cur: &std::path::Path, new_exe: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = cur
        .parent()
        .with_context(|| format!("{} has no parent dir", cur.display()))?;
    let tmp = dir.join(format!(".roomler.update.{}", std::process::id()));
    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => bail!(
            "cannot write in {}: re-run as root (`sudo roomler self-update`)",
            dir.display()
        ),
        Err(e) => return Err(e).with_context(|| format!("create {}", tmp.display())),
    };
    let written = f
        .write_all(new_exe)
        .and_then(|()| f.sync_all())
        // The mode a umask may have trimmed at create.
        .and_then(|()| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)))
        .and_then(|()| std::fs::rename(&tmp, cur));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replace {}", cur.display()));
    }
    Ok(())
}

/// `dpkg -i` needs root: say so, before anything is downloaded.
#[cfg(unix)]
fn deb_needs_root() -> Result<()> {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "dpkg owns this binary, so the update installs its .deb, which needs root: re-run as root (`sudo roomler self-update`)"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn deb_needs_root() -> Result<()> {
    bail!("a .deb installs only on Linux")
}

/// Install the verified `.deb` with `dpkg -i`, after checking its control
/// `Version` is the version it was offered as. Root: dpkg needs it.
#[cfg(unix)]
fn install_deb(deb: &[u8], offered: &str) -> Result<()> {
    deb_needs_root()?;
    // A private dir (0700, a fresh name): nothing else can swap the file
    // between the check and dpkg reading it.
    let dir = tempfile::Builder::new()
        .prefix("roomler-update-")
        .tempdir()
        .context("create a private dir for the .deb")?;
    let path = dir.path().join(format!("{DEB_PACKAGE}.deb"));
    std::fs::write(&path, deb).context("write the .deb")?;
    let field = std::process::Command::new("dpkg-deb")
        .arg("--field")
        .arg(&path)
        .arg("Version")
        .output()
        .context("run dpkg-deb")?;
    let version = String::from_utf8_lossy(&field.stdout);
    if !field.status.success() || !deb_version_is(version.trim(), offered) {
        bail!(
            "the .deb says it is version {:?}, not {offered}, the version it was offered as; refusing it",
            version.trim()
        );
    }
    let st = std::process::Command::new("dpkg")
        .arg("-i")
        .arg(&path)
        .status()
        .context("run dpkg -i")?;
    if !st.success() {
        bail!("dpkg -i exited {:?}", st.code());
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_deb(_deb: &[u8], _offered: &str) -> Result<()> {
    bail!("a .deb installs only on Linux")
}

/// Does a Debian `Version` name the release `offered`? cargo-deb writes the
/// crate's version with a `-1` revision, and Debian spells a pre-release with
/// `~` (`0.3.0~rc.266-1` for `0.3.0-rc.266`).
#[cfg_attr(not(unix), allow(dead_code))]
fn deb_version_is(version: &str, offered: &str) -> bool {
    let upstream = match version.rsplit_once('-') {
        Some((up, rev)) if !rev.is_empty() && rev.bytes().all(|b| b.is_ascii_digit()) => up,
        _ => version,
    };
    upstream.replace('~', "-") == offered
}

/// The config `self-update` reads its server from. Run under `sudo` (a
/// root-owned install dir, `dpkg -i`), the default config path is root's own,
/// which has no enrollment. So, without an explicit `--config`, a config not
/// found there is read from the invoking user's home (`SUDO_USER`), at the same
/// place relative to it. Only its server URL is used, and that user could run
/// the update as root anyway, so reading their own file grants nothing.
pub fn config_for_self_update(path: Option<std::path::PathBuf>) -> Result<TunnelConfig> {
    let explicit = path.is_some();
    match crate::config::load(path) {
        Ok(cfg) => Ok(cfg),
        Err(e) if !explicit => match sudo_user_config_path() {
            Some(p) if p.exists() => crate::config::load(Some(p.clone())).with_context(|| {
                format!("loading the invoking user's tunnel config {}", p.display())
            }),
            _ => Err(e).context("loading tunnel config"),
        },
        Err(e) => Err(e).context("loading tunnel config"),
    }
}

/// The invoking user's config under `sudo`: the default path, re-based from
/// this process's home onto theirs.
#[cfg(unix)]
fn sudo_user_config_path() -> Option<std::path::PathBuf> {
    let user = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root")?;
    let their_home = home_of(&user)?;
    let ours = crate::config::default_config_path().ok()?;
    let our_home = directories::BaseDirs::new()?.home_dir().to_path_buf();
    rebase_home(&ours, &our_home, &their_home)
}

#[cfg(not(unix))]
fn sudo_user_config_path() -> Option<std::path::PathBuf> {
    None
}

/// `path` moved from under `from` to under `to`; `None` when it is not under
/// `from`.
#[cfg_attr(not(unix), allow(dead_code))]
fn rebase_home(
    path: &std::path::Path,
    from: &std::path::Path,
    to: &std::path::Path,
) -> Option<std::path::PathBuf> {
    path.strip_prefix(from).ok().map(|rel| to.join(rel))
}

/// An account's home directory (`getpwnam_r`, the buffer grown on `ERANGE`).
#[cfg(unix)]
fn home_of(user: &str) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(user).ok()?;
    let mut buf = vec![0 as libc::c_char; 1024];
    // SAFETY: an all-zero `passwd` is a valid value (null pointers, zero ids).
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        // SAFETY: every pointer is to memory this frame owns, sized as
        // passed; the answer points into `buf`, read below while it lives.
        let rc = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 64 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        break;
    }
    // SAFETY: `pw_dir` is non-null and points into `buf`, which is alive.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        dir.to_bytes(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    // FR-97 P6b — `sudo roomler self-update` reads the invoking user's config.
    #[test]
    fn a_config_path_moves_from_one_home_to_another() {
        use std::path::Path;
        assert_eq!(
            rebase_home(
                Path::new("/root/.config/x/config.toml"),
                Path::new("/root"),
                Path::new("/home/u"),
            )
            .as_deref(),
            Some(Path::new("/home/u/.config/x/config.toml"))
        );
        assert_eq!(
            rebase_home(
                Path::new("/etc/x.toml"),
                Path::new("/root"),
                Path::new("/home/u")
            ),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_has_a_home() {
        assert_eq!(
            home_of("root").as_deref(),
            Some(std::path::Path::new("/root"))
        );
        assert_eq!(home_of("no-such-account-p6b"), None);
    }

    #[test]
    fn rc_compare() {
        assert!(is_newer("0.3.0-rc.151", "0.3.0-rc.150"));
        assert!(!is_newer("0.3.0-rc.150", "0.3.0-rc.150"));
        assert!(!is_newer("0.3.0-rc.149", "0.3.0-rc.150"));
        // rc integer compare, not lexical (rc.9 < rc.100).
        assert!(is_newer("0.3.0-rc.100", "0.3.0-rc.9"));
        // Ordered across cores now (was "different string ⇒ update").
        assert!(is_newer("0.4.0-rc.1", "0.3.0-rc.150"));
        // The 0.4.x final scheme: finals outrank every rc of their core,
        // order among themselves, and a stale manifest can no longer
        // DOWNGRADE (the old fallback made any different string an update).
        assert!(is_newer("0.4.0", "0.3.0-rc.482"));
        assert!(is_newer("0.4.0", "0.4.0-rc.3"));
        assert!(is_newer("0.4.2", "0.4.1"));
        assert!(!is_newer("0.4.0", "0.4.1"));
        assert!(!is_newer("0.3.0-rc.482", "0.4.0"));
        // Malformed input can't force an update.
        assert!(!is_newer("banana", "0.4.0"));
    }

    #[test]
    fn sha256_roundtrip() {
        // echo -n "hello" | sha256sum
        let want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(b"hello", want).is_ok());
        assert!(verify_sha256(b"hello", &format!("sha256:{want}")).is_ok());
        assert!(verify_sha256(b"world", want).is_err());
    }

    // RETIRED-NAME-ANCHOR-BEGIN
    // Fixtures of PUBLISHED tunnel artifacts: their names, and the dir inside a
    // tarball, are `roomler-tunnel-<version>-<triple>`, frozen by FR-21 D6.
    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.into(),
            digest: None,
            browser_download_url: Some(format!("https://example.com/{name}")),
        }
    }

    // FR-97 P6b — every host's artifact, by the server picker's own rule.
    #[test]
    fn each_host_takes_its_own_artifact_and_never_a_sidecar() {
        let v = "0.4.149";
        // Each sidecar is listed BEFORE its artifact, so a match on "contains
        // the extension" would take the sidecar and fail this test.
        let assets: Vec<ReleaseAsset> = [
            "x86_64-unknown-linux-gnu.tar.gz.asc",
            "x86_64-unknown-linux-gnu.tar.gz.sha256",
            "x86_64-unknown-linux-gnu.tar.gz",
            "x86_64-unknown-linux-gnu.deb.asc",
            "x86_64-unknown-linux-gnu.deb",
            "aarch64-unknown-linux-gnu.tar.gz.asc",
            "aarch64-unknown-linux-gnu.tar.gz",
            "aarch64-unknown-linux-gnu.deb.sha256",
            "aarch64-unknown-linux-gnu.deb",
            "universal-apple-darwin.tar.gz.asc",
            "universal-apple-darwin.tar.gz",
            "x86_64-pc-windows-msvc.zip.asc",
            "x86_64-pc-windows-msvc.zip",
        ]
        .iter()
        .map(|t| asset(&format!("roomler-tunnel-{v}-{t}")))
        .collect();
        let pick = |platform, kind| {
            let (token, triple, ext) = artifact_for(platform, kind).expect("an artifact");
            (
                token,
                manifest_asset(&assets, triple, ext).map(|a| a.name.clone()),
            )
        };
        let named = |t: &str| Some(format!("roomler-tunnel-{v}-{t}"));
        assert_eq!(
            pick("linux-x86_64", Kind::Tarball),
            ("linux-x86_64", named("x86_64-unknown-linux-gnu.tar.gz"))
        );
        assert_eq!(
            pick("linux-x86_64", Kind::Deb),
            ("linux-deb", named("x86_64-unknown-linux-gnu.deb"))
        );
        assert_eq!(
            pick("linux-aarch64", Kind::Tarball),
            ("linux-aarch64", named("aarch64-unknown-linux-gnu.tar.gz"))
        );
        assert_eq!(
            pick("linux-aarch64", Kind::Deb),
            ("linux-deb-aarch64", named("aarch64-unknown-linux-gnu.deb"))
        );
        assert_eq!(
            pick("macos", Kind::Tarball),
            ("macos", named("universal-apple-darwin.tar.gz"))
        );
        assert_eq!(
            pick("windows-x86_64", Kind::Zip),
            ("windows-x86_64", named("x86_64-pc-windows-msvc.zip"))
        );
        // No artifact is built for these, so no download is attempted.
        assert_eq!(artifact_for("macos", Kind::Deb), None);
        assert_eq!(artifact_for("unknown", Kind::Tarball), None);
        assert_eq!(artifact_for("windows-x86_64", Kind::Tarball), None);
    }

    #[test]
    fn dpkg_names_the_owner_or_nobody() {
        let p = std::path::Path::new("/usr/bin/roomler");
        assert_eq!(
            dpkg_owner("roomler-cli: /usr/bin/roomler\n", p).as_deref(),
            Some("roomler-cli")
        );
        // Multiarch spelling, and a path shared by several packages.
        assert_eq!(
            dpkg_owner("roomler-cli:arm64: /usr/bin/roomler\n", p).as_deref(),
            Some("roomler-cli")
        );
        assert_eq!(
            dpkg_owner("roomlerd, roomler-cli: /usr/bin/roomler\n", p).as_deref(),
            Some("roomlerd")
        );
        // A diversion line names no owner; another path is not this one.
        assert_eq!(
            dpkg_owner("diversion by foo from: /usr/bin/roomler\n", p),
            None
        );
        assert_eq!(dpkg_owner("roomler-cli: /usr/bin/other\n", p), None);
        assert_eq!(dpkg_owner("", p), None);
    }

    #[test]
    fn our_package_under_either_name_takes_the_deb() {
        let p = std::path::Path::new("/usr/bin/roomler");
        assert_eq!(kind_for_owner(Some(DEB_PACKAGE), p).unwrap(), Kind::Deb);
        // The pre-rename package: the new .deb `replaces` it.
        assert_eq!(
            kind_for_owner(Some(DEB_PACKAGE_BEFORE_RENAME), p).unwrap(),
            Kind::Deb
        );
        assert_eq!(kind_for_owner(None, p).unwrap(), Kind::Tarball);
        // The agent's package (its shim is `roomler` too) is not ours.
        assert!(kind_for_owner(Some("roomlerd"), p).is_err());
    }

    #[test]
    fn a_deb_version_names_its_release() {
        assert!(deb_version_is("0.4.149-1", "0.4.149"));
        assert!(deb_version_is("0.4.149", "0.4.149"));
        assert!(deb_version_is("0.3.0~rc.266-1", "0.3.0-rc.266"));
        // Another release, however close, is refused.
        assert!(!deb_version_is("0.4.148-1", "0.4.149"));
        assert!(!deb_version_is("0.4.1490-1", "0.4.149"));
        assert!(!deb_version_is("", "0.4.149"));
    }

    /// A gzipped tar of `(path, bytes)` files, as `release-tunnel.yml` makes one.
    #[cfg(unix)]
    fn tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, path, *data)
                .expect("append");
        }
        builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    #[cfg(unix)]
    #[test]
    fn the_tarball_gives_up_its_binary_only_under_the_offered_version() {
        let dir = tarball_dir("0.4.149", "x86_64-unknown-linux-gnu");
        assert_eq!(dir, "roomler-tunnel-0.4.149-x86_64-unknown-linux-gnu");
        let good = tgz(&[
            (&format!("{dir}/README"), b"readme"),
            (&format!("{dir}/roomler"), b"the new binary"),
        ]);
        assert_eq!(
            extract_tarball_binary(&good, &dir).expect("found"),
            b"the new binary"
        );
        // Tarred as `./<dir>`.
        let dotted = tgz(&[(&format!("./{dir}/roomler"), b"dotted")]);
        assert_eq!(
            extract_tarball_binary(&dotted, &dir).expect("found"),
            b"dotted"
        );
        // An older release offered as this one: its dir names its own version.
        let old = tgz(&[(
            "roomler-tunnel-0.4.148-x86_64-unknown-linux-gnu/roomler",
            b"old binary",
        )]);
        assert!(extract_tarball_binary(&old, &dir).is_err());
        // An archive without the binary.
        let empty = tgz(&[(&format!("{dir}/README"), b"readme")]);
        assert!(extract_tarball_binary(&empty, &dir).is_err());
    }
    // RETIRED-NAME-ANCHOR-END

    #[cfg(unix)]
    #[test]
    fn the_swap_replaces_the_file_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin = tmp.path().join("roomler");
        std::fs::write(&bin, b"old").expect("write old");
        replace_self(&bin, b"new").expect("replace");
        assert_eq!(std::fs::read(&bin).expect("read"), b"new");
        let mode = std::fs::metadata(&bin).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        let left: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("list")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("roomler")]);
    }
}
