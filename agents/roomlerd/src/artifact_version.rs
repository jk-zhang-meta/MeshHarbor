// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Bind the version a release manifest CLAIMS to the version the downloaded
//! artifact actually IS.
//!
//! ## Why this exists
//!
//! [`crate::code_signature`] answers *whose* bytes these are. It does not
//! answer *which release* they are — and the updater decides those two
//! questions from different sources:
//!
//! - [`crate::updater::is_newer`] compares the **manifest's** tag against
//!   `CARGO_PKG_VERSION`.
//! - `verify_publisher` verifies the **artifact**.
//!
//! Nothing bound the two. An attacker able to serve the manifest (a
//! compromised release proxy or PoP, a stolen release token, a
//! TLS-terminating middlebox) advertises `agent-v0.3.0-rc.999` while pointing
//! `browser_download_url` at a genuinely-signed **older** build with a known
//! vulnerability. The signature passes — it really is ours. `is_newer` passes
//! — 999 outranks anything in the field. The fleet downgrades into a version
//! whose exploit is public, and the whole way through, nothing untrue was said
//! about the bytes. Publisher verification structurally cannot see this.
//!
//! The fix is to make the artifact state its own version and refuse when that
//! disagrees with what we were told it is. It works because the version lives
//! INSIDE the signed envelope: editing it invalidates the Authenticode
//! signature the previous check already enforces.
//!
//! ## ⚠️ The two checks are only meaningful together
//!
//! A version binding on its own proves nothing — whoever can replace the
//! artifact can equally set the version inside it. It is the *signature* that
//! makes the embedded version unforgeable, and the *embedded version* that
//! makes the signature mean "the release you asked for" rather than merely
//! "one of ours".
//!
//! That is why the Linux `.deb`, the macOS `.pkg` and the Linux tarball had
//! no binding until the updater authenticated them: a binding there would
//! have checked a claim against a claim while reading like a control. The
//! updater now verifies each one's detached OpenPGP `.asc` against the
//! release key **pinned in this binary** (`pgp_verify`), and the signature
//! covers the whole file, so the version inside is as unforgeable as an MSI's.
//!
//! ## FR-97 P6a — the same binding for `.deb`, `.pkg` and the tarball
//!
//! | Format | Where it states its version | Read by |
//! |---|---|---|
//! | `.msi` | `ProductVersion` in the `Property` table | the Windows Installer database API |
//! | `.deb` | `Version` in its control file (`0.4.142-1`; the `-1` is the Debian revision) | `dpkg-deb --field`, which ships with the dpkg the updater requires before picking a `.deb` |
//! | `.pkg` | `version` on the component `PackageInfo`'s `<pkg-info identifier="com.roomler.agent">` | `pkgutil --expand` |
//! | `.tar.gz` | its one top directory, `roomlerd-<version>-<target>` | `tar -tzf`, which the tarball install runs anyway |
//!
//! ⚠️ A wrong reader refuses every update fleet-wide, so the three new readers
//! sit behind `ROOMLERD_ARTIFACT_VERSION_CHECK=0`, and each was read against
//! real published releases before it shipped (FR-97 §8).

use std::path::Path;

/// Why a downloaded artifact was not accepted as the release it was offered
/// as. `Mismatch` is a refusal; the rest are described at each variant.
#[derive(Debug)]
pub enum VersionError {
    /// The artifact says it is a different release than the manifest claimed.
    /// This is the downgrade signature, and it is always a refusal.
    Mismatch {
        claimed: String,
        expected: String,
        found: String,
    },
    /// The artifact's own version could not be read — a corrupt package, or a
    /// file that is not the format its name says it is. A refusal: we are
    /// about to run this as SYSTEM and cannot say what it is.
    Unreadable(String),
    /// The manifest's tag maps to no version the release workflow could have
    /// produced. A refusal — a release like that does not exist, so a
    /// manifest offering one is already lying.
    UnmappableClaim(String),
    /// No version binding applies: a format this module does not read, a
    /// reader that cannot run on this OS, or the P6a readers switched off.
    /// NOT a refusal: nothing was proved either way.
    Unsupported(String),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mismatch {
                claimed,
                expected,
                found,
            } => write!(
                f,
                "offered as {claimed} (which must carry version {expected}) but the artifact says it is {found} — \
                 the manifest and the package disagree about which release this is"
            ),
            Self::Unreadable(why) => write!(f, "could not read the artifact's own version: {why}"),
            Self::UnmappableClaim(tag) => {
                write!(f, "no release version can be derived from the tag {tag:?}")
            }
            Self::Unsupported(fmt_name) => {
                write!(f, "no version binding is implemented for {fmt_name}")
            }
        }
    }
}

impl std::error::Error for VersionError {}

/// Check that the artifact at `path` self-identifies as the release `claimed`
/// (a tag such as `agent-v0.3.0-rc.458`, or the bare semver).
///
/// Returns the artifact's own version string on success.
pub fn verify_artifact_version(path: &Path, claimed: &str) -> Result<String, VersionError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    let tarball = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().ends_with(".tar.gz"));
    match ext.as_str() {
        "msi" => verify_msi(path, claimed),
        "deb" | "rpm" | "pkg" | "gz" if (ext != "gz" || tarball) && !unix_binding_enabled() => {
            let format = if tarball { "tar.gz" } else { ext.as_str() };
            Err(VersionError::Unsupported(format!(
                ".{format} artifacts while the binding is switched off \
                 (ROOMLERD_ARTIFACT_VERSION_CHECK=0)"
            )))
        }
        "deb" => verify_deb(path, claimed),
        "rpm" => verify_rpm(path, claimed),
        "pkg" => verify_pkg(path, claimed),
        "gz" if tarball => verify_tarball(path, claimed),
        "" => Err(VersionError::Unsupported(
            "a file with no extension".to_string(),
        )),
        other => Err(VersionError::Unsupported(format!(".{other} artifacts"))),
    }
}

/// FR-97 P6a — is the `.deb`, `.pkg` and tarball binding on? Default on;
/// `ROOMLERD_ARTIFACT_VERSION_CHECK=0` turns those three readers off (the
/// MSI's, older and proven, stays). A wrong reader would refuse every update
/// fleet-wide, so the switch is the way out that needs no new release.
fn unix_binding_enabled() -> bool {
    tunnel_core::env::flag("ARTIFACT_VERSION_CHECK", true)
}

/// FR-97 P6a — the version a release's `.deb`, `.pkg` and tarball carry: the
/// tag's own semver, `agent-v0.4.142` → `0.4.142` (`0.3.0-rc.458` stays
/// `0.3.0-rc.458`). `None` for a tag no release could have: not three numeric
/// fields, or a pre-release other than `rc.N` (the workflow refuses to build
/// either, as [`msi_product_version_for`] says).
pub fn release_version_for(release: &str) -> Option<String> {
    let s = release.trim_start_matches("agent-").trim_start_matches('v');
    let (core, pre) = match s.find('-') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let fields = numeric_fields(core)?;
    match pre {
        None => Some(fields),
        Some(pre) => {
            let rc: u64 = pre.strip_prefix("rc.")?.parse().ok()?;
            Some(format!("{fields}-rc.{rc}"))
        }
    }
}

/// `MAJOR.MINOR.PATCH`, each numeric, read back without leading zeros.
fn numeric_fields(core: &str) -> Option<String> {
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut out = Vec::with_capacity(3);
    for p in parts {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out.push(p.parse::<u64>().ok()?.to_string());
    }
    Some(out.join("."))
}

/// A Debian `Version` field as the release it names: no epoch (`1:`), no
/// Debian revision (the last `-N`, which cargo-deb sets to `1`: the 0.4.142
/// package says `0.4.142-1`), and a `~` read back as the `-` it stands for in
/// a pre-release (`0.3.0~rc.458` sorts before `0.3.0`, as `-rc.458` does).
#[cfg(any(target_os = "linux", test))]
fn deb_upstream_version(v: &str) -> String {
    let v = v.trim();
    let v = match v.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => v,
    };
    let v = match v.rsplit_once('-') {
        Some((upstream, rev))
            if !upstream.is_empty()
                && !rev.is_empty()
                && rev.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
        {
            upstream
        }
        _ => v,
    };
    v.replace('~', "-")
}

/// The release a tarball's top directory names:
/// `roomlerd-0.4.142-x86_64-unknown-linux-gnu` → `0.4.142`
/// (`roomlerd-0.3.0-rc.458-…` → `0.3.0-rc.458`). `None` for any other shape.
#[cfg(any(unix, test))]
fn tarball_version(top: &str) -> Option<String> {
    let rest = top
        .strip_prefix("meshharbor-")
        .or_else(|| top.strip_prefix("roomlerd-"))?;
    let mut parts = rest.split('-');
    let fields = numeric_fields(parts.next()?)?;
    match parts.next()? {
        p if p.starts_with("rc.") => {
            let rc: u64 = p["rc.".len()..].parse().ok()?;
            Some(format!("{fields}-rc.{rc}"))
        }
        // The target triple follows; a top directory without one is not ours.
        _ => Some(fields),
    }
}

/// The version a `.pkg`'s component `PackageInfo` declares for the agent: the
/// `version` attribute of its `<pkg-info identifier="com.roomler.agent" …>`.
/// `None` when it declares another package, or none.
#[cfg(any(target_os = "macos", test))]
fn pkg_info_version(xml: &str) -> Option<String> {
    let start = xml.find("<pkg-info")?;
    let end = start + xml[start..].find('>')?;
    let tag = &xml[start..end];
    if xml_attr(tag, "identifier")? != "com.roomler.agent" {
        return None;
    }
    xml_attr(tag, "version").map(str::to_string)
}

/// One attribute's value in a start tag. The name must follow whitespace, so
/// `version` never reads `format-version` or `generator-version`, both of
/// which a `PackageInfo` carries.
#[cfg(any(target_os = "macos", test))]
fn xml_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    tag.match_indices(&needle).find_map(|(i, _)| {
        let before = tag[..i].chars().next_back()?;
        if !before.is_whitespace() {
            return None;
        }
        let value = &tag[i + needle.len()..];
        Some(&value[..value.find('"')?])
    })
}

/// The verdict once a reader has the artifact's own version: `found` as the
/// package spells it, `normalized` as the release it names.
#[cfg(unix)]
fn bind(
    claimed: &str,
    expected: String,
    found: String,
    normalized: &str,
) -> Result<String, VersionError> {
    if normalized == expected {
        Ok(found)
    } else {
        Err(VersionError::Mismatch {
            claimed: claimed.to_string(),
            expected,
            found,
        })
    }
}

/// FR-97 P6a — a `.deb` states its version in its control file, inside the
/// signed bytes (the `.asc` the updater checks against the pinned key covers
/// the whole package). Read by `dpkg-deb`, which comes with the dpkg the
/// updater requires before it picks a `.deb` at all.
#[cfg(target_os = "linux")]
fn verify_deb(path: &Path, claimed: &str) -> Result<String, VersionError> {
    let expected = release_version_for(claimed)
        .ok_or_else(|| VersionError::UnmappableClaim(claimed.to_string()))?;
    let out = match std::process::Command::new("dpkg-deb")
        .arg("--field")
        .arg(path)
        .arg("Version")
        .output()
    {
        Ok(out) => out,
        // Nothing proved either way, and the install itself would need dpkg:
        // not a refusal of its own.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VersionError::Unsupported(
                ".deb artifacts without dpkg-deb".to_string(),
            ));
        }
        Err(e) => return Err(VersionError::Unreadable(format!("running dpkg-deb: {e}"))),
    };
    if !out.status.success() {
        return Err(VersionError::Unreadable(format!(
            "dpkg-deb: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let found = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if found.is_empty() {
        return Err(VersionError::Unreadable(
            "the package names no Version".to_string(),
        ));
    }
    let normalized = deb_upstream_version(&found);
    bind(claimed, expected, found, &normalized)
}

#[cfg(not(target_os = "linux"))]
fn verify_deb(_path: &Path, _claimed: &str) -> Result<String, VersionError> {
    Err(VersionError::Unsupported(
        ".deb artifacts off Linux".to_string(),
    ))
}

/// An `.rpm` header's `VERSION` as the release it names. It carries no release
/// suffix (that is `RELEASE`, a separate tag), and a pre-release is written
/// with `~` for the `-` RPM does not allow in a version (`0.3.0~rc.458`).
#[cfg(any(target_os = "linux", test))]
fn rpm_upstream_version(v: &str) -> String {
    v.trim().replace('~', "-")
}

/// FR-117 P1 — an `.rpm` states its version in its header, inside the signed
/// bytes (the `.asc` the updater checks against the pinned key covers the whole
/// package). Only the desktop companion ships as an `.rpm`, and it is picked
/// only on a host whose package database is rpm's, so `rpm` is there.
#[cfg(target_os = "linux")]
fn verify_rpm(path: &Path, claimed: &str) -> Result<String, VersionError> {
    let expected = release_version_for(claimed)
        .ok_or_else(|| VersionError::UnmappableClaim(claimed.to_string()))?;
    let out = match std::process::Command::new("rpm")
        .args(["-qp", "--qf", "%{VERSION}"])
        .arg(path)
        .output()
    {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VersionError::Unsupported(
                ".rpm artifacts without rpm".to_string(),
            ));
        }
        Err(e) => return Err(VersionError::Unreadable(format!("running rpm: {e}"))),
    };
    if !out.status.success() {
        return Err(VersionError::Unreadable(format!(
            "rpm: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let found = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if found.is_empty() {
        return Err(VersionError::Unreadable(
            "the package names no VERSION".to_string(),
        ));
    }
    let normalized = rpm_upstream_version(&found);
    bind(claimed, expected, found, &normalized)
}

#[cfg(not(target_os = "linux"))]
fn verify_rpm(_path: &Path, _claimed: &str) -> Result<String, VersionError> {
    Err(VersionError::Unsupported(
        ".rpm artifacts off Linux".to_string(),
    ))
}

/// FR-97 P6a — a tarball states its version in its one top directory,
/// `roomlerd-<version>-<target>`, inside the signed bytes. Listed by `tar`,
/// which the tarball install itself runs.
#[cfg(unix)]
fn verify_tarball(path: &Path, claimed: &str) -> Result<String, VersionError> {
    let expected = release_version_for(claimed)
        .ok_or_else(|| VersionError::UnmappableClaim(claimed.to_string()))?;
    let out = std::process::Command::new("tar")
        .arg("-tzf")
        .arg(path)
        .output()
        .map_err(|e| VersionError::Unreadable(format!("running tar: {e}")))?;
    if !out.status.success() {
        return Err(VersionError::Unreadable(format!(
            "tar: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let first = listing
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or_else(|| VersionError::Unreadable("the archive is empty".to_string()))?;
    let top = first
        .trim_start_matches("./")
        .split('/')
        .next()
        .unwrap_or_default();
    let found = tarball_version(top).ok_or_else(|| {
        VersionError::Unreadable(format!("the top directory {top:?} names no release"))
    })?;
    let normalized = found.clone();
    bind(claimed, expected, found, &normalized)
}

#[cfg(not(unix))]
fn verify_tarball(_path: &Path, _claimed: &str) -> Result<String, VersionError> {
    Err(VersionError::Unsupported(
        ".tar.gz artifacts on Windows".to_string(),
    ))
}

/// FR-97 P6a — a `.pkg` states its version in its component's
/// `PackageInfo`, inside the signed bytes. Expanded by `pkgutil` into a fresh
/// directory (it refuses an existing one), which goes again on every path.
#[cfg(target_os = "macos")]
fn verify_pkg(path: &Path, claimed: &str) -> Result<String, VersionError> {
    let expected = release_version_for(claimed)
        .ok_or_else(|| VersionError::UnmappableClaim(claimed.to_string()))?;
    struct Expanded(std::path::PathBuf);
    impl Drop for Expanded {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = Expanded(std::env::temp_dir().join(format!(
        "roomler-pkg-version-{}-{nanos}",
        std::process::id()
    )));
    let out = std::process::Command::new("/usr/sbin/pkgutil")
        .arg("--expand")
        .arg(path)
        .arg(&dir.0)
        .output()
        .map_err(|e| VersionError::Unreadable(format!("running pkgutil: {e}")))?;
    if !out.status.success() {
        return Err(VersionError::Unreadable(format!(
            "pkgutil --expand: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let entries = std::fs::read_dir(&dir.0)
        .map_err(|e| VersionError::Unreadable(format!("reading the expanded package: {e}")))?;
    for entry in entries.flatten() {
        let Ok(xml) = std::fs::read_to_string(entry.path().join("PackageInfo")) else {
            continue;
        };
        if let Some(found) = pkg_info_version(&xml) {
            let normalized = found.clone();
            return bind(claimed, expected, found, &normalized);
        }
    }
    Err(VersionError::Unreadable(
        "no component PackageInfo names com.roomler.agent".to_string(),
    ))
}

#[cfg(not(target_os = "macos"))]
fn verify_pkg(_path: &Path, _claimed: &str) -> Result<String, VersionError> {
    Err(VersionError::Unsupported(
        ".pkg artifacts off macOS".to_string(),
    ))
}

#[cfg(windows)]
fn verify_msi(path: &Path, claimed: &str) -> Result<String, VersionError> {
    let expected = msi_product_version_for(claimed)
        .ok_or_else(|| VersionError::UnmappableClaim(claimed.to_string()))?;
    let found = win::product_version(path).map_err(VersionError::Unreadable)?;

    // Compare the numeric fields, not the strings: `0.3.458` and `0.3.458.0`
    // are the same ProductVersion to Windows Installer, and a leading zero is
    // not a different version either.
    let want = msi_fields(&expected).ok_or_else(|| {
        VersionError::UnmappableClaim(format!(
            "{claimed} mapped to {expected:?}, which is not a valid ProductVersion"
        ))
    })?;
    let got = msi_fields(&found).ok_or_else(|| {
        VersionError::Unreadable(format!(
            "ProductVersion {found:?} is not three numeric fields"
        ))
    })?;

    if want == got {
        Ok(found)
    } else {
        Err(VersionError::Mismatch {
            claimed: claimed.to_string(),
            expected,
            found,
        })
    }
}

#[cfg(not(windows))]
fn verify_msi(_path: &Path, _claimed: &str) -> Result<String, VersionError> {
    // `pick_asset_for_platform` is compiled per target, so a non-Windows agent
    // never selects an MSI — this arm exists so the dispatch above stays one
    // list instead of two cfg-split ones.
    Err(VersionError::Unsupported(
        ".msi artifacts off Windows".to_string(),
    ))
}

/// The MSI `ProductVersion` a given release must carry.
///
/// Windows Installer's version is three numeric fields (`MAJOR.MINOR.BUILD`,
/// build ≤ 65535) and it IGNORES a 4th, so `0.3.0-rc.458` cannot be stored
/// literally. `release-agent.yml` therefore maps the rc number into the build
/// field — `MAJOR.MINOR.RC`, a final release taking 65535 so it outranks every
/// rc of that minor — and passes the result to `cargo wix --install-version`,
/// which lands it in `Product/@Version`.
///
/// ⚠️ This function and the workflow's `Resolve version` step ("Derive the MSI
/// ProductVersion") are two copies of one rule and MUST move together. If they
/// diverge, every agent refuses every update and the symptom is a silent
/// fleet-wide update freeze, not an error — the same coupling
/// [`crate::code_signature::EXPECTED_PUBLISHER`] has with the signing action,
/// and the same consequence.
///
/// `None` for any shape the workflow itself refuses to build: a non-`rc.N`
/// pre-release, an rc with a non-zero patch, an rc above the build field's
/// ceiling.
///
/// ## ⚠️ Releases before `agent-v0.3.0-rc.104` do not follow this mapping
///
/// The rc-into-the-build-field fix landed in `6bc9d58d` (2026-06-01), first
/// released as **rc.104**. MSIs older than that carry cargo-wix's raw
/// derivation — `0.3.0-rc.N` became `0.3.0.N`, i.e. the same three significant
/// fields `0.3.0` for every rc, which is precisely the collision the fix
/// removed. So this function's answer is **wrong for a pre-rc.104 tag**, and a
/// download of one is refused.
///
/// That is accepted rather than special-cased. The only path that fetches an
/// OLDER release is `updater::pin_version` — crash-loop rollback to
/// `last_known_good_version`, or an operator-chosen `rc:agent.update` tag — and
/// a refusal there folds into `CheckOutcome::Skipped`, which `main.rs` already
/// handles by raising the attention sentinel and leaving the operator to act.
/// So the failure mode is "rollback needs a human", not a wedge.
///
/// Teaching this function the legacy mapping would be worse than that: every
/// pre-rc.104 `0.3.0-rc.*` MSI shares the fields `0.3.0`, so accepting it would
/// make any one of them substitutable for any other — re-creating inside the
/// check the exact ambiguity the release fix removed.
pub fn msi_product_version_for(release: &str) -> Option<String> {
    // Accept a tag or a bare semver — every caller has a tag, and a helper
    // that silently mis-parses `agent-v…` would be a trap.
    let s = release.trim_start_matches("agent-");
    let s = s.trim_start_matches('v');

    let (core, pre) = match s.find('-') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };

    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major: u64 = parts[0].parse().ok()?;
    let minor: u64 = parts[1].parse().ok()?;
    let patch: u64 = parts[2].parse().ok()?;

    match pre {
        // Finals. Two eras, split at 0.4 (the rc train ended with
        // 0.3.0-rc.*):
        //
        //  * 0.4+ — the project ships plain `MAJOR.MINOR.PATCH` releases, so
        //    the PATCH is the build field: 0.4.5 → `0.4.5`. The old
        //    every-final-is-65535 rule would collapse ALL 0.4.x MSIs into
        //    one ProductVersion — Windows MajorUpgrade would never see a
        //    newer version within the minor, and any 0.4.x MSI would verify
        //    as any other (the substitution ambiguity this check exists to
        //    prevent).
        //  * pre-0.4 — legacy rule kept: build = 65535 so a hypothetical
        //    0.3 final outranks every 0.3 rc. No such final was ever
        //    published; the arm exists so historical answers don't change.
        //
        // ⚠️ Rollout note: agents ≤ 0.3.0-rc.485 carry the legacy rule and
        // EXPECT `x.y.65535` for any 0.4.x tag — they refuse a 0.4.x MSI
        // (CheckOutcome::Skipped, attention sentinel) until they are first
        // moved to a transition rc that has this arm. Push the transition
        // rc pinned to any laggard before pointing it at 0.4.
        None if (major, minor) >= (0, 4) => {
            if patch > 65535 {
                return None;
            }
            Some(format!("{major}.{minor}.{patch}"))
        }
        None => Some(format!("{major}.{minor}.65535")),
        Some(pre) => {
            // Only `rc.N`. The workflow's regex is equally strict and fails
            // the build for anything else, so a `-beta.1` release cannot
            // exist to be installed.
            let rc: u64 = pre.strip_prefix("rc.")?.parse().ok()?;
            // Both of these are hard errors in the workflow: a patched rc
            // would collide with a plain rc under this mapping, and the build
            // field cannot hold more than 65535.
            if patch != 0 || rc > 65535 {
                return None;
            }
            Some(format!("{major}.{minor}.{rc}"))
        }
    }
}

/// The three significant fields of an MSI `ProductVersion`. A 4th field is
/// legal and ignored — Windows Installer ignores it for version comparison,
/// and so must we or a legitimately published `0.3.458.0` would be refused.
///
/// Windows-only, like the thing it interprets: off Windows no artifact carries
/// a ProductVersion for this to read. (`msi_product_version_for` above stays
/// cross-platform — it is a pure string mapping, and compiling its tests
/// everywhere is worth more than symmetry.)
#[cfg(windows)]
fn msi_fields(v: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = v.trim().split('.').collect();
    if parts.len() < 3 || parts.len() > 4 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

#[cfg(windows)]
mod win {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
        MSIDBOPEN_READONLY, MSIHANDLE, MsiCloseHandle, MsiDatabaseOpenViewW, MsiOpenDatabaseW,
        MsiRecordGetStringW, MsiViewExecute, MsiViewFetch,
    };

    /// Closes an MSI handle on drop. Every path out of [`product_version`] is
    /// an early return, and a leaked `MSIHANDLE` holds the database file open
    /// — which on the refusal path would leave the staged installer
    /// undeletable, i.e. the rejected payload stranded on disk.
    struct Handle(MSIHANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: a handle this type owns came from a successful Msi*
                // call and is closed exactly once, here.
                unsafe { MsiCloseHandle(self.0) };
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    fn wide_path(p: &Path) -> Vec<u16> {
        OsStr::new(p).encode_wide().chain(once(0)).collect()
    }

    /// Read `ProductVersion` out of an MSI's `Property` table.
    ///
    /// This is a database read, not a package open: no install sequence runs,
    /// no custom action executes, the Windows Installer service is not
    /// involved. That distinction matters here — the file being opened is one
    /// we have not yet decided to trust.
    pub(super) fn product_version(path: &Path) -> Result<String, String> {
        let file = wide_path(path);

        let mut raw: MSIHANDLE = 0;
        // SAFETY: `file` is a NUL-terminated wide string that outlives the
        // call; `MSIDBOPEN_READONLY` is the documented sentinel (not a real
        // pointer) for the persist argument; `raw` is a valid out-param.
        let rc = unsafe { MsiOpenDatabaseW(file.as_ptr(), MSIDBOPEN_READONLY, &mut raw) };
        if rc != ERROR_SUCCESS {
            return Err(format!(
                "MsiOpenDatabaseW failed with {rc} (not a readable MSI?)"
            ));
        }
        let db = Handle(raw);

        let query = wide("SELECT `Value` FROM `Property` WHERE `Property` = 'ProductVersion'");
        let mut raw: MSIHANDLE = 0;
        // SAFETY: `db` is open for the duration; `query` is NUL-terminated and
        // outlives the call; `raw` is a valid out-param.
        let rc = unsafe { MsiDatabaseOpenViewW(db.0, query.as_ptr(), &mut raw) };
        if rc != ERROR_SUCCESS {
            return Err(format!("MsiDatabaseOpenViewW failed with {rc}"));
        }
        let view = Handle(raw);

        // No parameters in the query, so the parameter record is the null
        // handle.
        // SAFETY: `view` is an open view for the duration of the call.
        let rc = unsafe { MsiViewExecute(view.0, 0) };
        if rc != ERROR_SUCCESS {
            return Err(format!("MsiViewExecute failed with {rc}"));
        }

        let mut raw: MSIHANDLE = 0;
        // SAFETY: `view` has been executed; `raw` is a valid out-param.
        let rc = unsafe { MsiViewFetch(view.0, &mut raw) };
        if rc != ERROR_SUCCESS {
            // ERROR_NO_MORE_ITEMS lands here too: an MSI with no
            // ProductVersion row. Refusing is right — we cannot say what
            // release it is.
            return Err(format!(
                "no ProductVersion row in the Property table (MsiViewFetch returned {rc})"
            ));
        }
        let record = Handle(raw);

        // Two-call idiom, MSI flavour: `pcch` is the buffer size in chars
        // EXCLUDING the terminator, and on ERROR_MORE_DATA it comes back as
        // the length needed (also excluding it). A ProductVersion is a dozen
        // characters, so the first buffer is nearly always enough.
        let mut buf = vec![0u16; 64];
        let mut cch = (buf.len() - 1) as u32;
        // SAFETY: `record` is a fetched record; `buf` has `cch + 1` elements
        // so the callee may write its terminator.
        let mut rc = unsafe { MsiRecordGetStringW(record.0, 1, buf.as_mut_ptr(), &mut cch) };
        if rc == ERROR_MORE_DATA {
            buf = vec![0u16; cch as usize + 1];
            cch = (buf.len() - 1) as u32;
            // SAFETY: as above, with a buffer of the size the first call asked
            // for.
            rc = unsafe { MsiRecordGetStringW(record.0, 1, buf.as_mut_ptr(), &mut cch) };
        }
        if rc != ERROR_SUCCESS {
            return Err(format!("MsiRecordGetStringW failed with {rc}"));
        }

        let len = cch as usize;
        if len > buf.len() {
            return Err(format!(
                "MsiRecordGetStringW reported {len} chars into a {} char buffer",
                buf.len()
            ));
        }
        Ok(String::from_utf16_lossy(&buf[..len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn rc_releases_map_the_rc_into_the_build_field() {
        // The live example: what agent-v0.3.0-rc.458 must carry.
        assert_eq!(
            msi_product_version_for("agent-v0.3.0-rc.458").as_deref(),
            Some("0.3.458")
        );
        assert_eq!(
            msi_product_version_for("0.3.0-rc.1").as_deref(),
            Some("0.3.1")
        );
        assert_eq!(
            msi_product_version_for("v1.2.0-rc.65535").as_deref(),
            Some("1.2.65535")
        );
    }

    #[test]
    fn final_releases_take_the_top_of_the_build_field() {
        // Legacy (pre-0.4) rule only: 65535 so a final outranks every rc of
        // that minor. Historical answers must not change.
        assert_eq!(
            msi_product_version_for("agent-v0.3.0").as_deref(),
            Some("0.3.65535")
        );
        assert_eq!(
            msi_product_version_for("0.2.7").as_deref(),
            Some("0.2.65535")
        );
    }

    #[test]
    fn point_four_finals_map_patch_into_the_build_field() {
        // The 0.4+ scheme: PATCH is the build field, so ProductVersions are
        // monotonic WITHIN the minor (0.4.0 < 0.4.1 < …) — MajorUpgrade
        // keeps upgrading and no two 0.4.x MSIs share a version.
        assert_eq!(
            msi_product_version_for("agent-v0.4.0").as_deref(),
            Some("0.4.0")
        );
        assert_eq!(
            msi_product_version_for("agent-v0.4.17").as_deref(),
            Some("0.4.17")
        );
        assert_eq!(msi_product_version_for("v1.2.3").as_deref(), Some("1.2.3"));
        // Build-field ceiling still applies.
        assert_eq!(msi_product_version_for("0.4.65536"), None);
    }

    #[test]
    fn shapes_the_release_workflow_refuses_to_build_map_to_nothing() {
        // Each of these is a hard `::error::` in release-agent.yml, so no such
        // release can exist — a manifest offering one is lying.
        assert_eq!(msi_product_version_for("agent-v0.3.1-rc.5"), None); // patched rc
        assert_eq!(msi_product_version_for("agent-v0.3.0-rc.65536"), None); // over the ceiling
        assert_eq!(msi_product_version_for("agent-v0.3.0-beta.1"), None); // not an rc
        assert_eq!(msi_product_version_for("agent-v0.3"), None); // not three fields
        assert_eq!(msi_product_version_for("agent-v0.3.0.1"), None); // four fields
        assert_eq!(msi_product_version_for(""), None);
        assert_eq!(msi_product_version_for("agent-vNaN.3.0"), None);
    }

    #[test]
    fn pre_rc104_releases_are_mapped_by_todays_rule_and_so_will_be_refused() {
        // Deliberate, documented on `msi_product_version_for`: rc.104
        // (2026-06-01) is where MSIs began carrying MAJOR.MINOR.RC. An older
        // MSI carries `0.3.0.N`, i.e. fields (0, 3, 0), which this expectation
        // cannot match — so a rollback pinning a pre-rc.104 tag is refused and
        // falls through to the operator sentinel.
        //
        // This is locked so nobody "fixes" it by teaching the function the
        // legacy shape: every pre-rc.104 `0.3.0-rc.*` MSI shares the fields
        // `0.3.0`, so accepting that would make any one of them substitutable
        // for any other.
        assert_eq!(
            msi_product_version_for("agent-v0.3.0-rc.90").as_deref(),
            Some("0.3.90")
        );
        assert_ne!(
            msi_product_version_for("agent-v0.3.0-rc.90").as_deref(),
            Some("0.3.0")
        );
    }

    #[test]
    fn a_forged_high_version_still_has_to_produce_a_matching_artifact() {
        // The downgrade attack in the module docs: the manifest claims rc.999,
        // so the artifact must carry 0.3.999. A genuinely-signed rc.458 build
        // carries 0.3.458 and cannot satisfy it.
        assert_eq!(
            msi_product_version_for("agent-v0.3.0-rc.999").as_deref(),
            Some("0.3.999")
        );
        assert_ne!(
            msi_product_version_for("agent-v0.3.0-rc.999"),
            msi_product_version_for("agent-v0.3.0-rc.458")
        );
    }

    #[cfg(windows)]
    #[test]
    fn product_version_fields_ignore_a_fourth_field_and_reject_junk() {
        // Windows Installer ignores the 4th field; refusing `0.3.458.0` would
        // reject a legitimately published MSI.
        assert_eq!(msi_fields("0.3.458"), msi_fields("0.3.458.0"));
        assert_eq!(msi_fields("0.3.458"), Some((0, 3, 458)));
        assert_eq!(msi_fields("  0.3.458  "), Some((0, 3, 458)));
        assert_eq!(msi_fields("0.3"), None);
        assert_eq!(msi_fields("0.3.458.0.1"), None);
        assert_eq!(msi_fields("0.3.x"), None);
    }

    #[test]
    fn formats_with_no_reader_report_unsupported_rather_than_refusing() {
        for name in ["roomlerd.tgz", "roomlerd.zip", "roomlerd.gz", "roomlerd"] {
            let err = verify_artifact_version(&PathBuf::from(name), "agent-v0.4.142")
                .expect_err("no binding is implemented for this format");
            assert!(
                matches!(err, VersionError::Unsupported(_)),
                "{name} should report Unsupported, got {err:?}"
            );
        }
    }

    /// FR-97 P6a — each new reader runs on its own OS, and a file that is not
    /// what its name says is refused there, never waved through; elsewhere
    /// the reader reports Unsupported.
    #[test]
    fn a_deb_pkg_or_tarball_that_is_not_one_is_refused_where_its_reader_runs() {
        let dir = std::env::temp_dir().join(format!("p6a-decoy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A Linux host without dpkg (Fedora) reports Unsupported for a .deb,
        // which is the reader's answer there too.
        let dpkg = std::process::Command::new("dpkg-deb")
            .arg("--version")
            .output()
            .is_ok();
        // FR-117 P1 — the same for the companion's .rpm, wherever rpm runs (a
        // Debian host may well have it, and then its reader must refuse too).
        let rpm = std::process::Command::new("rpm")
            .arg("--version")
            .output()
            .is_ok();
        for (name, runs_here) in [
            ("roomlerd.deb", cfg!(target_os = "linux") && dpkg),
            ("roomler-desktop.rpm", cfg!(target_os = "linux") && rpm),
            ("roomlerd.pkg", cfg!(target_os = "macos")),
            ("roomlerd.tar.gz", cfg!(unix)),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, b"this is not a package").unwrap();
            let err = verify_artifact_version(&path, "agent-v0.4.142")
                .expect_err("a decoy must never verify");
            if runs_here {
                assert!(
                    matches!(err, VersionError::Unreadable(_)),
                    "{name}: expected Unreadable, got {err:?}"
                );
            } else {
                assert!(
                    matches!(err, VersionError::Unsupported(_)),
                    "{name}: expected Unsupported off its OS, got {err:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_release_tag_names_the_version_its_packages_carry() {
        assert_eq!(
            release_version_for("agent-v0.4.142").as_deref(),
            Some("0.4.142")
        );
        assert_eq!(release_version_for("v0.4.7").as_deref(), Some("0.4.7"));
        assert_eq!(release_version_for("0.4.07").as_deref(), Some("0.4.7"));
        assert_eq!(
            release_version_for("agent-v0.3.0-rc.458").as_deref(),
            Some("0.3.0-rc.458")
        );
        for bad in [
            "agent-v0.4",
            "agent-v0.4.x",
            "0.4.1-beta.1",
            "0.4.1-rc.",
            "",
        ] {
            assert_eq!(release_version_for(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_debian_version_reads_back_as_its_release() {
        assert_eq!(deb_upstream_version("0.4.142-1"), "0.4.142");
        assert_eq!(deb_upstream_version("0.4.142"), "0.4.142");
        assert_eq!(deb_upstream_version("1:0.4.142-1"), "0.4.142");
        assert_eq!(deb_upstream_version("0.3.0~rc.458-1"), "0.3.0-rc.458");
        // A pre-release with no revision keeps its `-rc.N`.
        assert_eq!(deb_upstream_version("0.3.0-rc.458"), "0.3.0-rc.458");
        assert_eq!(deb_upstream_version(" 0.4.142-1\n"), "0.4.142");
    }

    /// FR-117 P1 — the companion's `.rpm`: `VERSION` alone (the `-1` is
    /// `RELEASE`, never part of it), and `~` for a pre-release's `-`.
    #[test]
    fn an_rpm_version_reads_back_as_its_release() {
        assert_eq!(rpm_upstream_version("0.4.147"), "0.4.147");
        assert_eq!(rpm_upstream_version(" 0.4.147\n"), "0.4.147");
        assert_eq!(rpm_upstream_version("0.3.0~rc.458"), "0.3.0-rc.458");
        // The binding then compares it with the tag's own semver.
        assert_eq!(
            release_version_for("agent-v0.4.147").as_deref(),
            Some(rpm_upstream_version("0.4.147").as_str())
        );
    }

    #[test]
    fn a_tarballs_top_directory_names_its_release() {
        assert_eq!(
            tarball_version("roomlerd-0.4.142-x86_64-unknown-linux-gnu").as_deref(),
            Some("0.4.142")
        );
        assert_eq!(
            tarball_version("roomlerd-0.4.142-aarch64-unknown-linux-gnu").as_deref(),
            Some("0.4.142")
        );
        assert_eq!(
            tarball_version("roomlerd-0.3.0-rc.458-x86_64-unknown-linux-gnu").as_deref(),
            Some("0.3.0-rc.458")
        );
        for bad in [
            "roomlerd-0.4.142",
            "other-0.4.142-x86_64",
            "roomlerd-x-y",
            "usr",
        ] {
            assert_eq!(tarball_version(bad), None, "{bad:?}");
        }
    }

    /// The real 0.4.142 `PackageInfo`'s start tag: `format-version` and
    /// `generator-version` must not be read as the version.
    #[test]
    fn a_pkg_info_names_the_agents_version_and_nothing_else() {
        let real = r#"<?xml version="1.0" encoding="utf-8"?>
<pkg-info overwrite-permissions="true" relocatable="false" identifier="com.roomler.agent" postinstall-action="none" version="0.4.142" format-version="2" generator-version="InstallCmds-860.14 (24G830)" install-location="/" auth="root">
    <payload numberOfFiles="35" installKBytes="69357"/>"#;
        assert_eq!(pkg_info_version(real).as_deref(), Some("0.4.142"));
        let reordered = r#"<pkg-info format-version="2" generator-version="9" identifier="com.roomler.agent" version="0.4.7">"#;
        assert_eq!(pkg_info_version(reordered).as_deref(), Some("0.4.7"));
        let other = r#"<pkg-info identifier="com.example.other" version="9.9.9">"#;
        assert_eq!(pkg_info_version(other), None, "another package's version");
        assert_eq!(pkg_info_version("<installer-gui-script/>"), None);
    }

    /// FR-97 P6a — a real tarball, built with `tar` as the release workflow
    /// builds one: its own release verifies, a higher claim is the downgrade
    /// and is refused, and a top directory that names no release is refused.
    #[cfg(unix)]
    #[test]
    fn a_real_tarball_binds_to_its_release_and_refuses_another() {
        let base = std::env::temp_dir().join(format!("p6a-tar-{}", std::process::id()));
        let build = |top: &str| -> std::path::PathBuf {
            let root = base.join(top).join("usr/bin");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("roomlerd"), b"x").unwrap();
            let out = base.join(format!("{top}.tar.gz"));
            let st = std::process::Command::new("tar")
                .arg("-czf")
                .arg(&out)
                .arg("-C")
                .arg(&base)
                .arg(top)
                .status()
                .expect("tar");
            assert!(st.success());
            out
        };
        let real = build("roomlerd-0.4.142-x86_64-unknown-linux-gnu");
        assert_eq!(
            verify_artifact_version(&real, "agent-v0.4.142").unwrap(),
            "0.4.142"
        );
        let err = verify_artifact_version(&real, "agent-v0.4.999").unwrap_err();
        assert!(matches!(err, VersionError::Mismatch { .. }), "{err:?}");
        let odd = build("payload");
        let err = verify_artifact_version(&odd, "agent-v0.4.142").unwrap_err();
        assert!(matches!(err, VersionError::Unreadable(_)), "{err:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// FR-97 P6a — a real `.deb`, built with `dpkg-deb --build` where it is
    /// installed (every Debian CI runner): its own release verifies, the
    /// Debian revision is not part of the release, and a higher claim is
    /// refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_deb_binds_to_its_release_and_refuses_another() {
        let base = std::env::temp_dir().join(format!("p6a-deb-{}", std::process::id()));
        let pkg = base.join("pkg");
        std::fs::create_dir_all(pkg.join("DEBIAN")).unwrap();
        std::fs::write(
            pkg.join("DEBIAN/control"),
            "Package: roomlerd\nVersion: 0.4.142-1\nArchitecture: all\n\
             Maintainer: test <test@example.invalid>\nDescription: P6a test\n",
        )
        .unwrap();
        let deb = base.join("roomlerd-0.4.142.deb");
        match std::process::Command::new("dpkg-deb")
            .arg("--build")
            .arg(&pkg)
            .arg(&deb)
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => panic!("dpkg-deb --build: {}", String::from_utf8_lossy(&out.stderr)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipped: no dpkg-deb on this host");
                let _ = std::fs::remove_dir_all(&base);
                return;
            }
            Err(e) => panic!("dpkg-deb: {e}"),
        }
        assert_eq!(
            verify_artifact_version(&deb, "agent-v0.4.142").unwrap(),
            "0.4.142-1"
        );
        let err = verify_artifact_version(&deb, "agent-v0.4.999").unwrap_err();
        assert!(matches!(err, VersionError::Mismatch { .. }), "{err:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn a_file_that_is_not_an_msi_is_refused_not_waved_through() {
        // Naming a payload `.msi` must not be enough to skip the binding: the
        // database open fails and that is a refusal, not an Unsupported.
        let path = std::env::temp_dir().join("roomler-artifact-version-test.msi");
        std::fs::write(&path, b"this is not an MSI").expect("writing the decoy");
        let err = verify_artifact_version(&path, "agent-v0.3.0-rc.458")
            .expect_err("a non-MSI named .msi must not verify");
        let _ = std::fs::remove_file(&path);
        assert!(
            matches!(err, VersionError::Unreadable(_)),
            "expected Unreadable, got {err:?}"
        );
    }

    // RETIRED-NAME-ANCHOR(2): names a PUBLISHED release asset. Filenames are fixed by
    // what is already on GitHub Releases (FR-21 D6) — this is a real downloaded file.
    /// The mapping above is derived from reading `release-agent.yml`, and a
    /// wrong reading of it would not fail loudly — it would make every agent
    /// refuse every update, which looks like nothing happening. So it is
    /// checked against a REAL published MSI rather than against itself.
    ///
    /// `#[ignore]` because it needs an artifact this repo does not carry. Run
    /// it after any change to the workflow's version derivation:
    ///
    /// ```text
    /// gh release download agent-v0.3.0-rc.458 --repo gjovanov/roomler-ai \
    ///   --pattern '*perMachine*.msi' --dir /tmp
    /// ROOMLER_TEST_MSI=/tmp/roomler-agent-0.3.0-rc.458-perMachine-x86_64-pc-windows-msvc.msi \
    /// ROOMLER_TEST_MSI_TAG=agent-v0.3.0-rc.458 \
    ///   cargo test -p roomlerd --lib -- --ignored real_published_msi
    /// ```
    #[cfg(windows)]
    #[test]
    #[ignore = "needs a published MSI; see the doc comment for the invocation"]
    fn real_published_msi_binds_to_its_own_tag_and_refuses_a_forged_one() {
        let Ok(msi) = std::env::var("ROOMLER_TEST_MSI") else {
            panic!("set ROOMLER_TEST_MSI to a downloaded release MSI");
        };
        let tag = std::env::var("ROOMLER_TEST_MSI_TAG")
            .expect("set ROOMLER_TEST_MSI_TAG to the tag that MSI was published under");
        let path = PathBuf::from(&msi);

        let found = verify_artifact_version(&path, &tag)
            .unwrap_or_else(|e| panic!("{tag} should verify against its own MSI, got: {e}"));
        assert_eq!(
            Some(found.as_str()),
            msi_product_version_for(&tag).as_deref(),
            "the MSI's ProductVersion and the mapping disagree — the workflow's \
             derivation has changed and this module has not"
        );

        // The attack itself: same genuinely-signed bytes, a tag claiming a
        // release they are not.
        let forged = "agent-v0.3.0-rc.65000";
        assert_ne!(
            tag, forged,
            "pick a forged tag that differs from the real one"
        );
        let err = verify_artifact_version(&path, forged)
            .expect_err("a forged high version must not accept an older artifact");
        assert!(
            matches!(err, VersionError::Mismatch { .. }),
            "expected Mismatch, got {err:?}"
        );
    }
}
