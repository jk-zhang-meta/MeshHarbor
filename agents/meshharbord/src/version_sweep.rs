// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Sweep obsolete same-flavour roomlerd MSI products.
//!
//! ## Why this exists
//!
//! Field finding 2026-06-01: a host had **eight** perMachine agent
//! versions installed simultaneously (`0.3.0.83`, `.85`, `.91`, `.93`,
//! `.96`, `.97`, `.98`, `.99`). Root cause: the release pipeline passes
//! the full semver (`0.3.0-rc.N`) to `cargo wix --install-version`,
//! which lands the rc number in the **4th** MSI version field
//! (`0.3.0.N`). Windows Installer **ignores the 4th field** for version
//! comparison, so every rc looks like the same `0.3.0` product →
//! WiX `MajorUpgrade` never sees an install as "newer" → it never
//! removes the prior product → they pile up in Add/Remove Programs and
//! on disk.
//!
//! The proper long-term fix is to put the rc in the **3rd** (build)
//! field so MSI versions increase monotonically and `MajorUpgrade`
//! works natively. This module is the complementary runtime cleanup:
//! it removes versions that have *already* piled up, and is a safety
//! net even after the version scheme is fixed.
//!
//! ## What it does
//!
//! Enumerates every installed roomlerd MSI product of the running
//! agent's flavour ([`crate::install_detect::enumerate_installed_products`]),
//! then `msiexec /x`-uninstalls each one **strictly older** than the
//! running version. It never touches:
//!   - the current version (equal → kept — this is the self-protection),
//!   - a newer version (greater → kept — no downgrade-removal),
//!   - the OTHER flavour (a SYSTEM service can't cleanly uninstall a
//!     perUser product, and a user-token task can't uninstall a
//!     perMachine one without UAC — so cross-flavour is out of scope
//!     here; the install wizard's elevated context handles that),
//!   - a product whose `DisplayVersion` is missing/unparseable (kept,
//!     conservatively).
//!
//! ## Privilege
//!
//! `msiexec /x` of a **perMachine** product needs elevation. Run the
//! `sweep-old-versions` CLI from an elevated shell, or rely on the
//! perMachine SCM service (LocalSystem) invoking the sweep — both have
//! the admin token. A non-elevated perUser agent can uninstall its own
//! perUser products without a prompt.
//!
//! The destructive `msiexec /x` path is **not** wired into agent
//! startup yet — it's exposed only via the `sweep-old-versions`
//! subcommand (with `--dry-run`) so it can be validated against a real
//! pile-up before being made automatic.

use anyhow::Result;

use crate::install_detect::{Flavour, InstalledProduct};

/// A comparable MSI version 4-tuple `(major, minor, build, revision)`.
/// MSI itself ignores `revision` for upgrade comparison — that's the
/// bug this module works around — but we compare it explicitly so we
/// CAN tell `0.3.0.97` from `0.3.0.99`.
type MsiVersion = (u64, u64, u64, u64);

/// Parse an MSI `DisplayVersion` string (`a.b.c.d`, dotted, numeric)
/// into a 4-tuple. Missing trailing fields default to 0; a
/// non-numeric field also degrades to 0 so a weird value can't panic.
pub(crate) fn parse_msi_version(v: &str) -> MsiVersion {
    let mut it = v.trim().split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// Map the running agent's Cargo semver to the MSI version tuple the
/// release pipeline assigns it. This MUST mirror release-agent.yml's
/// `msi_version` derivation or the strictly-older comparison misfires:
///
/// * rc build `MAJOR.MINOR.0-rc.N` → MSI `MAJOR.MINOR.N` (the rc in the
///   3rd field — Windows Installer IGNORES the 4th field for upgrade
///   comparison, which is why the pipeline moved it; the workflow hard-
///   fails rc builds with patch != 0).
/// * final `MAJOR.MINOR.PATCH` → MSI `MAJOR.MINOR.65535` (outranks every
///   rc of that minor).
///
/// Pre-scheme-change products registered the legacy `MAJOR.MINOR.0.N`
/// DisplayVersion; those parse to `(maj, min, 0, N)` and correctly rank
/// BELOW any new-scheme runner — old-scheme leftovers are sweepable.
/// The (unbuildable) patched-rc shape falls back to the legacy 4th-field
/// mapping so a weird local build still compares sanely.
pub(crate) fn own_msi_version(semver: &str) -> MsiVersion {
    let (core, pre) = match semver.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (semver, None),
    };
    let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let major = it.next().unwrap_or(0);
    let minor = it.next().unwrap_or(0);
    let patch = it.next().unwrap_or(0);
    match pre.map(parse_rc_number) {
        Some(Some(rc)) if patch == 0 => (major, minor, rc, 0),
        Some(Some(rc)) => (major, minor, patch, rc),
        // Unknown pre-release label: legacy mapping (rc treated as 0).
        Some(None) => (major, minor, patch, 0),
        // Finals, 0.4+ scheme: the pipeline stamps PATCH into the MSI build
        // field (see artifact_version::msi_product_version_for — the eras
        // split at 0.4). Mirroring it here is SELF-PROTECTION-critical: with
        // the legacy 65535 answer a 0.4.5 agent would rank its OWN installed
        // product (0.4.5) below itself (0.4.65535) and the sweep would
        // uninstall the MSI it is running from.
        None if (major, minor) >= (0, 4) => (major, minor, patch, 0),
        None => (major, minor, 65535, 0),
    }
}

/// Parse the `N` out of an `rc.N` / `rc-N` / `rcN` pre-release suffix.
fn parse_rc_number(pre: &str) -> Option<u64> {
    pre.strip_prefix("rc.")
        .or_else(|| pre.strip_prefix("rc-"))
        .or_else(|| pre.strip_prefix("rc"))?
        .parse::<u64>()
        .ok()
}

/// Decide which installed products to uninstall: same flavour as the
/// running agent AND strictly older than it. Pure — no registry, no
/// process spawn — so the policy is unit-tested directly against the
/// real field pile-up.
///
/// Self-protection is structural: the running version compares *equal*
/// to its own installed product, and `<` is strict, so it's never in
/// the result. Newer products (`>`) and version-less products are also
/// excluded.
pub fn plan_obsolete_uninstalls(
    own_semver: &str,
    own_flavour: Flavour,
    products: &[InstalledProduct],
) -> Vec<InstalledProduct> {
    let own = own_msi_version(own_semver);
    products
        .iter()
        .filter(|p| p.flavour == own_flavour)
        .filter(|p| match &p.version {
            Some(v) => parse_msi_version(v) < own,
            None => false,
        })
        .cloned()
        .collect()
}

/// Tally of what the sweep did (or would do, under `--dry-run`).
#[derive(Debug, Default)]
pub struct SweepReport {
    pub removed: Vec<String>,
    pub skipped: Vec<String>,
    pub errors: Vec<String>,
}

impl SweepReport {
    pub fn summary(&self) -> String {
        format!(
            "sweep-old-versions: removed {} skipped {} errors {} ({})",
            self.removed.len(),
            self.skipped.len(),
            self.errors.len(),
            self.removed
                .iter()
                .chain(self.skipped.iter())
                .chain(self.errors.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// Run the obsolete-version sweep. When `dry_run` is true, reports what
/// WOULD be uninstalled without touching anything. Non-Windows hosts
/// are a no-op (no MSI). Best-effort: a single `msiexec /x` failure is
/// recorded as an error but doesn't abort the rest.
pub fn run_sweep(dry_run: bool, flavour_override: Option<Flavour>) -> Result<SweepReport> {
    let mut report = SweepReport::default();

    #[cfg(target_os = "windows")]
    {
        let own_flavour = match flavour_override {
            Some(f) => f,
            None => match crate::updater::current_install_flavour() {
                crate::updater::WindowsInstallFlavour::PerUser => Flavour::PerUser,
                crate::updater::WindowsInstallFlavour::PerMachine => Flavour::PerMachine,
            },
        };
        let own_semver = env!("CARGO_PKG_VERSION");
        let products = crate::install_detect::enumerate_installed_products();
        let obsolete = plan_obsolete_uninstalls(own_semver, own_flavour, &products);

        if obsolete.is_empty() {
            report.skipped.push(format!(
                "no obsolete {own_flavour:?} products older than {own_semver} (found {} installed)",
                products.len()
            ));
            return Ok(report);
        }

        for p in obsolete {
            let label = format!("{} {}", p.product_code, p.version.as_deref().unwrap_or("?"));
            if dry_run {
                report.removed.push(format!("[dry-run] msiexec /x {label}"));
            } else {
                match uninstall_product(&p.product_code) {
                    Ok(()) => report.removed.push(label),
                    Err(e) => report.errors.push(format!("{label}: {e}")),
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (dry_run, flavour_override);
        report
            .skipped
            .push("non-Windows host — no MSI version sweep".to_string());
    }

    Ok(report)
}

/// `msiexec /x {ProductCode} /qn /norestart`. perMachine products need
/// the caller to be elevated. Treats "already gone" (1605) and
/// "success, reboot required" (3010) as success.
#[cfg(target_os = "windows")]
fn uninstall_product(product_code: &str) -> Result<()> {
    use anyhow::{Context, bail};
    let status = std::process::Command::new("msiexec")
        .args(["/x", product_code, "/qn", "/norestart"])
        .status()
        .context("spawning msiexec /x")?;
    match status.code() {
        // 0 = success; 3010 = success, reboot required; 1605 = this
        // product is not installed (already removed — idempotent OK).
        Some(0) | Some(3010) | Some(1605) => Ok(()),
        other => bail!("msiexec /x exited {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_detect::{Flavour, InstalledProduct};

    fn prod(flavour: Flavour, version: &str, pc: &str) -> InstalledProduct {
        InstalledProduct {
            flavour,
            product_code: pc.to_string(),
            version: Some(version.to_string()),
        }
    }

    #[test]
    fn parse_msi_version_reads_four_fields() {
        assert_eq!(parse_msi_version("0.3.0.99"), (0, 3, 0, 99));
        assert_eq!(parse_msi_version("0.3.0"), (0, 3, 0, 0));
        assert_eq!(parse_msi_version("1.2.3.4"), (1, 2, 3, 4));
        // Garbage degrades to 0 rather than panicking.
        assert_eq!(parse_msi_version("0.3.x.7"), (0, 3, 0, 7));
    }

    #[test]
    fn own_version_mirrors_the_pipeline_msi_mapping() {
        // rc → MAJOR.MINOR.RC (3rd field), matching release-agent.yml.
        assert_eq!(own_msi_version("0.3.0-rc.99"), (0, 3, 99, 0));
        assert_eq!(own_msi_version("0.3.0-rc.254"), (0, 3, 254, 0));
        // Final release → MAJOR.MINOR.65535 (outranks every rc).
        assert_eq!(own_msi_version("0.3.0"), (0, 3, 65535, 0));
        // The own-mapping and the DisplayVersion parse agree, so an
        // installed product's tuple equals the running tuple → kept.
        assert_eq!(own_msi_version("0.3.0-rc.99"), parse_msi_version("0.3.99"));
        // Legacy old-scheme products (rc in the 4th field) rank below
        // any new-scheme runner — sweepable leftovers, by design.
        assert!(parse_msi_version("0.3.0.99") < own_msi_version("0.3.0-rc.99"));
    }

    #[test]
    fn point_four_finals_mirror_the_patch_in_build_field_scheme() {
        // 0.4+ finals: PATCH is the build field (artifact_version's era
        // split). SELF-PROTECTION: the running 0.4.5 must compare EQUAL to
        // its own installed product or the sweep uninstalls itself.
        assert_eq!(own_msi_version("0.4.5"), (0, 4, 5, 0));
        assert_eq!(own_msi_version("0.4.5"), parse_msi_version("0.4.5"));
        // Monotonic within the minor, and every rc-era install ranks below.
        assert!(own_msi_version("0.4.1") < own_msi_version("0.4.2"));
        assert!(own_msi_version("0.3.0-rc.482") < own_msi_version("0.4.0"));
        // Pre-0.4 finals keep the legacy 65535 answer (historical).
        assert_eq!(own_msi_version("0.3.0"), (0, 3, 65535, 0));
    }

    /// The exact field pile-up: eight perMachine versions, running
    /// rc.99. The sweep must target the seven older ones and KEEP the
    /// running `0.3.0.99` (self-protection) — proving the bug's fix.
    #[test]
    fn sweep_removes_seven_older_permachine_keeps_self() {
        let products = vec![
            prod(
                Flavour::PerMachine,
                "0.3.0.97",
                "{10428E78-4BA3-434A-B0B4-64D8C4870B04}",
            ),
            prod(
                Flavour::PerMachine,
                "0.3.0.99",
                "{1317F249-CDA7-4372-92B6-883239BCB780}",
            ),
            prod(
                Flavour::PerMachine,
                "0.3.0.85",
                "{2D9E123E-79A0-4483-8201-22002C6AD4E8}",
            ),
            prod(
                Flavour::PerMachine,
                "0.3.0.91",
                "{48BCFFF7-1AD9-45DF-9BF3-E54F81DB2B85}",
            ),
            prod(
                Flavour::PerMachine,
                "0.3.0.93",
                "{58E26383-FC3E-4242-8948-1AA36C63643D}",
            ),
            prod(
                Flavour::PerMachine,
                "0.3.0.98",
                "{C0C3491C-6D7B-4BC4-912A-C949F413DB7A}",
            ),
            prod(
                Flavour::PerMachine,
                "0.3.0.83",
                "{D087F520-0E39-4203-B2DD-42905C550185}",
            ),
            prod(
                Flavour::PerMachine,
                "0.3.0.96",
                "{F1F85607-AB13-4EA9-814F-32370D1BF925}",
            ),
        ];
        let plan = plan_obsolete_uninstalls("0.3.0-rc.99", Flavour::PerMachine, &products);
        // Under the MAJOR.MINOR.RC scheme every legacy-scheme product —
        // including the legacy registration of rc.99 itself — ranks
        // below the running build and is swept. Self-protection lives
        // on the NEW-scheme DisplayVersion, covered below.
        assert_eq!(plan.len(), 8, "all legacy-scheme versions targeted");
        // Spot-check a couple that MUST be swept.
        assert!(
            plan.iter()
                .any(|p| p.version.as_deref() == Some("0.3.0.83"))
        );
        assert!(
            plan.iter()
                .any(|p| p.version.as_deref() == Some("0.3.0.98"))
        );
    }

    /// Self-protection under the current pipeline scheme: the running
    /// build's own product registers DisplayVersion `MAJOR.MINOR.RC`
    /// and compares equal → never planned.
    #[test]
    fn keeps_own_new_scheme_registration() {
        let products = vec![
            prod(Flavour::PerMachine, "0.3.99", "{SELF-NEW}"),
            prod(Flavour::PerMachine, "0.3.98", "{OLDER-NEW}"),
            prod(Flavour::PerMachine, "0.3.0.99", "{SELF-LEGACY}"),
        ];
        let plan = plan_obsolete_uninstalls("0.3.0-rc.99", Flavour::PerMachine, &products);
        assert_eq!(plan.len(), 2);
        assert!(
            plan.iter().all(|p| p.product_code != "{SELF-NEW}"),
            "the running version's own product must never be planned"
        );
    }

    #[test]
    fn never_removes_a_newer_version() {
        // Running rc.99, but somehow rc.100 is also installed — the
        // sweep must not downgrade-remove the newer one.
        let products = vec![
            prod(Flavour::PerMachine, "0.3.99", "{AAAA}"),
            prod(Flavour::PerMachine, "0.3.100", "{BBBB}"),
        ];
        let plan = plan_obsolete_uninstalls("0.3.0-rc.99", Flavour::PerMachine, &products);
        assert!(plan.is_empty(), "neither self nor a newer build is swept");
    }

    #[test]
    fn ignores_the_other_flavour() {
        // Running perMachine; perUser leftovers are out of scope (a
        // SYSTEM service can't cleanly uninstall a per-user product).
        let products = vec![
            prod(Flavour::PerUser, "0.3.83", "{USER-OLD}"),
            prod(Flavour::PerMachine, "0.3.83", "{MACH-OLD}"),
            prod(Flavour::PerMachine, "0.3.99", "{MACH-SELF}"),
        ];
        let plan = plan_obsolete_uninstalls("0.3.0-rc.99", Flavour::PerMachine, &products);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].product_code, "{MACH-OLD}");
    }

    #[test]
    fn version_less_product_is_kept_conservatively() {
        let products = vec![InstalledProduct {
            flavour: Flavour::PerMachine,
            product_code: "{NO-VER}".to_string(),
            version: None,
        }];
        let plan = plan_obsolete_uninstalls("0.3.0-rc.99", Flavour::PerMachine, &products);
        assert!(
            plan.is_empty(),
            "a product with no DisplayVersion is never swept"
        );
    }

    #[test]
    fn empty_inventory_plans_nothing() {
        let plan = plan_obsolete_uninstalls("0.3.0-rc.99", Flavour::PerMachine, &[]);
        assert!(plan.is_empty());
    }
}
