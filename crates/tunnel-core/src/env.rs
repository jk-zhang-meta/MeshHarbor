// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// RETIRED-NAME-ANCHOR-BEGIN
// This whole module IS the env-prefix fallback chain. Every occurrence of a
// retired name in it is a prefix the chain must keep honouring
// (`ROOMLER_AGENT_`, `ROOMLER_NODE_`), its documentation, or a test that sets one
// to prove the field keeps working.
// INVARIANT: if you add a retired name here that is NOT part of that chain, that
// is a bug, not a new exemption. docs/fr/FR-21
//! Roomler node env-var reads with legacy-prefix fallback.
//!
//! The controlled-host daemon is being renamed `roomler-agent` → `roomlerd`
//! (the unified "device / node" model — see the unification plan). Operators
//! set tuning vars in the Windows service Environment block (e.g.
//! `ROOMLER_AGENT_OVERLAY_DIRECT`), and those MUST keep working across the
//! rename: silently dropping a prefix is the MajorUpgrade-drops-env-vars class
//! of bug that already bit the fleet. So every node env read goes through
//! [`node_env`], which tries `ROOMLERD_<SUFFIX>` first, then the interim
//! `ROOMLER_NODE_<SUFFIX>`, then the original `ROOMLER_AGENT_<SUFFIX>`.
//!
//! FR-21 P3 (decision D1) makes `ROOMLERD_*` the spelling new code and docs
//! use — it matches the binary. Both older prefixes stay readable
//! INDEFINITELY: they are a contract with hosts already in the field, and the
//! cost of honouring them is one `or_else` arm. Adding a preferred prefix is a
//! change to this one function, never to the 166 call sites, because every
//! caller passes a bare SUFFIX.
//!
//! S2 adds a THIRD source: config-backed fallbacks. The daemon registers the
//! operator-grade knobs from its `config.toml` once at startup
//! ([`register_config_fallbacks`]); precedence is env (either prefix) >
//! config > built-in default. Debug/media dials stay env-only.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::OnceLock;

/// S2 — config-backed fallback values (suffix → env-equivalent string),
/// registered once by the daemon right after its config loads and BEFORE any
/// runtime that reads these knobs spawns. Consulted by [`node_env`] AFTER
/// both env prefixes, so an operator env var always overrides config, and
/// config overrides the built-in default. One daemon per process makes the
/// process-global honest; re-registration is a no-op (`OnceLock`). Values use
/// the same strings the env parsers accept (`"1"`/`"0"` for the bool knobs).
static CONFIG_FALLBACKS: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Register the config-backed fallback map. Call once, before spawning the
/// overlay/tunnel runtimes; later calls are ignored.
pub fn register_config_fallbacks(map: HashMap<String, String>) {
    let _ = CONFIG_FALLBACKS.set(map);
}

fn config_fallback(suffix: &str) -> Option<String> {
    CONFIG_FALLBACKS.get().and_then(|m| m.get(suffix).cloned())
}

/// The registered config fallbacks as REAL env-var pairs for a child process.
///
/// The registry is process-local, so a child this daemon spawns — the caps
/// probe (`roomlerd caps-probe`, rc.433) — inherits the environment but NOT
/// the registry, and every `node_env` read inside it falls straight to the
/// built-in default. Field 2026-08-29 (FR-19 P4c): `relay_server_enabled =
/// true` in `config.toml` started the relay server in-process, while the
/// hello's capability list — computed in the probe child — never carried
/// `relay-server`, so the server could only ever answer `no_relay`.
///
/// Each pair is resolved through [`node_env`], i.e. with the full precedence
/// (an operator env var still wins over config), and spelled with the
/// current prefix so the child reads it on the first arm of the chain.
pub fn config_fallbacks_for_child() -> Vec<(String, String)> {
    let Some(map) = CONFIG_FALLBACKS.get() else {
        return Vec::new();
    };
    map.keys()
        .filter_map(|suffix| node_env(suffix).map(|v| (format!("ROOMLERD_{suffix}"), v)))
        .collect()
}

/// Test-only helpers for the env chain. Compiled unconditionally because the
/// tests that need them live in OTHER crates — `roomlerd`'s lib AND its bin —
/// and `#[cfg(test)]` does not cross a crate boundary.
///
/// Why this exists rather than each test hand-rolling `remove_var`: [`node_env`]
/// reads THREE prefixes, so clearing one and asserting a default is not
/// hermetic. That was not hypothetical — it was true of every env test in the
/// agent (14 suffixes across 8 files), in both directions: some cleared only
/// the retired name and so proved nothing about the current one, others cleared
/// only the current name and would have read a stale alias.
#[doc(hidden)]
pub mod test_env {
    use super::{PREFIXES, RETIRED_PREFIXES};

    /// Remove EVERY spelling of `suffix` from the environment.
    ///
    /// # Safety
    /// `remove_var` is unsafe in Rust 2024: a concurrent read in another thread
    /// races it. Callers must serialise tests touching the same suffix.
    pub unsafe fn clear(suffix: &str) {
        for p in PREFIXES.iter().chain(RETIRED_PREFIXES.iter()) {
            unsafe { std::env::remove_var(format!("{p}{suffix}")) };
        }
    }

    /// Set `suffix` under `prefix` ONLY, clearing the other spellings first, so
    /// the value under test is the only one the chain can see.
    ///
    /// # Safety
    /// See [`clear`].
    pub unsafe fn set_as(prefix: &str, suffix: &str, value: impl AsRef<str>) {
        assert!(
            PREFIXES.contains(&prefix),
            "{prefix} is not one of the node_env prefixes"
        );
        unsafe { clear(suffix) };
        unsafe { std::env::set_var(format!("{prefix}{suffix}"), value.as_ref()) };
    }

    /// Set `suffix` under the CURRENT prefix, clearing the others.
    ///
    /// # Safety
    /// See [`clear`].
    pub unsafe fn set(suffix: &str, value: impl AsRef<str>) {
        unsafe { set_as(PREFIXES[0], suffix, value) };
    }

    /// Snapshots every spelling of `suffix` and restores them on drop, so a
    /// test cannot leak env state into whatever runs next — including when it
    /// fails, which a hand-written restore at the end of the body never covers.
    pub struct Saved {
        suffix: String,
        prior: Vec<(String, Option<String>)>,
    }

    impl Saved {
        /// Snapshot, then clear — the hermetic starting point.
        pub fn cleared(suffix: &str) -> Self {
            let prior = PREFIXES
                .iter()
                .map(|p| {
                    let name = format!("{p}{suffix}");
                    let v = std::env::var(&name).ok();
                    (name, v)
                })
                .collect();
            unsafe { clear(suffix) };
            Self {
                suffix: suffix.to_string(),
                prior,
            }
        }

        /// The suffix this guard restores.
        pub fn suffix(&self) -> &str {
            &self.suffix
        }
    }

    impl Drop for Saved {
        fn drop(&mut self) {
            for (name, v) in &self.prior {
                match v {
                    Some(v) => unsafe { std::env::set_var(name, v) },
                    None => unsafe { std::env::remove_var(name) },
                }
            }
        }
    }
}

// RETIRED-NAME-ANCHOR(4): arms 2 and 3 are the reason a rename here costs
// nothing in the field. Both spellings are set on real hosts today — mars,
// jupiter and zeus each carry four `ROOMLER_AGENT_*` entries in an
// operator-authored `/etc/systemd/system/meshharbord.service.d/` drop-in, which a
// package upgrade never rewrites. Dropping either arm silently un-configures
// those hosts: the daemon starts fine and simply ignores what it was told.
/// Read a Roomler node env var by suffix. Precedence, highest first:
///
///   1. `ROOMLERD_<suffix>`      — the current spelling (FR-21 P3, decision D1)
///   2. `ROOMLER_NODE_<suffix>`  — the previous "new" spelling, still honoured
///   3. `ROOMLER_AGENT_<suffix>` — the original, still honoured
///   4. a registered config-backed fallback (S2)
///
/// Returns `None` if none is set (or the env value isn't valid Unicode).
///
/// Every knob in the daemon reads through here and passes a SUFFIX, never a
/// full name, so adding a preferred prefix is one arm in this chain rather than
/// an edit at 166 call sites.
///
/// See docs/fr/FR-21.
/// The env-var prefixes [`node_env`] READS, most current first.
///
/// One list, because three things must agree about it: both readers below and
/// every test that clears a variable. A test that clears one spelling and
/// asserts a default is not hermetic — an inherited value under another
/// spelling silently decides the assertion — so `test_env` clears from this
/// list AND from [`RETIRED_PREFIXES`].
/// MeshHarbor: `MESHHARBORD_` is the spelling to use; the Roomler ones still read.
pub const PREFIXES: [&str; 3] = ["MESHHARBORD_", "ROOMLERD_", "ROOMLER_NODE_"];

/// Prefixes that are no longer READ, but are still LOOKED FOR.
///
/// FR-46 P2b removed `ROOMLER_AGENT_` from the read chain. Dropping it outright
/// would have made a host that still sets one start fine and silently ignore
/// what it was told — the exact failure this program spent two sweeps proving
/// is real (three cluster nodes in operator-authored systemd drop-ins, and a
/// Windows host with two values machine-wide in the registry, none of it in any
/// runbook).
///
/// So the prefix is retired from the chain and kept in the SEARCH: every host
/// that sets one is told, loudly, at startup and on `meshharbor status`, naming
/// the current spelling to use. A dormant device that wakes up months from now
/// announces itself instead of quietly losing a setting.
///
/// ⚠️ This is not a compatibility arm and must never grow into one. Nothing
/// here is ever returned to a caller.
pub const RETIRED_PREFIXES: [&str; 1] = ["ROOMLER_AGENT_"];

/// Full names of retired-prefix variables PRESENT in this process's
/// environment, sorted. Ignored by every reader — reported so that being
/// ignored is visible rather than silent.
///
/// ⚠️ Distinct from [`legacy_env_uses`], and the two must not be folded
/// together: that one is "a non-current prefix was READ", this one is "a
/// retired prefix EXISTS and was not". They lead to different actions —
/// rename the variable, versus nothing at all.
pub fn retired_env_present() -> Vec<String> {
    let mut out: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| RETIRED_PREFIXES.iter().any(|p| k.starts_with(p)))
        .collect();
    out.sort();
    out
}

/// Warn once per retired variable found in the environment.
///
/// Called at daemon startup. The message names the CURRENT spelling, because
/// "this is ignored" without "set that instead" leaves the operator to work out
/// the mapping from a prefix they cannot see.
pub fn warn_on_retired_env() {
    for name in retired_env_present() {
        let current = RETIRED_PREFIXES
            .iter()
            .find(|p| name.starts_with(*p))
            .map(|p| format!("{}{}", PREFIXES[0], &name[p.len()..]))
            .unwrap_or_else(|| name.clone());
        tracing::warn!(
            var = %name,
            current = %current,
            "env: a RETIRED variable name is set and is NOT read — rename it to the current one"
        );
    }
}

pub fn node_env(suffix: &str) -> Option<String> {
    PREFIXES
        .iter()
        .find_map(|p| {
            let v = std::env::var(format!("{p}{suffix}")).ok()?;
            note_legacy_use(p, suffix);
            Some(v)
        })
        .or_else(|| config_fallback(suffix))
}

/// Parse a boolean gate the way every overlay kill-switch does. With
/// `default = true` (default-ON keys) anything except `0`/`false`/`no`/`off`
/// keeps the gate on; with `default = false` (opt-in keys) only
/// `1`/`true`/`yes`/`on` turns it on. Reads via [`node_env`] (both prefixes +
/// config fallback). Extracted in rc.279 — the fourth hand-rolled copy of
/// this parser was about to land; new gates use this, existing gates keep
/// their in-place parsers until touched.
pub fn flag(suffix: &str, default: bool) -> bool {
    match node_env(suffix) {
        Some(v) => {
            let t = v.trim();
            if default {
                !(t.eq_ignore_ascii_case("0")
                    || t.eq_ignore_ascii_case("false")
                    || t.eq_ignore_ascii_case("no")
                    || t.eq_ignore_ascii_case("off"))
            } else {
                t.eq_ignore_ascii_case("1")
                    || t.eq_ignore_ascii_case("true")
                    || t.eq_ignore_ascii_case("yes")
                    || t.eq_ignore_ascii_case("on")
            }
        }
        None => default,
    }
}

/// OsString twin of [`node_env`] for reads that must tolerate non-Unicode
/// values (`std::env::var_os` semantics). Same precedence, and it MUST stay the
/// same: two readers of one knob that disagree about which prefix wins is a
/// bug nobody would think to look for.
///
// RETIRED-NAME-ANCHOR(5): the legacy arms, as in [`node_env`]. See docs/fr/FR-21.
pub fn node_env_os(suffix: &str) -> Option<std::ffi::OsString> {
    PREFIXES
        .iter()
        .find_map(|p| {
            let v = std::env::var_os(format!("{p}{suffix}"))?;
            note_legacy_use(p, suffix);
            Some(v)
        })
        .or_else(|| config_fallback(suffix).map(std::ffi::OsString::from))
}

/// Warn ONCE per (prefix, suffix) per process when a value was resolved through
/// a retired spelling.
///
/// Why it is worth the code: the aliases are a compatibility promise, and
/// nothing currently says which hosts still rely on them. Without this, the
/// only way to know whether a spelling is safe to drop is to grep the fleet's
/// unit files by hand — so the aliases would be kept forever out of caution.
/// A host that logs nothing here is a host the alias could be removed from.
///
/// The hot path is unaffected: `relay_max_bps` and friends re-read per frame,
/// and a hit on the CURRENT prefix returns before any lock is taken. Only a
/// legacy hit — rare, and only on hosts that still set one — reaches the set.
fn note_legacy_use(prefix: &str, suffix: &str) {
    if legacy_use_is_new(prefix, suffix) {
        tracing::warn!(
            var = %format!("{prefix}{suffix}"),
            current = %format!("{}{}", PREFIXES[0], suffix),
            "env: value read through a RETIRED variable name; set the current one instead"
        );
    }
}

/// Every retired-prefix variable this process has actually READ, deduped.
///
/// Hoisted out of [`legacy_use_is_new`] by FR-46 (#1051) so the set can be
/// READ, not only warned about. The warning alone was write-only: it fires once
/// near startup, so a `meshharbor logs` tail on a long-running daemon cannot find
/// it, and answering "does any host still depend on a retired name?" meant
/// sweeping env vars and registries by hand — which under-reported twice.
static LEGACY_SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn legacy_seen() -> &'static Mutex<HashSet<String>> {
    LEGACY_SEEN.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Full names (`PREFIX` + `SUFFIX`) this process has read through a RETIRED
/// prefix, sorted. Surfaced on `NodeStatus` so the question can be asked of a
/// running daemon instead of guessed at from the outside.
///
/// ⚠️ **Empty means "nothing retired has been read YET", not "this host sets
/// none."** Knobs are read lazily — some only on a code path that has not run —
/// so an empty list is weak evidence of absence and strong evidence of
/// presence. It is the same asymmetry as `ssh_activity`: the positive is
/// authoritative, the negative is not.
pub fn legacy_env_uses() -> Vec<String> {
    let Ok(set) = legacy_seen().lock() else {
        return Vec::new();
    };
    let mut out: Vec<String> = set.iter().cloned().collect();
    out.sort();
    out
}

/// Record `(prefix, suffix)` and report whether it had NOT been seen before.
///
/// Split out so the once-per-variable rule is testable without capturing
/// tracing output — that would test the subscriber, not this decision.
fn legacy_use_is_new(prefix: &str, suffix: &str) -> bool {
    if prefix == PREFIXES[0] {
        // The current spelling is not a legacy use, and returning here keeps
        // the hot path lock-free: `relay_max_bps` and friends re-read per frame.
        return false;
    }
    let Ok(mut set) = legacy_seen().lock() else {
        // A poisoned set must never take the daemon down over a warning, and
        // must not spam either: treat it as already-seen.
        return false;
    };
    set.insert(format!("{prefix}{suffix}"))
}

#[cfg(test)]
mod tests {
    /// The one registration this test binary makes. The registry is a
    /// process-wide `OnceLock`, so two tests that each register their own map
    /// are mutually exclusive by construction — whichever runs first wins and
    /// the other's expectation is dead. Every test that needs the registry
    /// calls THIS, so the winner is irrelevant: the map is the same superset
    /// whoever installs it.
    fn register_test_registry() {
        let mut m = HashMap::new();
        m.insert(S_CFG.to_string(), "from-config".to_string());
        m.insert("CAPSFIX_TEST_ONLY".to_string(), "1".to_string());
        register_config_fallbacks(m);
    }

    /// The registry never reaches a child process by itself; the export must
    /// carry every registered suffix that resolves, spelled with the current
    /// prefix so the child reads it on the first arm of the precedence chain,
    /// and nothing that is not registered. Values are asserted only for the
    /// suffix no other test touches — `S_CFG` is toggled through env by a
    /// concurrently running test, so its value is deliberately not compared.
    #[test]
    fn config_fallbacks_are_exported_to_children_as_prefixed_env_pairs() {
        register_test_registry();
        let registry = CONFIG_FALLBACKS.get().expect("registered above");
        let pairs = config_fallbacks_for_child();
        assert!(
            pairs.contains(&("ROOMLERD_CAPSFIX_TEST_ONLY".to_string(), "1".to_string())),
            "{pairs:?}"
        );
        for (k, _) in &pairs {
            let suffix = k
                .strip_prefix("ROOMLERD_")
                .unwrap_or_else(|| panic!("exported name lacks the current prefix: {k}"));
            assert!(registry.contains_key(suffix), "unregistered export: {k}");
        }
    }

    // ── FR-21 P3 (D1): ROOMLERD_* wins, and NOTHING in the field stops working ──

    const S3: &str = "UNIFY_TEST_P3_PRECEDENCE";

    fn dk() -> String {
        format!("ROOMLERD_{S3}")
    }
    fn nk3() -> String {
        format!("ROOMLER_NODE_{S3}")
    }
    fn ak3() -> String {
        format!("ROOMLER_AGENT_{S3}")
    }

    #[test]
    fn roomlerd_prefix_wins_and_the_retired_spelling_is_ignored_but_reported() {
        // SAFETY (edition 2024): suffix is unique to this test, no concurrency.
        unsafe {
            std::env::remove_var(dk());
            std::env::remove_var(nk3());
            std::env::remove_var(ak3());
        }
        assert_eq!(node_env(S3), None, "none set -> None");

        // FR-46 P2b: the ORIGINAL spelling is no longer read. It used to be —
        // this test asserted the opposite until every host that set one had
        // been migrated, which took two sweeps to establish (systemd drop-ins
        // on three cluster nodes, and two values machine-wide in a Windows
        // registry that no unit-file search would ever have found).
        unsafe { std::env::set_var(ak3(), "from-agent") };
        assert_eq!(
            node_env(S3),
            None,
            "the retired prefix must NOT be read any more"
        );

        // ...but it must not vanish silently either. Being ignored is only safe
        // because it is REPORTED: a host that still sets one says so instead of
        // quietly losing the setting.
        assert!(
            super::retired_env_present().contains(&ak3()),
            "a retired variable that is set must be reported as present"
        );

        // The interim spelling is still read.
        unsafe { std::env::set_var(nk3(), "from-node") };
        assert_eq!(node_env(S3).as_deref(), Some("from-node"));

        // And the current spelling outranks it.
        unsafe { std::env::set_var(dk(), "from-roomlerd") };
        assert_eq!(node_env(S3).as_deref(), Some("from-roomlerd"));

        // Removing the winner falls back one step — and then to None, NOT to
        // the retired spelling, which is still set at this point.
        unsafe { std::env::remove_var(dk()) };
        assert_eq!(node_env(S3).as_deref(), Some("from-node"));
        unsafe { std::env::remove_var(nk3()) };
        assert_eq!(
            node_env(S3),
            None,
            "the chain must end above the retired prefix, not fall into it"
        );

        unsafe { std::env::remove_var(ak3()) };
        assert_eq!(node_env(S3), None);
        assert!(
            !super::retired_env_present().contains(&ak3()),
            "an unset retired variable must not be reported"
        );
    }

    #[test]
    fn the_os_twin_agrees_with_node_env_on_precedence() {
        // Two readers of one knob that disagree about which prefix wins is a
        // bug nobody would think to look for, so it is asserted rather than
        // assumed.
        const S4: &str = "UNIFY_TEST_P3_OS_TWIN";
        unsafe {
            std::env::set_var(format!("ROOMLER_AGENT_{S4}"), "agent");
            std::env::set_var(format!("ROOMLER_NODE_{S4}"), "node");
            std::env::set_var(format!("ROOMLERD_{S4}"), "roomlerd");
        }
        assert_eq!(node_env(S4).as_deref(), Some("roomlerd"));
        assert_eq!(
            node_env_os(S4).as_deref(),
            Some(std::ffi::OsStr::new("roomlerd"))
        );
        unsafe {
            std::env::remove_var(format!("ROOMLERD_{S4}"));
        }
        assert_eq!(node_env(S4).as_deref(), Some("node"));
        assert_eq!(
            node_env_os(S4).as_deref(),
            Some(std::ffi::OsStr::new("node"))
        );
        unsafe {
            std::env::remove_var(format!("ROOMLER_NODE_{S4}"));
            std::env::remove_var(format!("ROOMLER_AGENT_{S4}"));
        }
    }

    use super::*;

    // A unique suffix no other code/test touches, so setting these process-wide
    // env vars can't race a parallel test. All mutations happen inside the one
    // test with no `.await` between them.
    const S: &str = "UNIFY_TEST_DUALREAD";

    fn nk() -> String {
        format!("ROOMLER_NODE_{S}")
    }
    fn dks() -> String {
        format!("ROOMLERD_{S}")
    }

    // Unique suffix for the S2 config-fallback test (no other code touches it).
    const S_CFG: &str = "UNIFY_TEST_CFGFALLBACK";

    #[test]
    fn config_fallback_loses_to_env_and_beats_unset() {
        // Register once for the whole process — includes a suffix no env var
        // will ever set, plus the one this test also sets via env.
        register_test_registry();

        // No env set → the registered fallback answers.
        assert_eq!(node_env(S_CFG).as_deref(), Some("from-config"));
        assert_eq!(
            node_env_os(S_CFG).as_deref(),
            Some(std::ffi::OsStr::new("from-config"))
        );

        // Env (the older prefix) beats the registered fallback.
        // SAFETY (edition 2024): unique suffix, no concurrent access.
        unsafe { std::env::set_var(format!("ROOMLER_NODE_{S_CFG}"), "from-env") };
        assert_eq!(node_env(S_CFG).as_deref(), Some("from-env"));
        unsafe { std::env::remove_var(format!("ROOMLER_NODE_{S_CFG}")) };
        assert_eq!(node_env(S_CFG).as_deref(), Some("from-config"));

        // A suffix in neither env nor the map stays None.
        assert_eq!(node_env("UNIFY_TEST_CFGFALLBACK_UNSET"), None);
    }

    #[test]
    fn prefers_roomlerd_then_falls_back_to_node_then_none() {
        // FR-46 P2b: the chain is two prefixes now, so the dual-read this
        // asserts is ROOMLERD_ over ROOMLER_NODE_. The retired third arm has
        // its own test, which checks it is IGNORED and REPORTED.
        //
        // SAFETY (edition 2024): set/remove_var are `unsafe`; safe here because
        // the suffix is unique to this test and there is no concurrent access.
        unsafe {
            std::env::remove_var(nk());
            std::env::remove_var(dks());
        }
        assert_eq!(node_env(S), None, "unset → None");

        unsafe { std::env::set_var(nk(), "legacy") };
        assert_eq!(
            node_env(S).as_deref(),
            Some("legacy"),
            "ROOMLER_NODE_* is still honoured"
        );

        unsafe { std::env::set_var(dks(), "new") };
        assert_eq!(
            node_env(S).as_deref(),
            Some("new"),
            "ROOMLERD_* wins when both are set"
        );

        unsafe { std::env::remove_var(dks()) };
        assert_eq!(
            node_env(S).as_deref(),
            Some("legacy"),
            "falls back to the older spelling after the new var is removed"
        );

        unsafe {
            std::env::remove_var(nk());
            std::env::remove_var(dks());
        }
    }

    #[test]
    fn flag_parses_default_on_and_opt_in() {
        // Unique suffixes; all mutations inside this one test (no races).
        const ON: &str = "UNIFY_TEST_FLAG_DEFAULT_ON";
        const OPT: &str = "UNIFY_TEST_FLAG_OPT_IN";

        // default-ON: unset → true; only an explicit falsy turns it off.
        assert!(flag(ON, true));
        // SAFETY (edition 2024): unique suffix, no concurrent access.
        unsafe { std::env::set_var(format!("ROOMLER_NODE_{ON}"), "off") };
        assert!(!flag(ON, true));
        unsafe { std::env::set_var(format!("ROOMLER_NODE_{ON}"), "weird") };
        assert!(
            flag(ON, true),
            "unrecognised value keeps a default-ON gate on"
        );
        unsafe { std::env::remove_var(format!("ROOMLER_NODE_{ON}")) };

        // opt-in: unset → false; only an explicit truthy turns it on (the
        // the older ROOMLER_NODE_ prefix must work too).
        assert!(!flag(OPT, false));
        unsafe { std::env::set_var(format!("ROOMLER_NODE_{OPT}"), "YES") };
        assert!(flag(OPT, false));
        unsafe { std::env::set_var(format!("ROOMLER_NODE_{OPT}"), "weird") };
        assert!(
            !flag(OPT, false),
            "unrecognised value keeps an opt-in gate off"
        );
        unsafe { std::env::remove_var(format!("ROOMLER_NODE_{OPT}")) };
    }

    // A distinct unique suffix so this test can't race the String-variant one.
    const S_OS: &str = "UNIFY_TEST_DUALREAD_OS";

    fn nk_os() -> String {
        format!("ROOMLER_NODE_{S_OS}")
    }
    fn dks_os() -> String {
        format!("ROOMLERD_{S_OS}")
    }

    #[test]
    fn os_prefers_roomlerd_then_falls_back_to_node_then_none() {
        // The OsString twin of the string reader, on the two prefixes the chain
        // still has after FR-46 P2b. Kept in lockstep deliberately: two readers
        // of one knob that disagree about precedence is a bug nobody would
        // think to look for.
        //
        // SAFETY (edition 2024): set/remove_var are `unsafe`; safe here because
        // the suffix is unique to this test and there is no concurrent access.
        unsafe {
            std::env::remove_var(nk_os());
            std::env::remove_var(dks_os());
        }
        assert_eq!(node_env_os(S_OS), None, "unset → None");

        unsafe { std::env::set_var(nk_os(), "legacy") };
        assert_eq!(
            node_env_os(S_OS).as_deref(),
            Some(std::ffi::OsStr::new("legacy")),
            "ROOMLER_NODE_* is still honoured"
        );

        unsafe { std::env::set_var(dks_os(), "new") };
        assert_eq!(
            node_env_os(S_OS).as_deref(),
            Some(std::ffi::OsStr::new("new")),
            "ROOMLERD_* wins when both are set"
        );

        unsafe { std::env::remove_var(dks_os()) };
        assert_eq!(
            node_env_os(S_OS).as_deref(),
            Some(std::ffi::OsStr::new("legacy")),
            "falls back to the older spelling after the new var is removed"
        );

        unsafe {
            std::env::remove_var(nk_os());
            std::env::remove_var(dks_os());
        }
    }

    // ── FR-21: the retired-spelling deprecation warning ─────────────────────

    #[test]
    fn legacy_reads_warn_once_per_variable_and_current_reads_never_do() {
        const S: &str = "FR21_DEPRECATION_PROBE";
        // `note_legacy_use` dedupes on the FULL variable name, so each retired
        // spelling gets its own single warning while the current one gets none.
        assert!(!warned(PREFIXES[0], S), "current spelling must never warn");
        assert!(
            !warned(PREFIXES[0], S),
            "...and must stay silent when re-read"
        );

        for legacy in &PREFIXES[1..] {
            assert!(warned(legacy, S), "{legacy}: first read must warn");
            assert!(
                !warned(legacy, S),
                "{legacy}: second read must NOT warn again"
            );
        }

        // A DIFFERENT suffix under the same retired prefix is a different
        // variable, so it warns on its own — otherwise one noisy host would
        // mask every other legacy setting it has.
        assert!(warned(PREFIXES[1], "FR21_DEPRECATION_PROBE_TWO"));
    }

    /// FR-46 (#1051): the dedupe set is also the ANSWER to "does this host
    /// still depend on a retired name?", so it must be readable, not only
    /// warnable. Before this the set was a local static inside
    /// `legacy_use_is_new` and the only trace of a legacy read was one WARN
    /// line near startup — unreachable from a `meshharbor logs` tail on a
    /// long-running daemon, which is exactly when the question gets asked.
    #[test]
    fn legacy_uses_are_readable_and_exclude_the_current_spelling() {
        const S: &str = "FR46_READBACK_PROBE";
        let before = super::legacy_env_uses();

        // The current spelling must never enter the set: it is not a legacy
        // use, and counting it would make every host look dirty forever.
        super::legacy_use_is_new(PREFIXES[0], S);
        assert!(
            !super::legacy_env_uses()
                .iter()
                .any(|v| v == &format!("{}{S}", PREFIXES[0])),
            "the current prefix must never be recorded as a legacy use"
        );

        super::legacy_use_is_new(PREFIXES[1], S);
        let after = super::legacy_env_uses();
        let want = format!("{}{S}", PREFIXES[1]);
        assert!(
            after.contains(&want),
            "{want} must be readable after a read"
        );

        // Sorted, so two hosts' reports diff cleanly rather than by insertion
        // order — the whole point is comparing them across a fleet.
        let mut sorted = after.clone();
        sorted.sort();
        assert_eq!(after, sorted, "the report must be sorted");

        assert!(
            after.len() > before.len(),
            "a new legacy read must grow the set"
        );
    }

    /// Did `note_legacy_use` emit for this (prefix, suffix)? Reads the dedupe
    /// set's decision directly: capturing tracing output would test the
    /// subscriber, not the once-per-variable rule this asserts.
    fn warned(prefix: &str, suffix: &str) -> bool {
        super::legacy_use_is_new(prefix, suffix)
    }
}

// RETIRED-NAME-ANCHOR-END
