// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Which organizations the vault serves (`vault.tenants`), and (P3-9-1)
//! whose people it lends to (`vault.people`).
//!
//! `vault.tenants` is the same dial as `hive.tenants` (FR-90 P1g), with the
//! same rules: empty or `*` is every organization, a list is only those, and
//! an entry that is not an organization id matches nothing — a typo shuts the
//! vault for the org it meant rather than opening it to every other. Every
//! other organization is answered as if the module were not there for it.
//!
//! ⚠️ `vault.people` reads the other way about: empty is NO organization
//! ([`TenantScope::parse_opt_in`]). A person's `meshharbor connect` is a new
//! kind of principal, and an organization the vault already serves for its
//! sessions must not start lending to its people on an upgrade.
//!
//! A copy of hive's `TenantScope`, not a call into it: the vault depends on
//! core alone in P3-1, and an edge to hive for one parser would be the
//! wrong reason to have one.

use std::collections::HashSet;

use bson::oid::ObjectId;
use tracing::{error, info};

/// The organizations the vault serves: every one, or a set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantScope(Option<HashSet<ObjectId>>);

impl TenantScope {
    /// Every organization.
    pub fn everyone() -> Self {
        Self(None)
    }

    /// No organization.
    pub fn nobody() -> Self {
        Self(Some(HashSet::new()))
    }

    /// `vault.tenants` read: empty or `*` is every organization; otherwise
    /// the ids listed.
    pub fn parse(raw: &str) -> Self {
        let entries = entries(raw);
        if entries.is_empty() {
            return Self::everyone();
        }
        Self::listed(&entries, "vault.tenants")
    }

    /// P3-9-1 — `vault.people` read: opt-in. Empty is NO organization, `*`
    /// every one, and otherwise the ids listed, with [`Self::parse`]'s rule
    /// for an entry that is no id.
    pub fn parse_opt_in(raw: &str) -> Self {
        let entries = entries(raw);
        if entries.is_empty() {
            return Self::nobody();
        }
        Self::listed(&entries, "vault.people")
    }

    /// `*` anywhere is every organization; otherwise the ids listed, and an
    /// entry that is no id matches nothing.
    fn listed(entries: &[&str], setting: &str) -> Self {
        if entries.contains(&"*") {
            return Self::everyone();
        }
        let mut ids = HashSet::new();
        for e in entries {
            match ObjectId::parse_str(e) {
                Ok(id) => {
                    ids.insert(id);
                }
                Err(_) => {
                    error!(
                        entry = e,
                        setting, "vault: not an organization id — it matches nothing"
                    )
                }
            }
        }
        Self(Some(ids))
    }

    /// Whether the vault serves `tenant`.
    pub fn serves(&self, tenant: ObjectId) -> bool {
        self.0.as_ref().is_none_or(|ids| ids.contains(&tenant))
    }

    /// Said once at boot, so the log shows whom the vault is open to.
    pub fn log(&self) {
        match &self.0 {
            None => info!("vault: serves every organization"),
            Some(ids) => info!(
                organizations = ids.len(),
                "vault: serves only the organizations in vault.tenants"
            ),
        }
    }

    /// P3-9-1 — said once at boot, so the log shows whose people the vault
    /// lends to.
    pub fn log_people(&self) {
        match &self.0 {
            None => info!("vault: lends to the people of every organization it serves"),
            Some(ids) if ids.is_empty() => {
                info!("vault: lends to no organization's people (vault.people is empty)")
            }
            Some(ids) => info!(
                organizations = ids.len(),
                "vault: lends only to the people of the organizations in vault.people"
            ),
        }
    }
}

/// A setting's entries: split on commas and whitespace, empties dropped.
fn entries(raw: &str) -> Vec<&str> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|e| !e.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "65f0000000000000000000a1";
    const B: &str = "65f0000000000000000000b2";

    fn oid(s: &str) -> ObjectId {
        ObjectId::parse_str(s).unwrap()
    }

    #[test]
    fn empty_or_a_star_is_every_organization() {
        for raw in ["", "  ", ",", "*", &format!("{A},*")] {
            let s = TenantScope::parse(raw);
            assert_eq!(s, TenantScope::everyone(), "{raw:?}");
            assert!(s.serves(oid(B)));
        }
    }

    #[test]
    fn a_list_serves_only_its_organizations() {
        let s = TenantScope::parse(&format!(" {A} , "));
        assert!(s.serves(oid(A)));
        assert!(!s.serves(oid(B)));
        let spaced = TenantScope::parse(&format!("{A} {B}"));
        assert!(spaced.serves(oid(A)) && spaced.serves(oid(B)));
    }

    #[test]
    fn an_entry_that_is_no_id_matches_nothing_and_opens_nothing() {
        let s = TenantScope::parse("65f0000000000000000000aZ");
        assert!(!s.serves(oid(A)));
        assert!(!s.serves(oid(B)));
        let mixed = TenantScope::parse(&format!("not-an-id,{A}"));
        assert!(mixed.serves(oid(A)));
        assert!(!mixed.serves(oid(B)));
    }

    /// P3-9-1 — `vault.people` is opt-in: empty is nobody, the opposite of
    /// `vault.tenants`; `*` and a list read as they do there.
    #[test]
    fn people_are_lent_to_only_where_listed() {
        for raw in ["", "  ", ","] {
            let s = TenantScope::parse_opt_in(raw);
            assert_eq!(s, TenantScope::nobody(), "{raw:?}");
            assert!(!s.serves(oid(A)) && !s.serves(oid(B)), "{raw:?}");
        }
        for raw in ["*", &format!("{A},*")] {
            assert_eq!(TenantScope::parse_opt_in(raw), TenantScope::everyone());
        }
        let s = TenantScope::parse_opt_in(&format!(" {A} , "));
        assert!(s.serves(oid(A)));
        assert!(!s.serves(oid(B)));
        // A typo lends to nobody, never to everybody.
        let typo = TenantScope::parse_opt_in("65f0000000000000000000aZ");
        assert!(!typo.serves(oid(A)) && !typo.serves(oid(B)));
    }
}
