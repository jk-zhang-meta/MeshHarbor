// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-6b — dynamic secrets: an issuer, for a credential minted per lease
//! (FR-90 §3e "P3-6, `short-lived`, as designed").
//!
//! | Piece | Here |
//! |---|---|
//! | the secret | `kind: "dynamic"` and a `provider` ([`providers`]). Its fields are the issuer's, and a write of any other is refused ([`check_issuer_field`]). It names one audience, where its provider mints ([`check_audiences`]) |
//! | the providers served | `vault.providers` ([`ProviderScope`]) |
//! | a lease | in `short-lived`, for the secret as a whole: every issuer field that holds a value, opened and sealed together in one JSON object, the bundle ([`bundle_json`]), each at the version it carried ([`bundle_of`]) |
//! | its standing | a newer version of any of the issuer's fields takes it back ([`bundle_changed`]) |
//!
//! ⚠️ The pairing of the kind with its mode is decided by policy, not here:
//! the guardrails `dynamic-only-short-lived` and `short-lived-only-dynamic`
//! refuse a dynamic secret in any other mode, and anything else in
//! `short-lived`, and each refusal is recorded with the guardrail that made
//! it.

use std::collections::{BTreeMap, HashSet};

use meshharbor_remote_control::vault::providers::{self, Provider};
use serde::Serialize;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::model::{FieldState, VaultSecret};

/// The providers the vault leases for (`vault.providers`): every one this
/// build knows, or a set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderScope(Option<HashSet<&'static str>>);

impl ProviderScope {
    /// `vault.providers` read: empty or `*` is every provider; otherwise the
    /// ones listed. A word that names no provider serves nothing, so a typo
    /// turns a provider off rather than another one on.
    pub fn parse(raw: &str) -> Self {
        let entries: Vec<&str> = raw
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|e| !e.is_empty())
            .collect();
        if entries.is_empty() || entries.contains(&"*") {
            return Self(None);
        }
        let mut names = HashSet::new();
        for e in entries {
            match providers::named(e) {
                Some(p) => {
                    names.insert(p.name);
                }
                None => warn!(
                    entry = e,
                    "vault.providers: names no provider — it serves nothing"
                ),
            }
        }
        Self(Some(names))
    }

    /// Whether the vault leases for `p`.
    pub fn serves(&self, p: &Provider) -> bool {
        self.0.as_ref().is_none_or(|names| names.contains(p.name))
    }

    pub fn log(&self) {
        match &self.0 {
            None => info!("vault: every provider served"),
            Some(names) => {
                let mut names: Vec<_> = names.iter().collect();
                names.sort();
                info!(providers = ?names, "vault: these providers served");
            }
        }
    }
}

/// The provider a dynamic secret names, where this build knows it.
pub fn provider_of(secret: &VaultSecret) -> Option<&'static Provider> {
    secret.provider.as_deref().and_then(providers::named)
}

/// A dynamic secret's field must be one its provider's issuer holds.
pub fn check_issuer_field(p: &Provider, field: &str) -> Result<(), String> {
    if p.issuer.contains(&field) {
        Ok(())
    } else {
        Err(format!("a {} secret holds {}", p.name, p.issuer.join(", ")))
    }
}

/// A dynamic secret names exactly one audience: where its provider mints.
pub fn check_audiences(audiences: &[String]) -> Result<(), String> {
    if audiences.len() == 1 {
        Ok(())
    } else {
        Err("a dynamic secret names exactly one audience, where its provider mints".into())
    }
}

/// The issuer's fields that hold a value, each at its current version: what
/// a lease carries.
pub fn bundle_of(p: &Provider, fields: &BTreeMap<String, FieldState>) -> BTreeMap<String, i64> {
    p.issuer
        .iter()
        .filter_map(|f| {
            fields
                .get(*f)
                .filter(|s| s.current > 0)
                .map(|s| ((*f).to_string(), s.current))
        })
        .collect()
}

/// The first issuer field no mint can do without that `bundle` lacks.
pub fn missing_required(p: &Provider, bundle: &BTreeMap<String, i64>) -> Option<&'static str> {
    p.required
        .iter()
        .copied()
        .find(|f| !bundle.contains_key(*f))
}

/// Whether a bundle lease no longer stands: a field it carried has a newer
/// version, or one it did not carry holds a value now. A provider this
/// build cannot name stands for nothing.
pub fn bundle_changed(
    bundle: &BTreeMap<String, i64>,
    provider: Option<&Provider>,
    fields: &BTreeMap<String, FieldState>,
) -> bool {
    provider.is_none_or(|p| bundle_of(p, fields) != *bundle)
}

/// A bundle's plaintext: `{"audience": …, "fields": {name: value, …}}`.
#[derive(Serialize)]
struct Bundle<'a> {
    audience: &'a str,
    fields: BTreeMap<&'a str, &'a str>,
}

/// The bundle a lease seals: the audience its provider mints toward, and
/// the issuer's opened fields. The buffer is sized up front for the worst
/// escaping, so it never grows: a buffer that grew would leave a copy of
/// the values behind, unzeroed.
pub fn bundle_json(
    audience: &str,
    opened: &[(&str, &[u8])],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut fields = BTreeMap::new();
    let mut room = 64 + 6 * audience.len();
    for (name, value) in opened {
        let value = std::str::from_utf8(value).map_err(|_| "bundle_not_text")?;
        room += 8 + 6 * name.len() + 6 * value.len();
        fields.insert(*name, value);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(room));
    let before = out.capacity();
    serde_json::to_writer(&mut *out, &Bundle { audience, fields })
        .map_err(|_| "bundle_unwritten")?;
    debug_assert_eq!(out.capacity(), before, "the bundle's buffer grew");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use providers::{MYSQL, POSTGRES};

    fn fields(of: &[(&str, i64)]) -> BTreeMap<String, FieldState> {
        of.iter()
            .map(|(f, n)| {
                (
                    (*f).to_string(),
                    FieldState {
                        seq: *n,
                        current: *n,
                        updated_at: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn the_providers_served_are_every_one_or_those_listed() {
        for raw in ["", " ", "*", "postgres", "mysql, postgres", "postgres,*"] {
            assert!(ProviderScope::parse(raw).serves(&POSTGRES), "{raw:?}");
        }
        for raw in ["none", "mysql", "Postgres", "-"] {
            assert!(!ProviderScope::parse(raw).serves(&POSTGRES), "{raw:?}");
        }
        // P3-6d-1b — each provider by its own name, and only by it.
        for raw in ["", "*", "mysql", "mysql, postgres"] {
            assert!(ProviderScope::parse(raw).serves(&MYSQL), "{raw:?}");
        }
        for raw in ["postgres", "MySQL", "none"] {
            assert!(!ProviderScope::parse(raw).serves(&MYSQL), "{raw:?}");
        }
    }

    #[test]
    fn a_dynamic_secret_holds_its_issuers_fields_alone() {
        for f in POSTGRES.issuer {
            assert_eq!(check_issuer_field(&POSTGRES, f), Ok(()), "{f}");
        }
        // Its minted credential's own fields are not the issuer's to hold.
        for f in ["user", "password", "host", "port", "value", "admin"] {
            assert!(check_issuer_field(&POSTGRES, f).is_err(), "{f}");
        }
    }

    #[test]
    fn a_dynamic_secret_names_one_audience() {
        assert!(check_audiences(&[]).is_err());
        assert_eq!(check_audiences(&["db.internal:5432".into()]), Ok(()));
        assert!(check_audiences(&["a:5432".into(), "b:5432".into()]).is_err());
    }

    #[test]
    fn a_bundle_carries_the_issuers_fields_that_hold_a_value() {
        let f = fields(&[
            ("admin_user", 1),
            ("admin_password", 3),
            ("database", 1),
            ("grants", 0),
        ]);
        let b = bundle_of(&POSTGRES, &f);
        assert_eq!(
            b,
            BTreeMap::from([
                ("admin_password".to_string(), 3),
                ("admin_user".to_string(), 1),
                ("database".to_string(), 1),
            ])
        );
        assert_eq!(missing_required(&POSTGRES, &b), None);
        let short = bundle_of(&POSTGRES, &fields(&[("admin_user", 1), ("database", 2)]));
        assert_eq!(missing_required(&POSTGRES, &short), Some("admin_password"));
    }

    #[test]
    fn a_bundle_stands_until_any_of_its_secrets_fields_changes() {
        let f = fields(&[("admin_user", 1), ("admin_password", 3), ("database", 1)]);
        let b = bundle_of(&POSTGRES, &f);
        assert!(!bundle_changed(&b, Some(&POSTGRES), &f));
        // A newer version of a field it carried.
        let rotated = fields(&[("admin_user", 1), ("admin_password", 4), ("database", 1)]);
        assert!(bundle_changed(&b, Some(&POSTGRES), &rotated));
        // A field it did not carry, written since.
        let grown = fields(&[
            ("admin_user", 1),
            ("admin_password", 3),
            ("database", 1),
            ("ca", 1),
        ]);
        assert!(bundle_changed(&b, Some(&POSTGRES), &grown));
        // A provider this build cannot name stands for nothing.
        assert!(bundle_changed(&b, None, &f));
    }

    #[test]
    fn a_bundle_is_one_json_object_its_values_escaped() {
        let pw = format!("{}\"\\\n\u{1}é", "p".repeat(40));
        let out = bundle_json(
            "db.internal:5432",
            &[
                ("admin_user", b"svc".as_slice()),
                ("admin_password", pw.as_bytes()),
            ],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["audience"], "db.internal:5432");
        assert_eq!(v["fields"]["admin_user"], "svc");
        assert_eq!(v["fields"]["admin_password"], pw.as_str());
        assert_eq!(v.as_object().unwrap().len(), 2);
        assert!(bundle_json("a:1", &[("admin_user", &[0xff, 0xfe])]).is_err());
    }
}
