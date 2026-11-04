// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1c — the exclusion set every growth number applies.
//!
//! Internal orgs and people must not count (spec §3c item 4): the platform
//! admins' own sign-ups, the orgs they create to test with, the throwaway
//! orgs a field test leaves behind. Two kinds of exclusion fold into ONE set:
//!
//! * **implicit** — every platform admin (`ROOMLER__STATS__PLATFORM_ADMINS`)
//!   and every org owned by an excluded user. No row needed: the allowlist
//!   is the record, and an admin who creates a new test org tomorrow is
//!   excluded with it.
//! * **explicit** — the `growth_exclusions` rows a platform admin writes
//!   (`PUT /api/admin/growth/exclusions`), each with a reason.
//!
//! [`ExclusionSet::load`] is the one function; a growth number that reads
//! the collection directly, or applies only the explicit rows, is wrong by
//! construction. `include_internal=true` is [`ExclusionSet::none`] — the raw
//! totals, with the set empty rather than the filter skipped, so the code
//! path is the same either way.

use std::collections::HashSet;

use bson::{Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_services::dao::{
    base::DaoResult,
    growth::{ExclusionKind, GrowthDao, GrowthExclusion},
};

use crate::Core;

/// Why an implicit exclusion applies — the label the admin view shows.
pub const IMPLICIT_PLATFORM_ADMIN: &str = "platform admin";
pub const IMPLICIT_OWNED_BY_EXCLUDED: &str = "owned by an excluded user";

#[derive(Debug, Clone, Default)]
pub struct ExclusionSet {
    /// Every excluded user id, implicit and explicit.
    pub users: HashSet<ObjectId>,
    /// Every excluded tenant id, implicit and explicit.
    pub tenants: HashSet<ObjectId>,
    /// The explicit rows, as stored.
    pub explicit: Vec<GrowthExclusion>,
    /// The platform admins (implicit users).
    pub implicit_users: Vec<ObjectId>,
    /// The orgs owned by an excluded user (implicit tenants), minus any that
    /// also has an explicit row.
    pub implicit_tenants: Vec<ObjectId>,
}

impl ExclusionSet {
    /// The empty set: `include_internal=true`.
    pub fn none() -> Self {
        Self::default()
    }

    /// Platform admins + the explicit rows + every org owned by any of those
    /// users. One read of `growth_exclusions`, one of `tenants`.
    pub async fn load(core: &Core) -> DaoResult<Self> {
        let explicit = GrowthDao::new(&core.db).list_exclusions().await?;
        let mut implicit_users: Vec<ObjectId> = core.platform_admins.iter().copied().collect();
        implicit_users.sort_unstable();

        let mut users: HashSet<ObjectId> = implicit_users.iter().copied().collect();
        let mut tenants: HashSet<ObjectId> = HashSet::new();
        for row in &explicit {
            match row.kind {
                ExclusionKind::User => {
                    users.insert(row.id);
                }
                ExclusionKind::Tenant => {
                    tenants.insert(row.id);
                }
            }
        }

        // Tombstoned orgs included: an archived test org is still internal.
        let owners: Vec<ObjectId> = users.iter().copied().collect();
        let mut implicit_tenants = Vec::new();
        if !owners.is_empty() {
            let mut cursor = core
                .db
                .collection::<Document>("tenants")
                .find(doc! { "owner_id": { "$in": &owners } })
                .projection(doc! { "_id": 1 })
                .await?;
            while let Some(d) = cursor.try_next().await? {
                if let Ok(id) = d.get_object_id("_id")
                    && tenants.insert(id)
                {
                    implicit_tenants.push(id);
                }
            }
        }
        implicit_tenants.sort_unstable();

        Ok(Self {
            users,
            tenants,
            explicit,
            implicit_users,
            implicit_tenants,
        })
    }

    pub fn user_excluded(&self, id: &ObjectId) -> bool {
        self.users.contains(id)
    }

    pub fn tenant_excluded(&self, id: &ObjectId) -> bool {
        self.tenants.contains(id)
    }

    /// `(users, tenants)` — what the digest footer reports as left out.
    pub fn counts(&self) -> (usize, usize) {
        (self.users.len(), self.tenants.len())
    }

    /// The `$nin` filter for a user-keyed query (`users._id`).
    pub fn user_filter(&self, field: &str) -> Document {
        let ids: Vec<ObjectId> = self.users.iter().copied().collect();
        doc! { field: { "$nin": ids } }
    }

    /// The `$nin` filter for a tenant-keyed query.
    pub fn tenant_filter(&self, field: &str) -> Document {
        let ids: Vec<ObjectId> = self.tenants.iter().copied().collect();
        doc! { field: { "$nin": ids } }
    }
}

/// FR-102 P3c — the operator's internal source networks
/// (`growth.internal_networks`): the address ranges the lab's egress,
/// self-hosted CI runners and the operator's own machines fetch from (never
/// GitHub-hosted runner ranges: shared cloud space that would swallow real
/// users).
///
/// The exclusion set above removes internal orgs and people, but an install
/// fetch carries no tenant — the request happens before any enrollment — so
/// the lab's own installs inflated the install section's fetch counters with
/// nothing to remove them by (spec §8, 2026-10-16). This set is the other
/// half of "internal": a fetch whose client address falls inside is counted
/// as `internal` instead of under its client class, so the digest can say
/// how many were left out (nothing vanishes silently).
///
/// ⚠️ The address is compared in memory and dropped. Nothing here stores it,
/// logs it or hands it on; the set is the operator's configuration, never a
/// record of who asked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InternalNetworks {
    nets: Vec<ipnet::IpNet>,
}

impl InternalNetworks {
    /// Parse the comma-separated setting: each entry a CIDR (`203.0.113.0/24`,
    /// `2001:db8::/32`) or a bare address (its own `/32` or `/128`). Returns
    /// the set and every entry it refused, verbatim with its reason, for the
    /// caller to warn about once — a refused entry is NOT a reason to refuse
    /// the rest.
    ///
    /// ⚠️ Two spellings are refused rather than guessed, because each would
    /// count strangers as internal without a word:
    /// - a CIDR with host bits set (`94.130.141.98/24`): one address with the
    ///   wrong prefix, or a network written from one of its hosts? Widened, it
    ///   would be a provider's whole /24;
    /// - a prefix shorter than /8 (IPv4) or /16 (IPv6) — a typo like `/0` —
    ///   which would make nearly every fetch internal.
    ///
    /// Both err toward counting less as internal, never more.
    pub fn parse(raw: &str) -> (Self, Vec<(String, &'static str)>) {
        let mut nets = Vec::new();
        let mut refused = Vec::new();
        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(net) = entry.parse::<ipnet::IpNet>() {
                let shortest = match net {
                    ipnet::IpNet::V4(_) => 8,
                    ipnet::IpNet::V6(_) => 16,
                };
                if net != net.trunc() {
                    refused.push((
                        entry.to_string(),
                        "host bits set: write the network address, or the address alone for one host",
                    ));
                } else if net.prefix_len() < shortest {
                    refused.push((
                        entry.to_string(),
                        "prefix too short to be one network (shorter than /8 for IPv4, /16 for IPv6)",
                    ));
                } else {
                    nets.push(net);
                }
            } else if let Ok(ip) = entry.parse::<std::net::IpAddr>() {
                nets.push(ipnet::IpNet::from(ip));
            } else {
                refused.push((entry.to_string(), "neither a CIDR nor an address"));
            }
        }
        (Self { nets }, refused)
    }

    /// The networks in effect, as CIDRs, for the boot log: the operator's
    /// configuration, never a record of who asked.
    pub fn networks(&self) -> Vec<String> {
        self.nets.iter().map(ToString::to_string).collect()
    }

    /// No network configured (or none that parsed): nothing is classified
    /// internal, so an "internal" count is not measured — never a zero.
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }

    /// Whether `ip` is inside one of the networks. An IPv4-mapped IPv6
    /// address (`::ffff:a.b.c.d`, what a dual-stack listener records) is
    /// compared as the IPv4 address it carries.
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        let mapped = match ip {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4),
            std::net::IpAddr::V4(_) => None,
        };
        self.nets
            .iter()
            .any(|n| n.contains(&ip) || mapped.is_some_and(|m| n.contains(&m)))
    }
}

/// P2 — everything the growth collections hold about one org, removed:
/// its `growth_org_daily` rows and the `growth_daily` rows whose dims carry
/// it (spec principle 7: aggregates may outlive rows; rows never outlive
/// their owner). This is the ONE call an org deletion must make for growth.
///
/// ⚠️ There is no org hard-delete path today — orgs are only archived, and
/// reversibly (`crates/api/src/routes/tenant.rs`), so nothing in production
/// calls this yet and the 25-month TTL is what bounds the collection. It is
/// deliberately NOT wired into the archive cascade: an archived org keeps
/// everything it knows so that `unarchive` restores a working org, and its
/// activity history is part of that. When a real deletion path lands, it
/// calls this.
///
/// FR-102 P4 — the org's `billing_events` go too (§3o: "with the org"); the
/// monthly billed totals frozen into `growth_daily` carry no tenant and stay,
/// so deleting an org never rewrites last year's MRR.
pub async fn purge_tenant(
    core: &Core,
    tenant_id: ObjectId,
) -> DaoResult<meshharbor_services::dao::growth::PurgedCounts> {
    let mut counts = GrowthDao::new(&core.db).purge_tenant(tenant_id).await?;
    counts.billing_events = meshharbor_services::dao::billing_event::BillingEventDao::new(&core.db)
        .purge_tenant(tenant_id)
        .await?;
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_set_excludes_nothing() {
        let none = ExclusionSet::none();
        assert!(!none.user_excluded(&ObjectId::new()));
        assert!(!none.tenant_excluded(&ObjectId::new()));
        assert_eq!(none.counts(), (0, 0));
        let f = none.user_filter("_id");
        assert_eq!(
            f.get_document("_id")
                .unwrap()
                .get_array("$nin")
                .unwrap()
                .len(),
            0
        );
    }

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    /// P3c — the setting's spellings: CIDRs of both families, bare
    /// addresses, padding and empties; a bad entry is refused on its own, with
    /// its reason, and the rest still apply.
    #[test]
    fn internal_networks_parse_each_entry_on_its_own() {
        let (nets, refused) = InternalNetworks::parse(
            " 203.0.113.0/24 , 198.51.100.7,, 2001:db8::/32, not-a-net, 10.0.0.0/33 ,192.0.2.9/24, 0.0.0.0/0, ::/8",
        );
        assert_eq!(nets.len(), 3);
        assert_eq!(
            nets.networks(),
            vec!["203.0.113.0/24", "198.51.100.7/32", "2001:db8::/32"]
        );
        let entries: Vec<&str> = refused.iter().map(|(e, _)| e.as_str()).collect();
        assert_eq!(
            entries,
            vec![
                "not-a-net",
                "10.0.0.0/33",
                "192.0.2.9/24",
                "0.0.0.0/0",
                "::/8"
            ]
        );
        assert!(refused[0].1.contains("neither a CIDR"));
        assert!(refused[2].1.contains("host bits"), "{refused:?}");
        assert!(refused[3].1.contains("too short") && refused[4].1.contains("too short"));
        assert!(nets.contains(ip("203.0.113.9")));
        assert!(nets.contains(ip("203.0.113.255")));
        assert!(!nets.contains(ip("203.0.114.1")));
        // A bare address is its own /32.
        assert!(nets.contains(ip("198.51.100.7")));
        assert!(!nets.contains(ip("198.51.100.8")));
        // IPv6.
        assert!(nets.contains(ip("2001:db8::1")));
        assert!(!nets.contains(ip("2001:db9::1")));
        // A CIDR with host bits set is refused, not widened: neither the
        // network it might name nor the host it was written from is internal.
        assert!(!nets.contains(ip("192.0.2.200")));
        assert!(!nets.contains(ip("192.0.2.9")));
        // Nor does a refused `/0` make everyone internal.
        assert!(!nets.contains(ip("8.8.8.8")));
        // What a dual-stack listener records for an IPv4 client.
        assert!(nets.contains(ip("::ffff:203.0.113.9")));
        assert!(!nets.contains(ip("::ffff:8.8.8.8")));
    }

    /// The default (unset) is the empty set: nothing is ever internal.
    #[test]
    fn no_internal_networks_means_nothing_is_internal() {
        for raw in ["", "  ", ",, ,"] {
            let (nets, refused) = InternalNetworks::parse(raw);
            assert!(nets.is_empty() && refused.is_empty(), "{raw:?}");
            assert!(!nets.contains(ip("127.0.0.1")));
        }
        assert!(InternalNetworks::default().is_empty());
    }
}
