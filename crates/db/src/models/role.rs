// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<u32>,
    #[serde(default)]
    pub position: u32,
    #[serde(default)]
    pub permissions: u64,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub is_managed: bool,
    #[serde(default)]
    pub is_mentionable: bool,
    #[serde(default)]
    pub is_hoisted: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

/// Permission bits (u64 bitfield)
#[allow(dead_code)]
pub mod permissions {
    pub const VIEW_CHANNELS: u64 = 1 << 0;
    pub const MANAGE_CHANNELS: u64 = 1 << 1;
    pub const MANAGE_ROLES: u64 = 1 << 2;
    pub const MANAGE_TENANT: u64 = 1 << 3;
    pub const KICK_MEMBERS: u64 = 1 << 4;
    pub const BAN_MEMBERS: u64 = 1 << 5;
    pub const INVITE_MEMBERS: u64 = 1 << 6;
    pub const SEND_MESSAGES: u64 = 1 << 7;
    pub const SEND_THREADS: u64 = 1 << 8;
    pub const EMBED_LINKS: u64 = 1 << 9;
    pub const ATTACH_FILES: u64 = 1 << 10;
    pub const READ_HISTORY: u64 = 1 << 11;
    pub const MENTION_EVERYONE: u64 = 1 << 12;
    pub const MANAGE_MESSAGES: u64 = 1 << 13;
    pub const ADD_REACTIONS: u64 = 1 << 14;
    pub const CONNECT_VOICE: u64 = 1 << 15;
    pub const SPEAK: u64 = 1 << 16;
    pub const STREAM_VIDEO: u64 = 1 << 17;
    pub const MUTE_MEMBERS: u64 = 1 << 18;
    pub const DEAFEN_MEMBERS: u64 = 1 << 19;
    pub const MOVE_MEMBERS: u64 = 1 << 20;
    pub const MANAGE_MEETINGS: u64 = 1 << 21;
    pub const MANAGE_DOCUMENTS: u64 = 1 << 22;
    pub const ADMINISTRATOR: u64 = 1 << 23;
    /// Enroll / rename / delete / assign-owner / set-policy for remote-control
    /// agents (devices).
    pub const MANAGE_AGENTS: u64 = 1 << 24;
    /// Initiate a remote-control session against a device you do NOT own.
    /// (Controlling your OWN device — `controller == owner_user_id` — never
    /// needs this; it's gated only by the device's consent mode.)
    pub const REMOTE_CONTROL: u64 = 1 << 25;
    /// View the remote-control audit log (`remote_audit`).
    pub const VIEW_REMOTE_AUDIT: u64 = 1 << 26;
    /// Run a command on a device via Fleet RPC (`meshharbor exec`, the device
    /// console). Gate 2 of four — the org kill-switch, the device's own
    /// `ExecPolicy`, and the agent-local `exec_enabled` key each deny
    /// independently. Deliberately NOT implied by `MANAGE_AGENTS`: managing a
    /// device's metadata and running a root shell on it are different powers.
    pub const EXEC_DEVICE: u64 = 1 << 27;
    /// View the Fleet-RPC audit log (`exec_audit`) — who ran what, where.
    pub const VIEW_EXEC_AUDIT: u64 = 1 << 28;
    /// Open a meshharbor SSH session to a device (`meshharbor ssh`). Gate 2 of four,
    /// mirroring [`EXEC_DEVICE`].
    ///
    /// Deliberately a SEPARATE bit rather than a reuse of `EXEC_DEVICE`, for
    /// the same reason `EXEC_DEVICE` is separate from `MANAGE_AGENTS`: an SSH
    /// session is strictly more than a bounded command. It is interactive, it
    /// lasts, and it grows file transfer and port forwarding as later slices
    /// land — so "may run one clamped diagnostic" and "may hold a live session"
    /// have to be grantable independently.
    pub const SSH_DEVICE: u64 = 1 << 29;
    /// View the meshharbor-SSH audit log (`ssh_audit`) — who was granted, or
    /// refused, a session on which device.
    ///
    /// Separate from [`VIEW_EXEC_AUDIT`] for the same reason [`SSH_DEVICE`] is
    /// separate from [`EXEC_DEVICE`]: the two logs answer different questions
    /// and an org may well want one reviewer for bounded commands and another
    /// for interactive sessions.
    pub const VIEW_SSH_AUDIT: u64 = 1 << 30;
    /// FR-85 P3 — record a device's screen from a remote-control session (the
    /// session bit `Permissions::RECORD` survives the hub only for a holder of
    /// this, the device's owner, or an ADMINISTRATOR — and never under
    /// break-glass).
    ///
    /// ⚠️ In NO managed row below the ADMINISTRATOR bypass, like
    /// [`EXEC_DEVICE`] and [`SSH_DEVICE`]: controlling a screen is visible to
    /// whoever is at it and ends with the session, but a recording is a copy
    /// that outlives both. An org grants it on purpose or not at all.
    pub const RECORD_REMOTE_SCREEN: u64 = 1 << 31;
    /// FR-90 — start and drive Hive agent sessions on a device
    /// (`docs/meshharbor-hive-design.md` §3.4). The first bit above 31: the UI
    /// mirror's mask arithmetic is exact to bit 52 since #888.
    ///
    /// ⚠️ In NO managed row below the ADMINISTRATOR bypass, like
    /// [`EXEC_DEVICE`], [`SSH_DEVICE`] and [`RECORD_REMOTE_SCREEN`]: an agent
    /// session is remote code execution on a device. It runs as the account
    /// the DEVICE maps the starter to — never SYSTEM/root — but "an AI
    /// typing commands as you on that box" is still a power an org grants on
    /// purpose or not at all.
    pub const HIVE_RUN: u64 = 1 << 32;
    // ⚠️ Bit 52 is the ceiling, and the reason is the JSON number rather than
    // anything here: a mask crosses the wire as a JSON integer, which is exact
    // only below 2^53. The UI mirror (`ui/src/utils/permissions.ts`) does its
    // mask arithmetic WITHOUT bitwise operators for exactly this reason — JS
    // coerces those to signed int32, which is what capped the catalog at bit 30
    // until #888. Adding a bit at 31..52 now needs a catalog entry there and
    // nothing else; going above 52 needs BigInt or string masks end to end.
    //
    // ⚠️ Still true, and the thing to check when adding one: a bit defined HERE
    // that the UI does not list is a permission nobody can grant from the
    // product. The mirror is hand-maintained and its spec locks the count.
    //
    // FR-19's relay approval rides MANAGE_AGENTS + EXEC_DEVICE (an EXEC_DEVICE
    // holder can already enable a relay on any exec-enabled device as root, so
    // the coupling grants nothing new). That was a workaround for the ceiling;
    // it can now become a dedicated bit whenever FR-19 wants one.

    /// Default member permissions
    pub const DEFAULT_MEMBER: u64 = VIEW_CHANNELS
        | SEND_MESSAGES
        | SEND_THREADS
        | EMBED_LINKS
        | ATTACH_FILES
        | READ_HISTORY
        | ADD_REACTIONS
        | CONNECT_VOICE
        | SPEAK
        | STREAM_VIDEO;

    /// Admin permissions (all except ADMINISTRATOR)
    pub const DEFAULT_ADMIN: u64 = DEFAULT_MEMBER
        | MANAGE_CHANNELS
        | MANAGE_ROLES
        | KICK_MEMBERS
        | BAN_MEMBERS
        | INVITE_MEMBERS
        | MENTION_EVERYONE
        | MANAGE_MESSAGES
        | MUTE_MEMBERS
        | DEAFEN_MEMBERS
        | MOVE_MEMBERS
        | MANAGE_MEETINGS
        | MANAGE_DOCUMENTS
        | MANAGE_AGENTS
        | REMOTE_CONTROL
        | VIEW_REMOTE_AUDIT
        // VIEW_EXEC_AUDIT but deliberately NOT EXEC_DEVICE, and for the same
        // reason not SSH_DEVICE: an admin should see every command the fleet
        // ran without silently gaining the power to run one. REMOTE_CONTROL is
        // not the same power — it is consent-gated, visible to whoever is at
        // the machine, and runs as the interactive user; exec and ssh run as
        // SYSTEM/root with nobody watching. Both stay explicit grants.
        | VIEW_EXEC_AUDIT
        // Same split for SSH: see the audit without gaining the session.
        | VIEW_SSH_AUDIT;

    /// Owner permissions (everything). Bump the mask whenever a new bit is
    /// added above so `ALL` literally contains every defined permission (owner
    /// also passes via the `ADMINISTRATOR` bypass in `has`, but keep this exact).
    pub const ALL: u64 = (1 << 33) - 1;

    /// Every named bit, with its wire name. Lives here rather than in the test
    /// module because two callers need it: `all_contains_every_named_permission`
    /// (so a new bit cannot be added without bumping `ALL`), and the escalation
    /// guard's 403, which has to be able to SAY which permission it refused —
    /// "you may not grant 0x8000000" is not an actionable error.
    pub const NAMED: &[(&str, u64)] = &[
        ("VIEW_CHANNELS", VIEW_CHANNELS),
        ("MANAGE_CHANNELS", MANAGE_CHANNELS),
        ("MANAGE_ROLES", MANAGE_ROLES),
        ("MANAGE_TENANT", MANAGE_TENANT),
        ("KICK_MEMBERS", KICK_MEMBERS),
        ("BAN_MEMBERS", BAN_MEMBERS),
        ("INVITE_MEMBERS", INVITE_MEMBERS),
        ("SEND_MESSAGES", SEND_MESSAGES),
        ("SEND_THREADS", SEND_THREADS),
        ("EMBED_LINKS", EMBED_LINKS),
        ("ATTACH_FILES", ATTACH_FILES),
        ("READ_HISTORY", READ_HISTORY),
        ("MENTION_EVERYONE", MENTION_EVERYONE),
        ("MANAGE_MESSAGES", MANAGE_MESSAGES),
        ("ADD_REACTIONS", ADD_REACTIONS),
        ("CONNECT_VOICE", CONNECT_VOICE),
        ("SPEAK", SPEAK),
        ("STREAM_VIDEO", STREAM_VIDEO),
        ("MUTE_MEMBERS", MUTE_MEMBERS),
        ("DEAFEN_MEMBERS", DEAFEN_MEMBERS),
        ("MOVE_MEMBERS", MOVE_MEMBERS),
        ("MANAGE_MEETINGS", MANAGE_MEETINGS),
        ("MANAGE_DOCUMENTS", MANAGE_DOCUMENTS),
        ("ADMINISTRATOR", ADMINISTRATOR),
        ("MANAGE_AGENTS", MANAGE_AGENTS),
        ("REMOTE_CONTROL", REMOTE_CONTROL),
        ("VIEW_REMOTE_AUDIT", VIEW_REMOTE_AUDIT),
        ("EXEC_DEVICE", EXEC_DEVICE),
        ("VIEW_EXEC_AUDIT", VIEW_EXEC_AUDIT),
        ("SSH_DEVICE", SSH_DEVICE),
        ("VIEW_SSH_AUDIT", VIEW_SSH_AUDIT),
        ("RECORD_REMOTE_SCREEN", RECORD_REMOTE_SCREEN),
        ("HIVE_RUN", HIVE_RUN),
    ];

    /// Names of every named bit set in `mask`, for error messages. An
    /// unnamed bit is rendered as its hex value rather than dropped — a mask
    /// that refuses something the table forgot must still say so.
    pub fn names(mask: u64) -> Vec<String> {
        let mut out: Vec<String> = NAMED
            .iter()
            .filter(|(_, bit)| mask & bit == *bit)
            .map(|(name, _)| (*name).to_string())
            .collect();
        let named_mask = NAMED.iter().fold(0u64, |a, (_, b)| a | b);
        let unnamed = mask & !named_mask;
        if unnamed != 0 {
            out.push(format!("{unnamed:#x}"));
        }
        out
    }

    pub fn has(permissions: u64, flag: u64) -> bool {
        permissions & ADMINISTRATOR != 0 || permissions & flag == flag
    }
}

impl Role {
    pub const COLLECTION: &'static str = "roles";
}

/// The definition of one system-managed role.
///
/// FR-82 — this table is the SINGLE place a seeded role's mask is written
/// down. Before it there were two divergent copies (`TenantDao::
/// create_default_roles`, which ran, and a dead `RoleDao::seed_defaults`
/// whose `Moderator` carried `MANAGE_MEETINGS` and no `REMOTE_CONTROL` — the
/// reverse of the one that shipped) and NOTHING that reconciled a live tenant
/// when a definition changed. The consequence was measured on the hosted
/// deployment: 63 of 72 orgs still carried `owner = 0xffffff`,
/// `admin = 0x7ffff7`, `moderator = 0x7ef91` — every mask frozen at the
/// permission set that existed on the day that org was created, so the seven
/// bits added since (`MANAGE_AGENTS` .. `VIEW_SSH_AUDIT`) reached nobody but
/// the newest seven tenants.
///
/// ⚠️ A role is `is_managed` because the SYSTEM owns its definition — the
/// product refuses to delete one for exactly that reason. A managed role that
/// silently diverges from its definition is therefore the defect, and the
/// reconcile that closes it is the contract being honoured, not a migration.
#[derive(Debug, Clone, Copy)]
pub struct ManagedRole {
    /// Stored lowercase. `TenantDao::get_role_by_name` resolves the default
    /// role for every invite by this string, so renaming one orphans the
    /// invite path rather than renaming anything.
    pub name: &'static str,
    pub description: &'static str,
    pub color: Option<u32>,
    pub position: u32,
    pub permissions: u64,
    pub is_default: bool,
    pub is_mentionable: bool,
    pub is_hoisted: bool,
}

/// Every system-managed role, in position order. Seeded from here at tenant
/// creation, reconciled from here at startup.
///
/// ⚠️ `EXEC_DEVICE` and `SSH_DEVICE` appear in no row BELOW the
/// `ADMINISTRATOR` bypass, deliberately: they run as SYSTEM/root with nobody
/// watching, so they stay grants an owner makes on purpose. (`owner` carries
/// them only as part of `ALL`, where the bypass already answered true for
/// every bit — they confer nothing there.) The reconcile hands out exactly
/// what this table says, so a bit added to a row here is a bit granted to
/// every existing org on the next boot — which is the point, and the reason
/// the omission has to be deliberate rather than incidental.
pub const MANAGED_ROLES: &[ManagedRole] = &[
    ManagedRole {
        name: "owner",
        description: "Full control over the tenant",
        color: Some(0xE91E63),
        position: 0,
        permissions: permissions::ALL,
        is_default: false,
        is_mentionable: false,
        is_hoisted: true,
    },
    ManagedRole {
        name: "admin",
        description: "Administrative access",
        color: Some(0x2196F3),
        position: 1,
        permissions: permissions::DEFAULT_ADMIN,
        is_default: false,
        is_mentionable: true,
        is_hoisted: true,
    },
    ManagedRole {
        name: "moderator",
        description: "Moderate channels/messages; remote-control operator",
        color: Some(0x4CAF50),
        position: 2,
        permissions: permissions::DEFAULT_MEMBER
            | permissions::MANAGE_MESSAGES
            | permissions::MUTE_MEMBERS
            | permissions::KICK_MEMBERS
            | permissions::REMOTE_CONTROL,
        is_default: false,
        is_mentionable: true,
        is_hoisted: true,
    },
    ManagedRole {
        name: "member",
        description: "Default member role",
        color: None,
        position: 3,
        permissions: permissions::DEFAULT_MEMBER,
        is_default: true,
        is_mentionable: false,
        is_hoisted: false,
    },
    ManagedRole {
        name: "guest",
        description: "Limited guest access",
        color: None,
        position: 4,
        permissions: permissions::VIEW_CHANNELS | permissions::READ_HISTORY,
        is_default: false,
        is_mentionable: false,
        is_hoisted: false,
    },
];

impl ManagedRole {
    /// The definition for `name`, or `None` for a role this table does not
    /// own — a tenant's own custom role, or a managed row whose name drifted.
    /// The reconcile leaves both alone and says so.
    pub fn by_name(name: &str) -> Option<&'static ManagedRole> {
        MANAGED_ROLES.iter().find(|r| r.name == name)
    }
}

/// One stratum the startup reconcile actually changed — the durable record of
/// a permission grant nobody asked for.
///
/// FR-82 shipped with the arithmetic at INFO and a comment saying it "has to
/// be readable in `kubectl logs` afterwards". Measured on the roll: ~10
/// minutes later it was readable nowhere. `kubectl logs` serves only the
/// CURRENT container, the emitting pod had been replaced, and the sole record
/// of a one-way grant across 63 organisations existed only because somebody
/// happened to be watching live. A log line is a notification, not an audit
/// trail.
///
/// ⚠️ **Deliberately NOT tenant-scoped**, unlike every other audit collection
/// here (`config_audit`, `ssh_audit`, `exec_audit` …). Those record a request
/// by a user against a device. This records a deployment-wide migration with
/// no tenant, no device and no requester — one row covers every organisation
/// that shared a stale mask, which is exactly the grouping the write used.
///
/// ⚠️ **Deliberately NOT TTL-indexed**, also unlike the others. Those bound an
/// append-only stream of routine decisions; this is bounded already — one row
/// per changed stratum, only on the boot that changes anything, so a
/// deployment's whole history is ~12 rows and then nothing, forever. Expiring
/// them after 90 days would delete the only record of an irreversible grant
/// and re-create the exact gap this type exists to close, just more slowly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleReconcileEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub at: DateTime,
    /// The build that ran it, so a row explains itself without a join against
    /// a deployment history nobody kept.
    pub version: String,
    /// The managed role's name (`admin`, `owner`, …).
    pub role: String,
    /// How many role rows — i.e. how many organisations — carried `stored`.
    pub rows: i64,
    /// The mask before, after, and the difference. All three are stored rather
    /// than derived, because the point of the row is to be readable years
    /// later by someone who will not re-run the bitwise arithmetic.
    pub stored: i64,
    pub granted: i64,
    pub gained: i64,
    /// The permission NAMES the grant added. The masks above are the record;
    /// this is the part a human reads. ⚠️ Resolved at write time against the
    /// build's own table — a bit renamed later does not rewrite history.
    pub gained_names: Vec<String>,
}

impl RoleReconcileEvent {
    pub const COLLECTION: &'static str = "role_reconcile_audit";
}

#[cfg(test)]
mod tests {
    use super::permissions::*;
    use super::{MANAGED_ROLES, ManagedRole};

    #[test]
    fn no_managed_role_below_administrator_seeds_a_root_shell() {
        // FR-82's load-bearing test. The startup reconcile grants whatever
        // this table says to EVERY existing org, so `DEFAULT_ADMIN |=
        // EXEC_DEVICE` — a one-token edit that reads as tidying — would open
        // exec-as-SYSTEM on the whole deployment at the next boot, with no
        // migration to review and no admin action to audit. `DEFAULT_ADMIN`'s
        // own test guards that constant; this one guards every SEEDED row,
        // including a future mask written here directly.
        //
        // ⚠️ `owner` is exempt, and the exemption is precise rather than
        // convenient: it carries ADMINISTRATOR, so `has()` already answers
        // true for EVERY bit by the bypass. Its `ALL` mask therefore grants
        // nothing the row did not already confer, which is why the check is
        // "no role BELOW the bypass" rather than "no role". Aiming it at
        // every row (the first draft) fails on `owner` for a reason that
        // says nothing about the risk this guards.
        for r in MANAGED_ROLES {
            if r.permissions & ADMINISTRATOR != 0 {
                continue;
            }
            assert_eq!(
                r.permissions & EXEC_DEVICE,
                0,
                "managed role `{}` seeds EXEC_DEVICE without the ADMINISTRATOR bypass",
                r.name
            );
            assert_eq!(
                r.permissions & SSH_DEVICE,
                0,
                "managed role `{}` seeds SSH_DEVICE without the ADMINISTRATOR bypass",
                r.name
            );
            // FR-85 P3 — a recording outlives the session; an org grants it
            // on purpose or not at all.
            assert_eq!(
                r.permissions & RECORD_REMOTE_SCREEN,
                0,
                "managed role `{}` seeds RECORD_REMOTE_SCREEN without the ADMINISTRATOR bypass",
                r.name
            );
            // FR-90 — an agent session is remote code execution on a device.
            assert_eq!(
                r.permissions & HIVE_RUN,
                0,
                "managed role `{}` seeds HIVE_RUN without the ADMINISTRATOR bypass",
                r.name
            );
        }
    }

    #[test]
    fn owner_is_the_only_seeded_administrator() {
        // ADMINISTRATOR is the bypass in `has`, so a second row carrying it
        // would hand every future permission to that role forever — silently,
        // and without ever appearing in a diff of the bits below it.
        for r in MANAGED_ROLES {
            let is_admin_bit = r.permissions & ADMINISTRATOR != 0;
            assert_eq!(
                is_admin_bit,
                r.name == "owner",
                "managed role `{}` and the ADMINISTRATOR bypass disagree",
                r.name
            );
        }
    }

    #[test]
    fn managed_role_names_are_unique_and_positions_are_dense() {
        for (i, r) in MANAGED_ROLES.iter().enumerate() {
            assert_eq!(r.position as usize, i, "`{}` is out of position", r.name);
            assert_eq!(
                r.name,
                r.name.to_lowercase(),
                "`{}` is not lowercase",
                r.name
            );
            assert!(
                MANAGED_ROLES.iter().filter(|o| o.name == r.name).count() == 1,
                "`{}` is defined twice",
                r.name
            );
        }
    }

    #[test]
    fn the_role_the_invite_path_resolves_by_name_exists_and_is_the_default() {
        // Both invite paths (`invite::accept`, `auth::register_with_invite`)
        // do `get_role_by_name(tid, "member")` and `.unwrap()` its id when the
        // invite names no role. Renaming the row breaks joining an org, and
        // the break is a 500 on someone else's signup.
        let member = ManagedRole::by_name("member").expect("no `member` role to seed invites with");
        assert!(member.is_default);
        assert_eq!(
            MANAGED_ROLES.iter().filter(|r| r.is_default).count(),
            1,
            "exactly one managed role may be the default"
        );
    }

    #[test]
    fn all_contains_every_named_permission() {
        // `ALL` is a hand-maintained `(1 << N) - 1` and it is what the Owner
        // role is created with. Adding a bit above without bumping it leaves
        // Owner missing that permission — invisible, because Owner also
        // carries ADMINISTRATOR and passes `has` by the bypass. This makes the
        // "bump the mask" comment executable instead of advisory.
        for (name, bit) in NAMED {
            assert!(
                ALL & bit == *bit,
                "{name} ({bit:#x}) is not in ALL ({ALL:#x}) — bump the mask"
            );
        }
    }

    #[test]
    fn every_named_permission_is_a_distinct_single_bit() {
        for (name, bit) in NAMED {
            assert_eq!(bit.count_ones(), 1, "{name} is not a single bit");
        }
        for (i, (an, ab)) in NAMED.iter().enumerate() {
            for (bn, bb) in &NAMED[i + 1..] {
                assert_ne!(ab, bb, "{an} and {bn} are the same bit");
            }
        }
    }

    #[test]
    fn admins_can_read_the_audits_without_gaining_the_powers() {
        // The deliberate asymmetry: an admin sees every session and command
        // the fleet served without silently acquiring the ability to open one.
        assert_ne!(
            DEFAULT_ADMIN & VIEW_EXEC_AUDIT,
            0,
            "admins must be able to read the exec audit"
        );
        assert_ne!(
            DEFAULT_ADMIN & VIEW_SSH_AUDIT,
            0,
            "admins must be able to read the ssh audit"
        );
        assert_eq!(
            DEFAULT_ADMIN & EXEC_DEVICE,
            0,
            "EXEC_DEVICE must stay an explicit grant"
        );
        assert_eq!(
            DEFAULT_ADMIN & SSH_DEVICE,
            0,
            "SSH_DEVICE must stay an explicit grant"
        );
        assert_eq!(
            DEFAULT_ADMIN & RECORD_REMOTE_SCREEN,
            0,
            "RECORD_REMOTE_SCREEN must stay an explicit grant"
        );
        assert_eq!(
            DEFAULT_ADMIN & HIVE_RUN,
            0,
            "HIVE_RUN must stay an explicit grant"
        );
    }

    #[test]
    fn ssh_and_exec_are_independently_grantable() {
        // Four separate bits on purpose: "may run one clamped command",
        // "may hold an interactive session", and the two audit views are
        // different powers and different jobs.
        for (a, b) in [
            (EXEC_DEVICE, SSH_DEVICE),
            (VIEW_EXEC_AUDIT, VIEW_SSH_AUDIT),
            (EXEC_DEVICE, VIEW_EXEC_AUDIT),
            (SSH_DEVICE, VIEW_SSH_AUDIT),
        ] {
            assert_eq!(a & b, 0, "{a:#x} and {b:#x} overlap");
        }
    }
}
