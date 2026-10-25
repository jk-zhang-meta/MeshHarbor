// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
pub mod fixtures;

/// Real HTTP/Mongo central account approval console routes.
#[cfg(test)]
mod account_approval_management_tests;

#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod channel_crud_tests;
#[cfg(test)]
mod channel_tests;
#[cfg(test)]
mod conference_message_tests;
#[cfg(test)]
mod conference_tests;
#[cfg(test)]
mod export_tests;
#[cfg(test)]
mod file_tests;
#[cfg(test)]
mod message_tests;
#[cfg(test)]
mod multi_tenancy_tests;
#[cfg(test)]
mod reaction_tests;
#[cfg(test)]
mod recording_tests;

/// Tests of the fixture itself, not of the product — see the module docs.
#[cfg(test)]
mod harness_tests;

/// FR-69 — the composition baseline (routes, index plan, wire names) asserted
/// identical after every module move. See docs/fr/FR-69-modular-monolith.md.
#[cfg(test)]
mod composition_tests;

#[cfg(test)]
mod agent_crash_tests;
#[cfg(test)]
mod agent_e2e_tests;
#[cfg(test)]
mod agent_exec_tests;
#[cfg(test)]
mod agent_presence_tests;
/// #2267 — a removal (or an archive) tells a connected device at once with
/// `rc:goodbye AgentDeleted`, instead of leaving it its socket.
#[cfg(test)]
mod agent_removal_tests;
/// FR-84 D5a — `/api/agent/self/{devices,mesh}`: a device's own view of its
/// org is exactly its netmap ∪ itself (the negative control lives here).
#[cfg(test)]
mod agent_self_tests;
#[cfg(test)]
mod agent_tests;
/// FR-88 P1a — sign-up attribution: stored once at creation, absent from
/// every user-facing response, parked across OAuth, counted for the admin.
#[cfg(test)]
mod attribution_tests;
#[cfg(test)]
mod billing_tests;
#[cfg(test)]
mod cluster_tests;
#[cfg(test)]
mod cors_tests;
#[cfg(test)]
mod device_list_tests;
#[cfg(test)]
mod device_naming_tests;
#[cfg(test)]
mod enroll_key_tests;
#[cfg(test)]
mod ephemeral_tests;
#[cfg(test)]
mod exec_service_tests;
// FR-52 P3c — the loopback proof: an outsider logs into the REAL agent through
// the server. ⚠️ A test file that is not registered here compiles green and
// runs nothing (P1 shipped one that way for a day).
#[cfg(test)]
mod extauth_tests;
#[cfg(test)]
mod external_access_tests;
/// FR-102 P6 — the purestat puller (seven closed days frozen once, a frozen
/// day never rewritten, a failed pull recorded rather than read as 0) and
/// the Campaigns table (both planes joined by the normalised key; a revoked
/// key reads `not_measured`, AC16's control; unmounted modules named).
#[cfg(test)]
mod growth_campaigns_tests;
/// FR-102 P8 — the ingest key and routes (AC18: a snapshot pushed twice is
/// stored once; an unknown platform and post text are refused; a wrong key
/// is a 404), and the Channels table's join with the reach column it fills.
#[cfg(test)]
mod growth_channels_tests;
/// FR-102 P1d — the daily digest: every section's exact numbers on a seeded
/// day, the once-only claim under two concurrent runs (AC23), the routes,
/// the no-address rule, and the purestat client against a fake server.
#[cfg(test)]
mod growth_digest_tests;
/// FR-102 P2 — the account funnel with pending/settled (AC6),
/// `growth_org_daily` surviving the audit TTL and dying with the org
/// (AC8), the weekly cohorts and the org views.
#[cfg(test)]
mod growth_funnel_tests;
/// FR-102 P7 — the GitHub puller against a fake GitHub (the closed day's
/// snapshot read once in its window, releases paged, drafts out, traffic
/// only with a token, a refused token recorded rather than zeroed) and its
/// readers (snapshots differenced, a gap read as null, never 0).
#[cfg(test)]
mod growth_github_tests;
/// FR-102 P5 — the newsletter's delivery side: SendGrid's signed Event
/// Webhook refusing what it cannot verify before parsing it, recording only
/// the four events, suppressing a hard bounce at the next send (AC14's test
/// half); the per-issue unsubscribe; the per-issue table and the digest.
#[cfg(test)]
mod growth_newsletter_tests;
/// FR-102 P10 — the read key (AC20: the admin's numbers on every GET view,
/// the empty 404 on every write and on the admin surface), the weekly
/// roll-up's once-only claim and routes, and the alert rules firing once,
/// clearing, and mailing at most once a day.
#[cfg(test)]
mod growth_p10_tests;
/// FR-102 P9a — remote-desktop quality from what is already recorded: the
/// nightly freeze of `growth_quality_daily` from the four sources as they
/// are really written (the camelCase crash payload, the browser's
/// `rc.connect` records, the agents' own batches), both scopes, the 7-day
/// log horizon, the Quality view and the digest's and weekly's sections.
#[cfg(test)]
mod growth_quality_tests;
/// FR-102 P4 — billed revenue through Stripe's own signature scheme (AC13's
/// test half: the lifecycle's invoice amounts, MRR month by month, the
/// coupon control), the frozen months surviving an org's purge, the
/// backfill against a fake Stripe, and the quota-collision counter.
#[cfg(test)]
mod growth_revenue_tests;
/// FR-102 P7 — the search pullers against fakes of Google, Bing and the
/// blog's feed: only final Search Console days, the service account's
/// token exchange, the weighted position, URL Inspection into
/// `growth_content`, Bing at its own grain, every refusal recorded.
#[cfg(test)]
mod growth_search_tests;
/// FR-102 P3b — the setup wizard's opt-in diagnostics (AC12's server half):
/// a record stored with exactly its fields and nothing about the request,
/// every invalid field refused with nothing stored, the kill switch's empty
/// 404, the per-run cap, the nightly freeze into `growth_daily`, and the
/// digest's `wizard_steps` over opted-in runs.
#[cfg(test)]
mod growth_setup_diagnostics_tests;
/// FR-102 — growth observability: the campaign taxonomy at ingress (AC5),
/// the exclusion list and the set every growth number applies (AC4).
#[cfg(test)]
mod growth_tests;
#[cfg(test)]
mod hive_tests;
/// FR-102 P3 — the install trace: the token ledger (AC11), the fetch
/// counters by client class with the updater never counted (AC10), and the
/// enroll's `install` claim as the row records it.
#[cfg(test)]
mod install_trace_tests;
#[cfg(test)]
mod invite_tests;
#[cfg(test)]
mod keep_busy_tests;
#[cfg(test)]
mod key_rotation_tests;
/// FR-115 P5 — the meeting-length cap: warned at 55, ended at 60, once.
#[cfg(test)]
mod meeting_cap_tests;
#[cfg(test)]
mod member_tests;
#[cfg(test)]
mod newsletter_tests;
#[cfg(test)]
mod notification_tests;
#[cfg(test)]
mod oauth_tests;
/// FR-115 P3 — an organization's concurrent remote-session cap: refused at
/// start with the holder named, per seat on Pro, carried across pods.
#[cfg(test)]
mod org_session_cap_tests;
#[cfg(test)]
mod overlay_growth_tests;
#[cfg(test)]
mod overlay_route_offer_tests;
#[cfg(test)]
mod overlay_tests;
#[cfg(test)]
mod pagination_tests;
#[cfg(test)]
mod pdf_export_tests;
/// FR-100 P1a — a device's identity key as the fleet stores and shows it, and
/// the real agent's hello carrying one it keeps beside its config.
#[cfg(test)]
mod peer_auth_key_tests;
#[cfg(test)]
mod business_isolation_tests;
#[cfg(test)]
mod peer_relay_auto_tests;
#[cfg(test)]
mod managed_forward_tests;
#[cfg(test)]
mod net_inventory_tests;
#[cfg(test)]
mod peer_relay_mint_tests;
#[cfg(test)]
mod peer_relay_tests;
#[cfg(test)]
mod plan_limit_tests;
#[cfg(test)]
mod privacy_activity_tests;
#[cfg(test)]
mod privacy_gate_tests;
#[cfg(test)]
mod rate_limit_tests;
#[cfg(test)]
mod rc_idle_limit_tests;
#[cfg(test)]
mod rc_no_common_codec_tests;
#[cfg(test)]
mod rc_request_ceiling_tests;
#[cfg(test)]
mod rc_session_limits_tests;
#[cfg(test)]
mod rc_session_policy_tests;
#[cfg(test)]
mod relay_allowance_tests;
#[cfg(test)]
mod relay_region_tests;
#[cfg(test)]
mod remote_control_tests;
#[cfg(test)]
mod remote_recording_tests;
#[cfg(test)]
mod role_reconcile_tests;
#[cfg(test)]
mod role_tests;
#[cfg(test)]
mod room_visibility_tests;
/// FR-102 P9c — the carrier a session rides: the agent records it on
/// `rc:session.stats` once Active, and the server stores it on
/// `remote_sessions.carrier` — a code only, absent read as unknown, never
/// overwritten by a later sample with none.
#[cfg(test)]
mod session_carrier_tests;
/// FR-102 P9b — the post-session rating's server half: a party stores one
/// rating with codes only, everyone else is refused with a code, the kill
/// switch's empty 404, `purge_user`, and the digest's `quality.ratings`.
#[cfg(test)]
mod session_feedback_tests;
#[cfg(test)]
mod ssh_grant_ack_tests;
#[cfg(test)]
mod ssh_service_tests;
/// FR-90 P3-8-1b — an agent session's SSH request is the session's own: held
/// to the vault's ticket, refused at gate 3 until decision 22, never served
/// as the device owner's, every outcome audited as the session's.
#[cfg(test)]
mod ssh_session_ticket_tests;
#[cfg(test)]
mod stats_tests;
#[cfg(test)]
mod subscribe_tests;
#[cfg(test)]
mod tenant_archive_tests;
/// FR-103 — device credentials renew themselves, and a removal ends every
/// earlier token (agents and tunnel clients alike).
#[cfg(test)]
mod token_renewal_tests;
/// FR-111 P4a — the org's on-screen control presets: any member reads them,
/// `MANAGE_TENANT` writes them, a foreign id is a 404, a bad body is refused
/// with a code, and an org keeps at most fifty.
#[cfg(test)]
mod touch_preset_tests;
#[cfg(test)]
mod transfer_activity_tests;
/// FR-90 P3-7-2a — a session's egress, the network module's half: a grant
/// bound at `rc:tunnel.open` only where it holds, its flows held to it and
/// decided for the session, never its device.
#[cfg(test)]
mod tunnel_grant_tests;
#[cfg(test)]
mod tunnel_tests;
/// FR-115 P4b — coturn's per-allocation totals into `turn_bytes`, for the
/// org a charged TURN username names, once per allocation leg.
#[cfg(test)]
mod turn_usage_tests;
#[cfg(test)]
mod tutorial_tests;
#[cfg(test)]
mod usage_ledger_tests;
/// FR-90 P3-4d-1 — what a device reports doing with its leases: kept apart
/// from the vault's decisions, and only for leases released to that device,
/// for that session, in the use's mode and toward its target.
#[cfg(test)]
mod vault_activity_tests;
/// FR-90 P3-4e — the approval a policy may ask for: one card in the
/// session's room, a driver's answer, and the one lease a yes allows.
#[cfg(test)]
mod vault_approval_tests;
/// FR-90 P3-9-1 — a person's `roomler connect`, the vault's half:
/// `rc:vault.connect` decided by Cedar's `secret:connect` for the device's
/// OWNER as its row names them, lent only where `vault.people` lists the
/// organization, never by a policy written for sessions, and taken back when
/// the owner changes or leaves.
#[cfg(test)]
mod vault_connect_tests;
/// FR-90 P3-6b-1 — dynamic secrets, the vault's half: declared with a
/// provider and one audience, holding the issuer's fields alone, leased in
/// `short-lived` as one bundle sealed to the device, the kind and its mode
/// paired by guardrails.
#[cfg(test)]
mod vault_dynamic_tests;
/// FR-90 P3-3a — a device's vault key as the fleet stores it: from every
/// hello, never a malformed one, and gone with the hello that drops it.
#[cfg(test)]
mod vault_key_tests;
/// FR-90 P3-3b — leases: sealed to the device's key, believed only from the
/// session record's device at its fence, decided by Cedar with the device's
/// facts from its row, recorded before they are sent.
#[cfg(test)]
mod vault_lease_tests;
/// FR-90 P3-4b — what a session may know of the vault: a listing and a
/// description, decided by Cedar's `secret:list`, believed as a lease is,
/// never a value.
#[cfg(test)]
mod vault_meta_tests;
/// FR-90 P3-7-1b — a session's own egress: `rc:vault.net` decided by Cedar's
/// `net:socks` or `net:forward`, believed as a lease is, answered with a grant
/// under its own audience that names exactly what was decided.
#[cfg(test)]
mod vault_net_tests;
/// FR-90 P3-3c — revocation: a session's end or move, a changed, disabled
/// or deleted secret, a new device key, a removed device; told at once on
/// the device's pod or at its sweep, again at every hello, never expired.
#[cfg(test)]
mod vault_revoke_tests;
/// FR-90 P3-8-1a — a session's command on another device: `rc:vault.ssh`
/// decided by Cedar's `ssh:run` over the target's row and the account its
/// SSH policy maps, never the session's own device, answered with a ticket
/// under its own audience that names exactly what was decided.
#[cfg(test)]
mod vault_ssh_tests;
/// FR-90 P3-1 — the vault's store: off until turned on, administrators
/// only and every decision recorded, no answer carrying a value, sealed
/// bytes that do not open where they were moved, no sealing without a KEK.
#[cfg(test)]
mod vault_tests;
#[cfg(test)]
mod ws_auth_tests;

#[cfg(test)]
mod device_share_tests;

#[cfg(test)]
mod account_devices_tests;
