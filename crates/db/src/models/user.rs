// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    /// The account's address, and a UNIQUE index — so whatever is here is
    /// *reserved*. Only an address the account has PROVEN belongs here (a
    /// password sign-up that completed activation, or an OAuth provider that
    /// verified it). Everything else goes to `unverified_email`.
    pub email: String,
    /// An address that was claimed but never proven: asserted by an OAuth
    /// provider without a verification claim, or evicted from an account that
    /// held it without proof. Kept for support and for a future claim flow —
    /// deliberately NOT indexed and never a lookup key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unverified_email: Option<String>,
    pub username: String,
    pub display_name: String,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub status: UserStatusInfo,
    #[serde(default)]
    pub presence: Presence,
    #[serde(default = "default_locale")]
    pub locale: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub is_verified: bool,
    /// Missing on legacy documents means unreviewed, never approved.
    #[serde(default)]
    pub account_approval: AccountApproval,
    #[serde(default)]
    pub is_mfa_enabled: bool,
    pub last_active_at: Option<DateTime>,
    #[serde(default)]
    pub oauth_providers: Vec<OAuthProvider>,
    #[serde(default)]
    pub notification_preferences: NotificationPrefs,
    /// FR-12 P3 — the tutorial's own state, mirrored here so it follows the
    /// PERSON rather than the browser profile. `#[serde(default)]` because
    /// every user document predates this field.
    #[serde(default)]
    pub tutorial: TutorialState,
    /// FR-88 P1a — where this account came from, written ONCE at creation and
    /// never updated. `None` for every account that predates the field and
    /// for every sign-up that arrived without a campaign.
    ///
    /// ⚠️ Never user-facing: no response DTO carries it, and no handler may
    /// serialise a `User` wholesale (`routes::auth::UserResponse::of` is the
    /// seam that proves it). Never logged at `info`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signup_attribution: Option<SignupAttribution>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

/// Account admission is independent of email verification and tenant roles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountApprovalState {
    Pending,
    Approved,
    Rejected,
    Suspended,
    #[default]
    LegacyUnreviewed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountApproval {
    #[serde(default)]
    pub state: AccountApprovalState,
    pub reviewed_by: Option<ObjectId>,
    pub reviewed_at: Option<DateTime>,
    /// CAS revision and user-token revocation generation.
    #[serde(default)]
    pub revision: u32,
}

impl AccountApproval {
    pub fn pending() -> Self {
        Self {
            state: AccountApprovalState::Pending,
            ..Self::default()
        }
    }
}

/// FR-88 — the campaign a sign-up arrived from, as stored on `users`.
///
/// Every field is optional and every value has already been through
/// `roomler_core::attribution::sanitize` (trimmed, printable ASCII, at most
/// [`MAX_ATTRIBUTION_VALUE_LEN`] characters; the referrer is a bare host, the
/// landing path starts with `/`). The struct is only ever built from that
/// sanitiser or read back from Mongo, so a value here is safe to group on.
///
/// `captured_at` is when the server first saw the values — the landing, for
/// an OAuth sign-up that parked them in Redis; the request, for a password
/// one. It is NOT the account's `created_at`, which is the join key the
/// activation view uses.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SignupAttribution {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    /// A host (`youtube.com`), never a URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_host: Option<String>,
    /// The page the visitor landed on, path only (`/blog/x/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landing_path: Option<String>,
    /// The answer to "How did you hear about Roomler?" — a slug from the
    /// register form's select, or whatever the client sent within the same
    /// character rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_reported: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<DateTime>,
}

/// The longest value any attribution field keeps. A UTM value is a slug the
/// operator chose; 64 is generous for one and still obviously a ceiling.
pub const MAX_ATTRIBUTION_VALUE_LEN: usize = 64;

impl SignupAttribution {
    /// True when no field carries a value — the shape the sanitiser turns
    /// into `None` rather than storing an empty subdocument.
    pub fn is_empty(&self) -> bool {
        self.source.is_none()
            && self.medium.is_none()
            && self.campaign.is_none()
            && self.content.is_none()
            && self.term.is_none()
            && self.referrer_host.is_none()
            && self.landing_path.is_none()
            && self.self_reported.is_none()
    }
}

/// FR-12 P3 — tutorial progress, server-side.
///
/// The client keeps the same state in `localStorage` and works entirely
/// without this; the mirror exists so someone who did the tour on their
/// laptop is not walked through it again on their phone.
///
/// ⚠️ `done` is CLIENT-SUPPLIED and lands on the caller's own user document,
/// so it is bounded on write (`MAX_TUTORIAL_CHAPTERS` ids, each
/// `MAX_TUTORIAL_CHAPTER_ID_LEN`). Without a bound this is an unbounded
/// write primitive against your own row — small, but there is no reason to
/// leave it open.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TutorialState {
    /// Chapter ids the user has ticked off. A SET in spirit; stored as a
    /// list because that is what the client holds and the order it ticks
    /// them in is mildly interesting.
    #[serde(default)]
    pub done: Vec<String>,
    /// When the welcome tour first auto-opened for this user. Presence is
    /// the whole signal — it gates the auto-open, and it is never cleared by
    /// normal use, so nobody is ambushed twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_at: Option<DateTime>,
}

/// A tutorial has chapters in the single digits; 64 is room to grow with a
/// ceiling that is still obviously a ceiling.
pub const MAX_TUTORIAL_CHAPTERS: usize = 64;
/// Chapter ids are slugs (`get-started`, `remote-desktop`).
pub const MAX_TUTORIAL_CHAPTER_ID_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserStatusInfo {
    pub text: Option<String>,
    pub emoji: Option<String>,
    pub expires_at: Option<DateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Online,
    Idle,
    Dnd,
    #[default]
    Offline,
    Invisible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub provider: String,
    pub provider_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPrefs {
    #[serde(default = "bool_true")]
    pub email: bool,
    #[serde(default = "bool_true")]
    pub push: bool,
    #[serde(default = "bool_true")]
    pub desktop: bool,
    #[serde(default)]
    pub mute_all: bool,
}

impl Default for NotificationPrefs {
    fn default() -> Self {
        Self {
            email: true,
            push: true,
            desktop: true,
            mute_all: false,
        }
    }
}

fn bool_true() -> bool {
    true
}

fn default_locale() -> String {
    "en-US".to_string()
}

fn default_timezone() -> String {
    "UTC".to_string()
}

impl User {
    pub const COLLECTION: &'static str = "users";
}

#[cfg(test)]
mod account_approval_tests {
    use super::*;
    #[test]
    fn account_approval_legacy_missing_fields_never_auto_approve() {
        let old: AccountApproval = bson::from_document(bson::doc! {}).unwrap();
        assert_eq!(old.state, AccountApprovalState::LegacyUnreviewed);
        assert_eq!(old.revision, 0);
        assert_eq!(
            AccountApproval::pending().state,
            AccountApprovalState::Pending
        );
        let round: AccountApproval =
            bson::from_bson(bson::to_bson(&AccountApproval::pending()).unwrap()).unwrap();
        assert_eq!(round.state, AccountApprovalState::Pending);
    }
}
