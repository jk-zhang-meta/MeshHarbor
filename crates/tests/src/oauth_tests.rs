// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use crate::fixtures::test_app::TestApp;

#[tokio::test]
async fn oauth_redirect_google_returns_302() {
    let app = TestApp::spawn_with_oauth().await;

    let resp = app
        .client
        .get(app.url("/api/oauth/google"))
        .send()
        .await
        .unwrap();

    // Should redirect to Google's OAuth consent page
    assert_eq!(resp.status().as_u16(), 307);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://accounts.google.com/o/oauth2/v2/auth"));
    assert!(location.contains("client_id=test-google-id"));
    assert!(location.contains("redirect_uri="));
    assert!(location.contains("scope=email+profile"));
}

#[tokio::test]
async fn oauth_redirect_github_returns_302() {
    let app = TestApp::spawn_with_oauth().await;

    let resp = app
        .client
        .get(app.url("/api/oauth/github"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 307);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://github.com/login/oauth/authorize"));
    assert!(location.contains("client_id=test-github-id"));
}

#[tokio::test]
async fn oauth_redirect_facebook_returns_302() {
    let app = TestApp::spawn_with_oauth().await;

    let resp = app
        .client
        .get(app.url("/api/oauth/facebook"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 307);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://www.facebook.com/v18.0/dialog/oauth"));
}

#[tokio::test]
async fn oauth_redirect_linkedin_returns_302() {
    let app = TestApp::spawn_with_oauth().await;

    let resp = app
        .client
        .get(app.url("/api/oauth/linkedin"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 307);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://www.linkedin.com/oauth/v2/authorization"));
}

#[tokio::test]
async fn oauth_redirect_microsoft_returns_302() {
    let app = TestApp::spawn_with_oauth().await;

    let resp = app
        .client
        .get(app.url("/api/oauth/microsoft"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 307);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"));
}

#[tokio::test]
async fn oauth_redirect_unknown_provider_returns_400() {
    let app = TestApp::spawn_with_oauth().await;

    let resp = app
        .client
        .get(app.url("/api/oauth/unknown"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn oauth_callback_without_code_returns_error() {
    let app = TestApp::spawn_with_oauth().await;

    let resp = app
        .client
        .get(app.url("/api/oauth/callback/google"))
        .send()
        .await
        .unwrap();

    // Missing query params → 400
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn oauth_user_dao_find_or_create_new_user() {
    let app = TestApp::spawn().await;

    let user = app
        .db
        .collection::<bson::Document>("users")
        .count_documents(bson::doc! {})
        .await
        .unwrap();
    assert_eq!(user, 0);

    // Create user via OAuth DAO
    let dao = meshharbor_services::dao::user::UserDao::new(&app.db);
    let user = dao
        .find_or_create_by_oauth(
            "google",
            "google-123",
            "oauth@test.com",
            "OAuth User",
            Some("https://example.com/avatar.jpg"),
            true,
            None,
        )
        .await
        .unwrap()
        .user;

    assert_eq!(user.email, "oauth@test.com");
    assert_eq!(user.display_name, "OAuth User");
    assert_eq!(
        user.avatar,
        Some("https://example.com/avatar.jpg".to_string())
    );
    assert!(user.is_verified);
    assert!(user.password_hash.is_none());
    assert_eq!(user.oauth_providers.len(), 1);
    assert_eq!(user.oauth_providers[0].provider, "google");
    assert_eq!(user.oauth_providers[0].provider_id, "google-123");
}

#[tokio::test]
async fn oauth_user_dao_links_existing_user() {
    let app = TestApp::spawn().await;

    // First, register a regular user
    let resp = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "email": "existing@test.com",
            "username": "existing",
            "display_name": "Existing User",
            "password": "Password123!",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);

    // Complete the sign-up. Registration alone leaves `is_verified: false` —
    // an address typed into a form, not a proven one — and OAuth deliberately
    // refuses to link into an account in that state (see the eviction test
    // below). This is the ordinary "user finished activation, then adds a
    // social login" case.
    app.activate_user("existing@test.com").await;

    // Now use OAuth with the same email
    let dao = meshharbor_services::dao::user::UserDao::new(&app.db);
    let user = dao
        .find_or_create_by_oauth(
            "github",
            "gh-456",
            "existing@test.com",
            "GitHub User",
            None,
            true,
            None,
        )
        .await
        .unwrap()
        .user;

    // Should be the same user, with OAuth linked
    assert_eq!(user.email, "existing@test.com");
    assert_eq!(user.username, "existing"); // keeps original username
    assert_eq!(user.oauth_providers.len(), 1);
    assert_eq!(user.oauth_providers[0].provider, "github");
    assert_eq!(user.oauth_providers[0].provider_id, "gh-456");
}

#[tokio::test]
async fn oauth_user_dao_does_not_duplicate_provider() {
    let app = TestApp::spawn().await;

    let dao = meshharbor_services::dao::user::UserDao::new(&app.db);

    // Create via OAuth
    dao.find_or_create_by_oauth(
        "google",
        "g-789",
        "nodupe@test.com",
        "No Dupe",
        None,
        true,
        None,
    )
    .await
    .unwrap();

    // Call again with same provider/id
    let user = dao
        .find_or_create_by_oauth(
            "google",
            "g-789",
            "nodupe@test.com",
            "No Dupe",
            None,
            true,
            None,
        )
        .await
        .unwrap()
        .user;

    // Should still have only 1 oauth provider, not 2
    assert_eq!(user.oauth_providers.len(), 1);
}

/// nOAuth: an identity whose email the provider did NOT verify must never
/// inherit an account that happens to share the address. Microsoft's
/// multi-tenant endpoint returns a tenant-settable `mail`, so treating it as
/// an account key was an account-takeover path.
///
/// When the address is free it gets its own account — holding a `.invalid`
/// placeholder, never the asserted address. When the address is already taken
/// it is REFUSED at step 2c: a parallel account is *possible* now that the
/// placeholder removed the collision, but it would be invisible to whoever owns
/// the address. Either way the identity is never linked to the existing user,
/// which is the takeover-relevant property.
#[tokio::test]
async fn unverified_oauth_email_never_links_into_an_existing_account() {
    let app = TestApp::spawn().await;
    let dao = meshharbor_services::dao::user::UserDao::new(&app.db);

    // Victim signs up normally AND completes activation, so the account has
    // actually PROVEN the address. The activation is load-bearing for the last
    // assertion in this test: step 2a links a verified identity only into an
    // account that is itself verified, and an unactivated one would be evicted
    // at 2b instead (see
    // `an_unactivated_signup_cannot_hold_an_address_against_a_proven_identity`).
    let victim = dao
        .create(
            "victim@corp.example".to_string(),
            "victim".to_string(),
            "Victim".to_string(),
            "hash".to_string(),
            None,
        )
        .await
        .unwrap();
    app.activate_user("victim@corp.example").await;

    // Attacker signs in via a provider asserting the SAME address with no
    // verification claim. This is REFUSED, not given a separate account.
    //
    // The original test demanded "its OWN account" and could never pass:
    // `users.email` is uniquely indexed, so a second row with the victim's
    // address cannot exist. The insert collided on EMAIL while the retry loop
    // assumed a USERNAME clash, and the whole thing surfaced as "Failed to
    // generate unique username after retries" — which is why this test died in
    // setup rather than on its assertion, leaving the protection unverified.
    //
    // Refusal is the correct outcome and was always the effective one: a
    // takeover needs the identity to be LINKED to the victim, and it never is.
    //
    // It is now a CHOICE rather than a forced outcome — #613's placeholder
    // means the create could succeed — so this assertion is pinning a policy,
    // not a mechanism. If someone deliberately changes 2c to mint the parallel
    // account, this is the test to update; the two below are the ones that
    // must not move.
    let err = dao
        .find_or_create_by_oauth(
            "microsoft",
            "ms-attacker-oid",
            "victim@corp.example",
            "Not The Victim",
            None,
            false,
            None,
        )
        .await
        .expect_err("unverified email must not resolve to the existing account");
    let msg = err.to_string();
    assert!(
        msg.contains("did not") && msg.contains("verify"),
        "the refusal must name its reason, not blame the username: {msg}"
    );

    // The victim's account is untouched — no provider grafted onto it, which
    // is the property that actually matters.
    let victim_after = dao.find_by_email("victim@corp.example").await.unwrap();
    assert_eq!(victim_after.id.unwrap(), victim.id.unwrap());
    assert!(victim_after.oauth_providers.is_empty());

    // ...and no second account was created behind the scenes.
    let all_with_email = app
        .db
        .collection::<bson::Document>("users")
        .count_documents(bson::doc! { "email": "victim@corp.example" })
        .await
        .unwrap();
    assert_eq!(all_with_email, 1, "no shadow account for the same address");

    // An unverified identity on a FRESH address is unaffected — it still gets
    // an account. The refusal above is about the collision, not about being
    // unverified.
    let fresh = dao
        .find_or_create_by_oauth(
            "microsoft",
            "ms-other-oid",
            "someone-else@corp.example",
            "Someone Else",
            None,
            false,
            None,
        )
        .await
        .expect("an unverified identity on a free address still signs up")
        .user;
    assert_ne!(fresh.id.unwrap(), victim.id.unwrap());

    // A VERIFIED provider email still links, as before.
    let linked = dao
        .find_or_create_by_oauth(
            "google",
            "g-verified",
            "victim@corp.example",
            "Victim",
            None,
            true,
            None,
        )
        .await
        .unwrap()
        .user;
    assert_eq!(linked.id.unwrap(), victim.id.unwrap());
}

/// Refusing to *link* an unverified assertion is only half of it: `users.email`
/// is a UNIQUE index, so writing the claimed address there at all would let a
/// hostile tenant RESERVE an address it does not own — blocking the real
/// owner's sign-up and collecting invites addressed to them. Same takeover,
/// one step further back.
#[tokio::test]
async fn an_unverified_identity_does_not_reserve_the_asserted_address() {
    let app = TestApp::spawn().await;
    let dao = meshharbor_services::dao::user::UserDao::new(&app.db);

    // Attacker gets there first, asserting an address it does not own.
    let attacker = dao
        .find_or_create_by_oauth(
            "microsoft",
            "ms-attacker-oid",
            "victim@corp.example",
            "Not The Victim",
            None,
            false,
            None,
        )
        .await
        .unwrap()
        .user;

    assert_ne!(
        attacker.email, "victim@corp.example",
        "an unproven claim must never land in the unique key"
    );
    assert!(
        attacker.email.ends_with("@unverified.invalid"),
        "placeholder must be undeliverable, got {}",
        attacker.email
    );
    assert_eq!(
        attacker.unverified_email.as_deref(),
        Some("victim@corp.example"),
        "the claim is still recorded — just not as ownership"
    );
    assert!(!attacker.is_verified);

    // So the address is still free, and its real owner can sign up.
    let victim = dao
        .create(
            "victim@corp.example".to_string(),
            "victim".to_string(),
            "Victim".to_string(),
            "hash".to_string(),
            None,
        )
        .await
        .unwrap();
    assert_ne!(victim.id.unwrap(), attacker.id.unwrap());

    // The unverified identity still signs in, stably, to its own account —
    // the promise the old code broke as soon as the address was taken.
    let again = dao
        .find_or_create_by_oauth(
            "microsoft",
            "ms-attacker-oid",
            "victim@corp.example",
            "Not The Victim",
            None,
            false,
            None,
        )
        .await
        .unwrap()
        .user;
    assert_eq!(again.id.unwrap(), attacker.id.unwrap());
}

/// The mirror image, and the reason the verified side needs a check too: a
/// password sign-up that never activated has not proven its address either, so
/// it cannot hold it against an identity that has.
///
/// Left merged, an attacker who registers `victim@corp` with a password of
/// their choosing and simply waits would end up sharing the victim's account —
/// and could password-log-in the moment the victim clicked the activation mail
/// that lands in the victim's OWN inbox.
#[tokio::test]
async fn an_unactivated_signup_cannot_hold_an_address_against_a_proven_identity() {
    let app = TestApp::spawn().await;
    let dao = meshharbor_services::dao::user::UserDao::new(&app.db);

    // Registered, password known to the attacker, never activated.
    let squatter = dao
        .create(
            "victim@corp.example".to_string(),
            "squatter".to_string(),
            "Squatter".to_string(),
            "attacker-known-hash".to_string(),
            None,
        )
        .await
        .unwrap();
    assert!(!squatter.is_verified);

    // The real owner arrives with an address the provider verified.
    let victim = dao
        .find_or_create_by_oauth(
            "google",
            "g-victim",
            "victim@corp.example",
            "Victim",
            None,
            true,
            None,
        )
        .await
        .unwrap()
        .user;

    assert_ne!(
        victim.id.unwrap(),
        squatter.id.unwrap(),
        "a proven identity must not be merged into an unproven claim"
    );
    assert_eq!(victim.email, "victim@corp.example");
    assert!(victim.is_verified);
    assert!(
        victim.password_hash.is_none(),
        "the attacker's password must not come attached to the account"
    );

    // The claim is evicted, not deleted — the row survives, it just no longer
    // owns the address, and says what it used to claim.
    let evicted = dao.base.find_by_id(squatter.id.unwrap()).await.unwrap();
    assert!(
        evicted.email.ends_with("@unverified.invalid"),
        "evicted claim must release the address, got {}",
        evicted.email
    );
    assert_eq!(
        evicted.unverified_email.as_deref(),
        Some("victim@corp.example")
    );

    // And the address now resolves to the account that proved it.
    let owner = dao.find_by_email("victim@corp.example").await.unwrap();
    assert_eq!(owner.id.unwrap(), victim.id.unwrap());
}
