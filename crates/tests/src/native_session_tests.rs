//! Explicit PKCE user grants, never device credentials, back native web sessions.
use crate::fixtures::test_app::TestApp;
use base64::{Engine as _,engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
const VERIFIER:&str="native-user-session-test-proof-0123456789abcdefghijklmnopqrstuv";
async fn grant(app:&TestApp,token:&str)->Value {
    let started=app.client.post(app.url("/api/native/device-login"))
        .json(&json!({"device_name":"Explicit GUI login","device_os":"linux","purpose":"user_session","code_challenge":URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),"code_challenge_method":"S256"})).send().await.unwrap();
    assert_eq!(started.status().as_u16(),201);
    let started:Value=started.json().await.unwrap();
    let decision=app.auth_post("/api/native/device-login/decision",token).header("Origin",&app.settings.app.frontend_url)
        .json(&json!({"user_code":started["user_code"],"approve":true})).send().await.unwrap();
    assert_eq!(decision.status().as_u16(),200,"user-only login needs no enrollment/admin role");
    let exchanged=app.client.post(app.url("/api/native/device-login/exchange"))
        .json(&json!({"device_code":started["device_code"],"code_verifier":VERIFIER})).send().await.unwrap();
    assert_eq!(exchanged.status().as_u16(),200);
    let body:Value=exchanged.json().await.unwrap();
    assert!(body.get("enrollment_token").is_none());
    body["native_session"].clone()
}
#[tokio::test]
async fn native_user_session_is_explicit_pkce_bound_and_revocable_after_refresh() {
    let app=TestApp::spawn_with_settings(|s| s.auth.native_device_login_enabled=true).await;
    let user=app.register_user("native-person@example.test","internal","Person","Native.Password.",None,None).await;
    let session=grant(&app,&user.access_token).await;
    assert_eq!(session["user"]["id"],user.id);assert_eq!(session["user"]["email_verified"],true);
    assert_eq!(app.db.collection::<bson::Document>("agents").count_documents(bson::doc!{}).await.unwrap(),0);
    let access=session["access_token"].as_str().unwrap();
    assert_eq!(app.auth_get("/api/auth/me",access).send().await.unwrap().status().as_u16(),200);
    let refreshed=app.client.post(app.url("/api/auth/refresh")).json(&json!({"refresh_token":session["refresh_token"]})).send().await.unwrap();
    assert_eq!(refreshed.status().as_u16(),200);
    let refreshed:Value=refreshed.json().await.unwrap();
    let revoked=app.auth_post("/api/native/session/revoke",access).json(&json!({})).send().await.unwrap();
    assert_eq!(revoked.status().as_u16(),204);
    for token in [access,refreshed["access_token"].as_str().unwrap()] {
        assert_eq!(app.auth_get("/api/auth/me",token).send().await.unwrap().status().as_u16(),401);
    }
    let expired=app.client.post(app.url("/api/auth/refresh")).json(&json!({"refresh_token":refreshed["refresh_token"]})).send().await.unwrap();
    assert_eq!(expired.status().as_u16(),401);
    assert_eq!(app.auth_get("/api/auth/me",&user.access_token).send().await.unwrap().status().as_u16(),200,"revoking one native sid does not revoke unrelated browser sessions");
}
