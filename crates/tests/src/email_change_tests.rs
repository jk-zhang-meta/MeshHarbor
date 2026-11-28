//! Account credential changes are one user-document transaction, not account creation.
use crate::fixtures::test_app::TestApp;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn capture_mail() -> (
    u16,
    tokio::sync::mpsc::Receiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                write
                    .write_all(b"220 localhost test SMTP\r\n")
                    .await
                    .unwrap();
                let mut data = None::<String>;
                while let Some(line) = lines.next_line().await.unwrap() {
                    if let Some(body) = data.as_mut() {
                        if line == "." {
                            tx.send(data.take().unwrap()).await.unwrap();
                            write.write_all(b"250 queued\r\n").await.unwrap();
                        } else {
                            body.push_str(&line);
                            body.push_str("\r\n");
                        }
                    } else if line.starts_with("DATA") {
                        data = Some(String::new());
                        write.write_all(b"354 send message\r\n").await.unwrap();
                    } else if line.starts_with("QUIT") {
                        write.write_all(b"221 bye\r\n").await.unwrap();
                        break;
                    } else {
                        write.write_all(b"250 OK\r\n").await.unwrap();
                    }
                }
            });
        }
    });
    (port, rx, task)
}

#[tokio::test]
async fn email_change_requires_password_and_confirms_same_account_once() {
    let (port, mut mail, task) = capture_mail().await;
    let app = TestApp::spawn_with_settings(|s| {
        s.email.smtp_host = Some("127.0.0.1".into());
        s.email.smtp_port = Some(port);
    })
    .await;
    let old = app
        .register_user(
            "before@example.test",
            "internal",
            "Same account",
            "Old.Password. ",
            None,
            None,
        )
        .await;
    let denied = app.auth_post("/api/auth/email-change/request", &old.access_token)
        .json(&json!({"email":"after@example.test","current_password":"wrong","new_password":"New.Password. "}))
        .send().await.unwrap();
    assert_eq!(
        denied.status().as_u16(),
        401,
        "stale access alone cannot change credentials"
    );
    let requested = app.auth_post("/api/auth/email-change/request", &old.access_token)
        .json(&json!({"email":" After@Example.test ","current_password":"Old.Password. ","new_password":"New.Password. "}))
        .send().await.unwrap();
    assert_eq!(requested.status().as_u16(), 200);
    let receipt: Value = requested.json().await.unwrap();
    assert!(receipt.get("token").is_none());
    let rid = receipt["request_id"].as_str().unwrap();
    let raw = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let body = mail
                .recv()
                .await
                .unwrap()
                .replace("=\r\n", "")
                .replace("=3D", "=");
            if body.contains("/verify-email-change?") {
                break body;
            }
        }
    })
    .await
    .unwrap();
    let token = raw
        .split("#token=")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .next()
        .unwrap();
    assert!(!token.is_empty());
    let confirm = app
        .client
        .post(app.url("/api/auth/email-change/confirm"))
        .json(&json!({"request_id":rid,"token":token}))
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status().as_u16(), 200);
    let replay = app
        .client
        .post(app.url("/api/auth/email-change/confirm"))
        .json(&json!({"request_id":rid,"token":token}))
        .send()
        .await
        .unwrap();
    assert!(!replay.status().is_success());
    let stale = app
        .auth_get("/api/auth/me", &old.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 401);
    let login = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({"email":"after@example.test","password":"New.Password. "}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status().as_u16(), 200);
    let user: Value = login.json().await.unwrap();
    assert_eq!(user["user"]["id"], old.id);
    assert_eq!(user["user"]["email_verified"], true);
    task.abort();
}

#[tokio::test]
async fn email_change_atomic_collision_supersede_and_concurrent_consume() {
    use bson::{DateTime, doc, oid::ObjectId};
    use meshharbor_services::dao::{
        email_change::{self, PendingEmailChange},
        user::UserDao,
    };
    let app = TestApp::spawn().await;
    let one = app
        .register_user(
            "first@example.test",
            "first",
            "First",
            "First.Password.",
            None,
            None,
        )
        .await;
    let _two = app
        .register_user(
            "occupied@example.test",
            "second",
            "Second",
            "Second.Password.",
            None,
            None,
        )
        .await;
    let dao = UserDao::new(&app.db);
    let user = dao
        .base
        .find_by_id(ObjectId::parse_str(&one.id).unwrap())
        .await
        .unwrap();
    let pending = |email: &str| PendingEmailChange {
        request_id: ObjectId::new(),
        email: email.into(),
        token_hash: "fixture-hash".into(),
        expires_at: DateTime::from_millis(DateTime::now().timestamp_millis() + 60_000),
        security_revision: user.security_revision().unwrap(),
        approval_revision: user.account_approval.revision,
        new_password_hash: None,
    };
    let collision = pending("OCCUPIED@example.test");
    assert!(
        email_change::begin(&app.db, &user, collision.clone())
            .await
            .unwrap()
    );
    let collection = app.db.collection::<bson::Document>("users");
    let before = collection
        .find_one(doc! {"_id":user.id})
        .await
        .unwrap()
        .unwrap();
    assert!(
        email_change::confirm(&app.db, collision.request_id, "fixture-hash")
            .await
            .is_err(),
        "normalized email uniqueness must be atomic at write, not check-then-write"
    );
    assert_eq!(
        collection
            .find_one(doc! {"_id":user.id})
            .await
            .unwrap()
            .unwrap(),
        before,
        "collision consumes nothing and changes no credential"
    );
    let old = pending("superseded@example.test");
    let latest = pending("latest@example.test");
    assert!(
        email_change::begin(&app.db, &user, old.clone())
            .await
            .unwrap()
    );
    assert!(
        email_change::begin(&app.db, &user, latest.clone())
            .await
            .unwrap()
    );
    assert!(
        email_change::confirm(&app.db, old.request_id, "fixture-hash")
            .await
            .unwrap()
            .is_none()
    );
    let (a, b) = tokio::join!(
        email_change::confirm(&app.db, latest.request_id, "fixture-hash"),
        email_change::confirm(&app.db, latest.request_id, "fixture-hash")
    );
    assert_eq!(
        usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()),
        1
    );
    let final_user = dao.base.find_by_id(user.id.unwrap()).await.unwrap();
    assert_eq!(final_user.id, user.id);
    assert_eq!(final_user.email, "latest@example.test");
    assert_eq!(
        final_user.security_revision(),
        Some(user.security_revision().unwrap() + 1)
    );
    assert_eq!(
        final_user.account_approval.revision,
        user.account_approval.revision + 1
    );
    assert!(
        !email_change::begin(&app.db, &user, pending("stale@example.test"))
            .await
            .unwrap(),
        "old step-up snapshot cannot supersede newly confirmed credentials"
    );
}

#[tokio::test]
async fn email_stepup_budget_cannot_be_reset_by_changing_destination() {
    let app = TestApp::spawn_with_settings(|s| {
        s.app.auth_rate_limit_burst = 2;
        s.app.auth_rate_limit_per_min = 1;
    })
    .await;
    let user = app
        .register_user(
            "stepup@example.test",
            "stepup",
            "Stepup",
            "Correct.Password.",
            None,
            None,
        )
        .await;
    for (i, expected) in [(0, 401), (1, 401), (2, 429)] {
        let result = app
            .auth_post("/api/auth/email-change/request", &user.access_token)
            .json(&json!({"email":format!("different{i}@example.test"),"current_password":"wrong"}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            result.status().as_u16(),
            expected,
            "destination is not the authenticated account being guessed"
        );
    }
}

#[tokio::test]
async fn email_change_write_rejection_preserves_pending_and_credentials() {
    use bson::{DateTime, doc, oid::ObjectId};
    use meshharbor_services::dao::{
        email_change::{self, PendingEmailChange},
        user::UserDao,
    };
    let app = TestApp::spawn().await;
    let u = app
        .register_user(
            "writebefore@example.test",
            "writebefore",
            "Write",
            "Before.Password.",
            None,
            None,
        )
        .await;
    let user = UserDao::new(&app.db)
        .base
        .find_by_id(ObjectId::parse_str(&u.id).unwrap())
        .await
        .unwrap();
    let pending = PendingEmailChange {
        request_id: ObjectId::new(),
        email: "blocked@example.test".into(),
        token_hash: "known-test-only".into(),
        expires_at: DateTime::from_millis(DateTime::now().timestamp_millis() + 60_000),
        security_revision: user.security_revision().unwrap(),
        approval_revision: user.account_approval.revision,
        new_password_hash: Some("test-new-hash".into()),
    };
    assert!(
        email_change::begin(&app.db, &user, pending.clone())
            .await
            .unwrap()
    );
    let c = app.db.collection::<bson::Document>("users");
    let before = c.find_one(doc! {"_id":user.id}).await.unwrap().unwrap();
    // Isolated database validator rejects the entire Mongo write. No global failpoint.
    app.db.run_command(doc!{"collMod":"users","validator":{"email":{"$ne":"blocked@example.test"}},"validationLevel":"strict"}).await.unwrap();
    assert!(
        email_change::confirm(&app.db, pending.request_id, "known-test-only")
            .await
            .is_err()
    );
    assert_eq!(
        c.find_one(doc! {"_id":user.id}).await.unwrap().unwrap(),
        before
    );
    app.db
        .run_command(doc! {"collMod":"users","validator":{}})
        .await
        .unwrap();
    let after = email_change::confirm(&app.db, pending.request_id, "known-test-only")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.id, user.id);
    assert_eq!(after.email, "blocked@example.test");
    assert_eq!(after.password_hash.as_deref(), Some("test-new-hash"));
}
