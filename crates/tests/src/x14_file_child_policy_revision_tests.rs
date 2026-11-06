// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! X14 policy revision foundation only: no HTTP, WS, agent, or child transport.
//! The runner must provide its own loopback MongoDB, never a configured service.

use bson::{Bson, Document, doc, oid::ObjectId};
use meshharbor_db::models::RcFeaturePolicy;
use meshharbor_remote_control::models::{AccessPolicy, Agent, OsKind};
use meshharbor_services::dao::{agent::AgentDao, tenant::TenantDao};
use mongodb::{Client, Database, options::ClientOptions};
use std::{future::Future, sync::Arc, time::Duration};

async fn with_database<F, Fut>(exercise: F)
where
    F: FnOnce(Database) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let url = std::env::var("MESHHARBOR_X14_TEST_MONGO_URL")
        .or_else(|_| std::env::var("MESHHARBOR__DATABASE__URL"))
        .unwrap_or_else(|_| "mongodb://127.0.0.1:27019".to_string());
    let port = url
        .strip_prefix("mongodb://127.0.0.1:")
        .or_else(|| url.strip_prefix("mongodb://localhost:"))
        .and_then(|s| s.strip_suffix('/').or(Some(s)))
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|p| *p > 0)
        .expect("X14 Mongo URL must be loopback-only, without credentials or options");
    let mut options = ClientOptions::parse(format!("mongodb://127.0.0.1:{port}/"))
        .await
        .unwrap();
    options.max_pool_size = Some(2);
    options.server_selection_timeout = Some(Duration::from_secs(3));
    let client = Client::with_options(options).unwrap();
    let database = client.database(&format!("mh_x14_policy_{}", uuid::Uuid::new_v4().simple()));
    let mut task = tokio::spawn(exercise(database.clone()));
    let outcome = tokio::time::timeout(Duration::from_secs(45), &mut task).await;
    if outcome.is_err() {
        task.abort();
        let _ = task.await;
    }
    // Reached even after an exercise panic; never delete any pre-existing DB.
    let cleanup = tokio::time::timeout(Duration::from_secs(5), database.drop()).await;
    client.shutdown().await;
    cleanup.expect("X14 database cleanup timed out").unwrap();
    outcome.expect("X14 policy exercise timed out").unwrap();
}

async fn new_agent(dao: &AgentDao, tenant: ObjectId, owner: ObjectId) -> Agent {
    dao.create(
        tenant,
        owner,
        "X14 synthetic device".into(),
        ObjectId::new().to_hex(),
        OsKind::Linux,
        "0.0.0-test".into(),
        "synthetic-unused-token-hash".into(),
        None,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn x14_policy_revisions_advance_across_restore_and_concurrent_agent_writes() {
    with_database(|db| async move {
        let tenants = TenantDao::new(&db);
        let tenant = tenants
            .create("X14".into(), "x14-policy".into(), ObjectId::new())
            .await
            .unwrap();
        let tid = tenant.id.unwrap();
        let initial = tenant.security_revision().unwrap();
        let restricted = tenants
            .set_rc_session_policy(tid, None, Some(RcFeaturePolicy::Off), None)
            .await
            .unwrap();
        let restored = tenants
            .set_rc_session_policy(tid, None, Some(RcFeaturePolicy::On), None)
            .await
            .unwrap();
        assert!(restricted.security_revision().unwrap() > initial);
        assert!(restored.security_revision().unwrap() > restricted.security_revision().unwrap());

        let agents = Arc::new(AgentDao::new(&db));
        let owner = ObjectId::new();
        let agent = new_agent(&agents, tid, owner).await;
        let aid = agent.id.unwrap();
        assert_eq!(agent.access_policy_revision(), Some(1));
        let restricted = AccessPolicy {
            allowed_user_ids: vec![ObjectId::new()],
            ..Default::default()
        };
        assert!(
            agents
                .update_access_policy(tid, aid, &restricted)
                .await
                .unwrap()
        );
        assert_eq!(
            agents
                .base
                .find_by_id(aid)
                .await
                .unwrap()
                .access_policy_revision(),
            Some(2)
        );
        assert!(
            agents
                .update_access_policy(tid, aid, &AccessPolicy::default())
                .await
                .unwrap()
        );
        assert_eq!(
            agents
                .base
                .find_by_id(aid)
                .await
                .unwrap()
                .access_policy_revision(),
            Some(3)
        );
        let mut writers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let agents = agents.clone();
            writers.spawn(async move {
                assert!(
                    agents
                        .update_access_policy(tid, aid, &AccessPolicy::default())
                        .await
                        .unwrap()
                );
            });
        }
        while let Some(result) = writers.join_next().await {
            result.unwrap();
        }
        assert_eq!(
            agents
                .base
                .find_by_id(aid)
                .await
                .unwrap()
                .access_policy_revision(),
            Some(11)
        );
        let new_owner = ObjectId::new();
        assert!(agents.update_owner(tid, aid, new_owner).await.unwrap());
        assert!(agents.update_owner(tid, aid, owner).await.unwrap());
        let row = agents.base.find_by_id(aid).await.unwrap();
        assert_eq!(row.access_policy_revision(), Some(13));
        assert_eq!(row.owner_user_id, owner);
        assert!(
            !agents
                .update_access_policy(ObjectId::new(), aid, &restricted)
                .await
                .unwrap()
        );
        assert!(
            !agents
                .update_owner(ObjectId::new(), aid, new_owner)
                .await
                .unwrap()
        );
        assert_eq!(
            agents
                .base
                .find_by_id(aid)
                .await
                .unwrap()
                .access_policy_revision(),
            Some(13)
        );
        assert!(agents.soft_delete(tid, aid).await.unwrap());
        assert_eq!(
            agents
                .base
                .find_by_id(aid)
                .await
                .unwrap()
                .access_policy_revision(),
            Some(14)
        );
        assert!(
            !agents
                .update_access_policy(tid, aid, &restricted)
                .await
                .unwrap()
        );
        assert!(!agents.update_owner(tid, aid, new_owner).await.unwrap());
        let row = agents.base.find_by_id(aid).await.unwrap();
        assert_eq!(row.access_policy_revision(), Some(14));
        assert_eq!(row.owner_user_id, owner);
    })
    .await;
}

#[tokio::test]
async fn x14_invalid_agent_revisions_deny_authority_without_blocking_restrictions() {
    with_database(|db| async move {
        let agents = AgentDao::new(&db);
        let raw = db.collection::<Document>(Agent::COLLECTION);
        let tid = ObjectId::new();
        let owner = ObjectId::new();
        for invalid in [
            Bson::Null,
            Bson::Int32(1),
            Bson::Int64(0),
            Bson::Int64(-1),
            Bson::Int64(i64::MAX),
            Bson::Double(1.0),
            Bson::String("1".into()),
            Bson::Boolean(true),
            Bson::Document(doc! { "value": 1_i64 }),
            Bson::Array(vec![Bson::Int64(1)]),
        ] {
            let aid = new_agent(&agents, tid, owner).await.id.unwrap();
            raw.update_one(
                doc! { "_id": aid },
                doc! { "$set": { "access_policy_rev": invalid.clone() } },
            )
            .await
            .unwrap();
            let row = agents.base.find_by_id(aid).await.unwrap();
            assert_eq!(row.access_policy_rev.as_ref(), Some(&invalid));
            assert_eq!(row.access_policy_revision(), None);
            // A full BSON round trip must preserve the invalid value too.
            assert_eq!(
                bson::to_document(&row).unwrap().get("access_policy_rev"),
                Some(&invalid)
            );
            let denied = AccessPolicy {
                allowed_user_ids: vec![ObjectId::new()],
                ..Default::default()
            };
            assert!(
                agents
                    .update_access_policy(tid, aid, &denied)
                    .await
                    .unwrap()
            );
            let stored = raw.find_one(doc! { "_id": aid }).await.unwrap().unwrap();
            assert_eq!(stored.get("access_policy_rev"), Some(&invalid));
            assert_eq!(
                stored.get_document("access_policy").unwrap(),
                &bson::to_document(&denied).unwrap()
            );
            assert!(
                agents
                    .update_owner(tid, aid, ObjectId::new())
                    .await
                    .unwrap()
            );
            assert!(
                agents
                    .update_access_policy(tid, aid, &AccessPolicy::default())
                    .await
                    .unwrap()
            );
            let row = agents.base.find_by_id(aid).await.unwrap();
            assert_eq!(row.access_policy_rev.as_ref(), Some(&invalid));
            assert_eq!(row.access_policy_revision(), None);
        }
    })
    .await;
}

#[tokio::test]
async fn x14_legacy_and_exhausted_agent_revisions_fail_closed_without_read_repair() {
    with_database(|db| async move {
        let agents = AgentDao::new(&db);
        let raw = db.collection::<Document>(Agent::COLLECTION);
        let tid = ObjectId::new();
        let aid = new_agent(&agents, tid, ObjectId::new()).await.id.unwrap();
        raw.update_one(
            doc! { "_id": aid },
            doc! { "$unset": { "access_policy_rev": "" } },
        )
        .await
        .unwrap();
        let legacy = agents.base.find_by_id(aid).await.unwrap();
        assert_eq!(legacy.access_policy_revision(), None);
        assert!(
            !bson::to_document(&legacy)
                .unwrap()
                .contains_key("access_policy_rev")
        );
        assert!(
            !raw.find_one(doc! { "_id": aid })
                .await
                .unwrap()
                .unwrap()
                .contains_key("access_policy_rev")
        );
        // Only an actual policy write initializes a missing legacy counter.
        assert!(
            agents
                .update_access_policy(tid, aid, &AccessPolicy::default())
                .await
                .unwrap()
        );
        assert_eq!(
            agents
                .base
                .find_by_id(aid)
                .await
                .unwrap()
                .access_policy_revision(),
            Some(1)
        );
        raw.update_one(
            doc! { "_id": aid },
            doc! { "$set": { "access_policy_rev": i64::MAX - 1 } },
        )
        .await
        .unwrap();
        assert_eq!(
            agents
                .base
                .find_by_id(aid)
                .await
                .unwrap()
                .access_policy_revision(),
            Some(i64::MAX - 1)
        );
        assert!(
            agents
                .update_access_policy(tid, aid, &AccessPolicy::default())
                .await
                .unwrap()
        );
        assert!(
            agents
                .update_owner(tid, aid, ObjectId::new())
                .await
                .unwrap()
        );
        let exhausted = agents.base.find_by_id(aid).await.unwrap();
        assert_eq!(exhausted.access_policy_revision(), None);
        assert_eq!(exhausted.access_policy_rev, Some(Bson::Int64(i64::MAX)));
    })
    .await;
}
