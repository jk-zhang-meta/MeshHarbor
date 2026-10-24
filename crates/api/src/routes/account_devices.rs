// SPDX-License-Identifier: AGPL-3.0-only
//! Account-owned directory and actor-related grant history, never an org-wide inventory.
use axum::{
    Json,
    extract::{Query, State},
};
use bson::{DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use roomler_ai_db::models::{DeviceShareGrant, Tenant, TenantMember};
use roomler_ai_remote_control::models::{Agent, AgentStatus, OsKind};
use roomler_ai_services::dao::base::DaoError;
use roomler_core::{ApiError, Core, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}
#[derive(Serialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    /// Existing stored Agent.name (registered name), NOT an OS hostname.
    pub machine_name: String,
    pub os: OsKind,
    /// Stored device status, not a promise that a service/PDP is available.
    pub status: AgentStatus,
    pub tenant_id: String,
}
#[derive(Serialize)]
pub struct DevicePage {
    pub items: Vec<DeviceRow>,
    pub page: u64,
    pub total: u64,
}
#[derive(Deserialize)]
struct StoredDevice {
    #[serde(rename = "_id")]
    id: ObjectId,
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    os: OsKind,
    status: AgentStatus,
    tenant_id: ObjectId,
}
#[derive(Deserialize)]
struct Count {
    total: u64,
}
#[derive(Deserialize)]
struct OwnPage {
    items: Vec<StoredDevice>,
    count: Vec<Count>,
}

// Aggregation $type inspects the field itself. Query equality/$type can traverse
// arrays, so keep the first indexable match but fence every identity relationship.
fn scalar_oid(path: &str) -> Document {
    doc! {"$eq":[{"$type":path},"objectId"]}
}
fn exact_oid(path: &str, user: ObjectId) -> Document {
    doc! {"$and":[scalar_oid(path),{"$eq":[path,user]}]}
}
fn false_or_missing(path: &str) -> Document {
    doc! {"$or":[{"$eq":[{"$type":path},"missing"]},
    {"$and":[{"$eq":[{"$type":path},"bool"]},{"$eq":[path,false]}]}]}
}
fn null_or_missing(path: &str) -> Document {
    doc! {"$in":[{"$type":path},["missing","null"]]}
}
/// Neither an org role nor platform admin can broaden ownership. Legacy missing
/// booleans mean false; arrays/null/nonboolean values never satisfy that default.
fn owned_pipeline(user: ObjectId) -> Vec<Document> {
    vec![
        doc! {"$match":{"owner_user_id":user,"deleted_at":null,
        "$expr":{"$and":[exact_oid("$owner_user_id",user),scalar_oid("$tenant_id"),null_or_missing("$deleted_at")]}}},
        doc! {"$lookup":{"from":TenantMember::COLLECTION,"let":{"tid":"$tenant_id"},"pipeline":[
            {"$match":{"user_id":user,"$expr":{"$and":[exact_oid("$user_id",user),scalar_oid("$tenant_id"),scalar_oid("$$tid"),
                {"$eq":["$tenant_id","$$tid"]},false_or_missing("$is_pending")]}}},
            {"$limit":1},{"$project":{"_id":1}}
        ],"as":"_account_membership"}},
        doc! {"$match":{"_account_membership.0":{"$exists":true}}},
        doc! {"$lookup":{"from":Tenant::COLLECTION,"let":{"tid":"$tenant_id"},"pipeline":[
            {"$match":{"deleted_at":null,"$expr":{"$and":[scalar_oid("$_id"),scalar_oid("$$tid"),
                {"$eq":["$_id","$$tid"]},false_or_missing("$is_archived"),null_or_missing("$deleted_at")]}}},
            {"$limit":1},{"$project":{"_id":1}}
        ],"as":"_account_tenant"}},
        doc! {"$match":{"_account_tenant.0":{"$exists":true}}},
    ]
}
async fn aggregate_one(
    core: &Core,
    collection: &str,
    pipeline: Vec<Document>,
) -> Result<Option<Document>, ApiError> {
    let mut cursor = core
        .db
        .collection::<Document>(collection)
        .aggregate(pipeline)
        .max_time(Duration::from_secs(5))
        .await
        .map_err(DaoError::from)?;
    Ok(cursor.try_next().await.map_err(DaoError::from)?)
}
pub async fn list(
    State(core): State<Core>,
    auth: AuthUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<DevicePage>, ApiError> {
    let page = q.page.unwrap_or(1).max(1);
    let size = q.per_page.unwrap_or(25).clamp(1, 100);
    let skip = (page - 1)
        .checked_mul(size)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| ApiError::BadRequest("Page out of range".into()))?;
    let mut pipeline = owned_pipeline(auth.user_id);
    // One facet guarantees items and total use the exact same authorization filter.
    pipeline.push(doc! {"$facet":{
        "items":[{"$sort":{"_id":1}},{"$skip":skip as i64},{"$limit":size as i64},
            {"$project":{"_id":1,"name":1,"display_name":1,"os":1,"status":1,"tenant_id":1}}],
        "count":[{"$count":"total"}]
    }});
    let row = aggregate_one(&core, Agent::COLLECTION, pipeline)
        .await?
        .ok_or_else(|| ApiError::Internal("Missing account directory aggregate".into()))?;
    let row: OwnPage = bson::from_document(row).map_err(DaoError::from)?;
    let total = row.count.first().map(|c| c.total).unwrap_or(0);
    let items = row
        .items
        .into_iter()
        .map(|a| DeviceRow {
            id: a.id.to_hex(),
            name: a
                .display_name
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| a.name.clone()),
            machine_name: a.name,
            os: a.os,
            status: a.status,
            tenant_id: a.tenant_id.to_hex(),
        })
        .collect();
    Ok(Json(DevicePage { items, page, total }))
}

#[derive(Default, Deserialize, Serialize)]
pub struct ShareCounts {
    pub active_devices: u64,
    pub active_grants: u64,
    pub total_records: u64,
    pub expired_records: u64,
    pub revoked_records: u64,
}
#[derive(Serialize)]
pub struct Summary {
    pub own_devices: u64,
    pub received: ShareCounts,
    pub sent: ShareCounts,
}
#[derive(Deserialize)]
struct GrantFacet {
    received: Vec<ShareCounts>,
    sent: Vec<ShareCounts>,
}

fn grant_counts(field: &str, user: ObjectId, now: DateTime) -> Vec<Document> {
    let mut actor = Document::new();
    actor.insert(field, user);
    actor.insert("$expr", exact_oid(&format!("${field}"), user));
    // These are time/ledger labels only, deliberately not DeviceShareGrant::live_at
    // or a PDP: they do not certify membership, consent, MFA, agent existence or connectivity.
    let unrevoked = doc! {"$eq":[{"$ifNull":["$revoked_at",null]},null]};
    let active = doc! {"$and":[unrevoked.clone(),{"$gt":["$expires_at",now]}]};
    let expired = doc! {"$and":[unrevoked,{"$lte":["$expires_at",now]}]};
    let revoked = doc! {"$ne":[{"$ifNull":["$revoked_at",null]},null]};
    vec![
        doc! {"$match":actor},
        // Group by device first so two active grants to one device count once.
        doc! {"$group":{"_id":"$device_id","active_grants":{"$sum":{"$cond":[active,1,0]}},
        "total_records":{"$sum":1},"expired_records":{"$sum":{"$cond":[expired,1,0]}},
        "revoked_records":{"$sum":{"$cond":[revoked,1,0]}}}},
        doc! {"$group":{"_id":null,"active_devices":{"$sum":{"$cond":[{"$gt":["$active_grants",0]},1,0]}},
        "active_grants":{"$sum":"$active_grants"},"total_records":{"$sum":"$total_records"},
        "expired_records":{"$sum":"$expired_records"},"revoked_records":{"$sum":"$revoked_records"}}},
    ]
}
pub async fn summary(State(core): State<Core>, auth: AuthUser) -> Result<Json<Summary>, ApiError> {
    // Capture once for both directions. This is not a cross-collection DB snapshot.
    let now = DateTime::now();
    let mut own = owned_pipeline(auth.user_id);
    own.push(doc! {"$count":"total"});
    let own_devices = match aggregate_one(&core, Agent::COLLECTION, own).await? {
        Some(doc) => {
            bson::from_document::<Count>(doc)
                .map_err(DaoError::from)?
                .total
        }
        None => 0,
    };
    let pipeline = vec![
        doc! {"$match":{"$or":[{"owner_user_id":auth.user_id},{"recipient_user_id":auth.user_id}],
        "$expr":{"$and":[scalar_oid("$owner_user_id"),scalar_oid("$recipient_user_id"),
            scalar_oid("$device_id"),scalar_oid("$tenant_id")]}}},
        doc! {"$facet":{"received":grant_counts("recipient_user_id",auth.user_id,now),"sent":grant_counts("owner_user_id",auth.user_id,now)}},
    ];
    let row = aggregate_one(&core, DeviceShareGrant::COLLECTION, pipeline)
        .await?
        .ok_or_else(|| ApiError::Internal("Missing account share aggregate".into()))?;
    let mut row: GrantFacet = bson::from_document(row).map_err(DaoError::from)?;
    Ok(Json(Summary {
        own_devices,
        received: row.received.pop().unwrap_or_default(),
        sent: row.sent.pop().unwrap_or_default(),
    }))
}
