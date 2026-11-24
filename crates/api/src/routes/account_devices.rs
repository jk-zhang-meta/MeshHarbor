// SPDX-License-Identifier: AGPL-3.0-only
//! Account-owned directory and actor-related grant history, never an org-wide inventory.
use axum::{
    Json,
    extract::{Query, State},
};
use bson::{DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use meshharbor_core::{
    ApiError, Core, extractors::auth::AuthUser, user_analytics::canonical_public_ip,
};
use meshharbor_db::models::{DeviceShareGrant, Tenant, TenantMember};
use meshharbor_remote_control::models::{
    Agent, AgentStatus, DeviceZoneResolution, NetworkZone, OsKind, OverlayNetwork, OverlayNode,
    PeerRelayPolicy, resolve_device_zone,
};
use meshharbor_services::dao::base::DaoError;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, time::Duration};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lat: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lon: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accuracy_radius_km: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_level: Option<meshharbor_remote_control::models::GeoLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_zone_name: Option<String>,
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
    #[serde(default)]
    machine_id: Option<String>,
    #[serde(default)]
    public_ip: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    pinned_zone_id: Option<String>,
    #[serde(default)]
    peer_relay_policy: PeerRelayPolicy,
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
    State(state): State<crate::state::AppState>,
    auth: AuthUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<DevicePage>, ApiError> {
    let core = &state.core;
    let fleet = state.modules.fleet.as_ref();
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
            {"$project":{
                "_id":1,"name":1,"display_name":1,"os":1,"status":1,"tenant_id":1,
                "machine_id":1,"public_ip":1,"country_code":1,"pinned_zone_id":1,
                "peer_relay_policy":1
            }}],
        "count":[{"$count":"total"}]
    }});
    let row = aggregate_one(core, Agent::COLLECTION, pipeline)
        .await?
        .ok_or_else(|| ApiError::Internal("Missing account directory aggregate".into()))?;
    let row: OwnPage = bson::from_document(row).map_err(DaoError::from)?;
    let total = row.count.first().map(|c| c.total).unwrap_or(0);

    // Best-effort enrichment for logical zones and fallback public IP from live overlay_nodes.
    let mut tenant_zones: HashMap<ObjectId, Vec<NetworkZone>> = HashMap::new();
    let mut node_public_ips: HashMap<(ObjectId, String), IpAddr> = HashMap::new();
    if !row.items.is_empty() {
        let mut tenant_ids: Vec<ObjectId> = row.items.iter().map(|a| a.tenant_id).collect();
        tenant_ids.sort_unstable();
        tenant_ids.dedup();
        if let Ok(mut net_cursor) = core
            .db
            .collection::<Document>(OverlayNetwork::COLLECTION)
            .find(doc! { "tenant_id": { "$in": &tenant_ids } })
            .projection(doc! { "tenant_id": 1, "zones": 1 })
            .max_time(Duration::from_secs(3))
            .await
        {
            while let Ok(Some(doc)) = net_cursor.try_next().await {
                if let Ok(tid) = doc.get_object_id("tenant_id")
                    && let Some(raw_zones) = doc.get("zones")
                    && let Ok(zones) = bson::from_bson::<Vec<NetworkZone>>(raw_zones.clone())
                {
                    tenant_zones.insert(tid, zones);
                }
            }
        }
        let missing_ip_machines: Vec<String> = row
            .items
            .iter()
            .filter(|a| {
                fleet
                    .and_then(|f| f.rc_hub.agent_live_public_ip(a.id))
                    .is_none()
                    && a.public_ip
                        .as_deref()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .and_then(canonical_public_ip)
                        .is_none()
            })
            .filter_map(|a| a.machine_id.clone().filter(|m| !m.is_empty()))
            .collect();
        if !missing_ip_machines.is_empty()
            && let Ok(mut node_cursor) = core
                .db
                .collection::<OverlayNode>(OverlayNode::COLLECTION)
                .find(doc! {
                    "tenant_id": { "$in": &tenant_ids },
                    "machine_id": { "$in": &missing_ip_machines },
                    "deleted_at": null
                })
                .max_time(Duration::from_secs(3))
                .await
        {
            while let Ok(Some(n)) = node_cursor.try_next().await {
                if let Some(ip) = n
                    .srflx_endpoints
                    .iter()
                    .chain(&n.lan_endpoints)
                    .filter_map(|e| e.parse::<std::net::SocketAddr>().ok())
                    .find_map(|sa| canonical_public_ip(sa.ip()))
                {
                    node_public_ips.insert((n.tenant_id, n.machine_id), ip);
                }
            }
        }
    }

    let items = row
        .items
        .into_iter()
        .map(|a| {
            let live_ip = fleet.and_then(|f| f.rc_hub.agent_live_public_ip(a.id));
            let resolved_ip = live_ip
                .or_else(|| {
                    a.public_ip
                        .as_deref()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .and_then(canonical_public_ip)
                })
                .or_else(|| {
                    a.machine_id
                        .as_ref()
                        .and_then(|m| node_public_ips.get(&(a.tenant_id, m.clone())).copied())
                });
            let loc = resolved_ip
                .map(|ip| core.geoip.lookup_location(ip))
                .unwrap_or_default();
            // Authoritative zone country uses the exact policy resolver
            // (`live_ip` -> `persisted_public_ip` -> `static_endpoints`),
            // independent of fallback display GeoIP.
            let zone_cc = fleet.and_then(|f| {
                meshharbor_mod_fleet::socket::effective_country_from_sources(
                    f,
                    Some(a.id),
                    a.public_ip.as_deref(),
                    &a.peer_relay_policy.static_endpoints,
                )
            });
            let display_cc = loc
                .country_code
                .clone()
                .or_else(|| zone_cc.clone())
                .or(a.country_code);
            let geo_level = loc.effective_geo_level(display_cc.as_deref());
            let zones = tenant_zones
                .get(&a.tenant_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let (effective_zone_id, effective_zone_name) =
                match resolve_device_zone(zones, a.pinned_zone_id.as_deref(), zone_cc.as_deref()) {
                    DeviceZoneResolution::Resolved(z) => (Some(z.id.clone()), Some(z.name.clone())),
                    _ => (None, None),
                };
            DeviceRow {
                id: a.id.to_hex(),
                name: a
                    .display_name
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| a.name.clone()),
                machine_name: a.name,
                os: a.os,
                status: a.status,
                tenant_id: a.tenant_id.to_hex(),
                public_ip: resolved_ip.map(|ip| ip.to_string()),
                country_code: display_cc,
                country: loc.country,
                region: loc.region,
                city: loc.city,
                lat: loc.lat,
                lon: loc.lon,
                accuracy_radius_km: loc.accuracy_radius_km,
                geo_level,
                pinned_zone_id: a.pinned_zone_id.filter(|s| !s.trim().is_empty()),
                effective_zone_id,
                effective_zone_name,
            }
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
