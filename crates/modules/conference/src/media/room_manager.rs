// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::oid::ObjectId;
use dashmap::DashMap;
use mediasoup::prelude::*;
use mediasoup::types::data_structures::DtlsState;
use mediasoup::webrtc_transport::{
    WebRtcTransportListenInfos, WebRtcTransportOptions, WebRtcTransportRemoteParameters,
};
use meshharbor_config::MediasoupSettings;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::num::NonZero;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::worker_pool::WorkerPool;

/// Holds the DirectTransport + Consumer for an RTP tap (transcription).
struct RtpTap {
    _direct_transport: DirectTransport,
    _consumer: Consumer,
}

/// A media room backed by a mediasoup Router.
pub struct MediaRoom {
    pub router: Router,
    /// Keyed by connection_id (UUID per WebSocket connection) so the same user
    /// can join from multiple tabs/devices without overwriting state.
    pub participants: DashMap<String, ParticipantMedia>,
    /// RTP taps for transcription, keyed by producer_id string.
    rtp_taps: DashMap<String, RtpTap>,
}

/// A producer with its source label (e.g. "camera", "screen", "audio").
pub struct ProducerEntry {
    pub producer: Producer,
    pub source: String,
}

/// Media state for a single participant (one WebSocket connection).
pub struct ParticipantMedia {
    pub user_id: ObjectId,
    pub send_transport: WebRtcTransport,
    pub recv_transport: WebRtcTransport,
    pub producers: Vec<ProducerEntry>,
    pub consumers: Vec<Consumer>,
}

/// Transport connection details sent to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportOptions {
    pub id: String,
    pub ice_parameters: serde_json::Value,
    pub ice_candidates: serde_json::Value,
    pub dtls_parameters: serde_json::Value,
}

/// Pair of transport options (send + recv).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPair {
    pub send_transport: TransportOptions,
    pub recv_transport: TransportOptions,
}

/// Consumer details sent to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerInfo {
    pub id: String,
    pub producer_id: String,
    pub kind: String,
    pub rtp_parameters: serde_json::Value,
    /// FR-30 P4 — is the SOURCE producer paused right now?
    ///
    /// The pause EVENT only reaches whoever was in the room when it happened.
    /// Without this, someone who joins a call after you muted sees no badge
    /// until your next toggle — measured in the field 2026-08-29. The state
    /// has to travel with the subscription, not only as a transition.
    #[serde(default)]
    pub producer_paused: bool,
}

/// Manages mediasoup rooms and their media state.
pub struct RoomManager {
    rooms: DashMap<ObjectId, MediaRoom>,
    /// Tracks which room each connection is in (connection_id -> room_id).
    connection_rooms: DashMap<String, ObjectId>,
    worker_pool: Arc<WorkerPool>,
    listen_ip: IpAddr,
    announced_ip: Option<String>,
}

/// Stats PR-2 — one participant's cloned transport handles:
/// `(user_id, send_transport, recv_transport)`.
pub type ParticipantTransports = (ObjectId, WebRtcTransport, WebRtcTransport);
/// One room's sampled topology: `(room_id, participants)`.
pub type RoomTransportSnapshot = (ObjectId, Vec<ParticipantTransports>);

impl RoomManager {
    /// Stats PR-2 — snapshot the live conference topology for the media
    /// sampler: per room, per participant, CLONED transport handles
    /// (cheap `Arc` clones). The clones are taken under the DashMap shard
    /// guards and the guards are dropped before the caller awaits
    /// `get_stats()` — holding a guard across an await can deadlock
    /// against join/leave writers on the same shard.
    pub fn sample_transports(&self) -> Vec<RoomTransportSnapshot> {
        self.rooms
            .iter()
            .map(|room| {
                let parts = room
                    .participants
                    .iter()
                    .map(|p| {
                        (
                            p.user_id,
                            p.send_transport.clone(),
                            p.recv_transport.clone(),
                        )
                    })
                    .collect();
                (*room.key(), parts)
            })
            .collect()
    }

    pub fn new(worker_pool: Arc<WorkerPool>, settings: &MediasoupSettings) -> Self {
        let listen_ip: IpAddr = settings
            .listen_ip
            .parse()
            .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

        // S6 — multi-pod: each pod may need a different public announced
        // IP (it rides its node's DNAT). `MESHHARBOR__POD_HOST_IP` is
        // injected via the Downward API (status.hostIP); single-pod
        // deployments without the map behave exactly as before.
        let pod_host_ip = std::env::var("MESHHARBOR__POD_HOST_IP").ok();
        let announced_ip = settings.resolve_announced_ip(pod_host_ip.as_deref());
        if let Some(ip) = &announced_ip {
            tracing::info!(announced_ip = %ip, pod_host_ip = ?pod_host_ip, "mediasoup announced IP resolved");
        }

        Self {
            rooms: DashMap::new(),
            connection_rooms: DashMap::new(),
            worker_pool,
            listen_ip,
            announced_ip,
        }
    }

    /// Creates a mediasoup Router for a room and stores it.
    /// Returns the router's RTP capabilities (serialized).
    pub async fn create_room(&self, room_id: ObjectId) -> anyhow::Result<serde_json::Value> {
        if self.rooms.contains_key(&room_id) {
            let room = self.rooms.get(&room_id).unwrap();
            let caps = room.router.rtp_capabilities().clone();
            return Ok(serde_json::to_value(caps)?);
        }

        let worker = self.worker_pool.get_worker();

        let media_codecs = media_codecs();
        let router_options = RouterOptions::new(media_codecs);
        let router = worker
            .create_router(router_options)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create router: {}", e))?;

        let caps = router.rtp_capabilities().clone();
        info!(?room_id, "mediasoup room created");

        self.rooms.insert(
            room_id,
            MediaRoom {
                router,
                participants: DashMap::new(),
                rtp_taps: DashMap::new(),
            },
        );

        Ok(serde_json::to_value(caps)?)
    }

    /// Removes a room and all its media state.
    pub fn remove_room(&self, room_id: &ObjectId) -> bool {
        if let Some((_, room)) = self.rooms.remove(room_id) {
            // Clean up connection_rooms mappings
            let conn_ids: Vec<String> = room
                .participants
                .iter()
                .map(|entry| entry.key().clone())
                .collect();
            for cid in conn_ids {
                self.connection_rooms.remove(&cid);
            }
            // Dropping the room closes the router and all transports/producers/consumers
            info!(?room_id, "mediasoup room removed");
            true
        } else {
            false
        }
    }

    pub fn has_room(&self, room_id: &ObjectId) -> bool {
        self.rooms.contains_key(room_id)
    }

    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Returns a reference to the rooms DashMap (for WS handler to read router capabilities).
    pub fn rooms_ref(&self) -> &DashMap<ObjectId, MediaRoom> {
        &self.rooms
    }

    /// Creates send + recv WebRtcTransport pair for a participant.
    pub async fn create_transports(
        &self,
        room_id: ObjectId,
        user_id: ObjectId,
        connection_id: String,
    ) -> anyhow::Result<TransportPair> {
        let room = self
            .rooms
            .get(&room_id)
            .ok_or_else(|| anyhow::anyhow!("Room not found"))?;

        let send_transport = self.create_webrtc_transport(&room.router).await?;
        let recv_transport = self.create_webrtc_transport(&room.router).await?;

        let send_opts = transport_to_options(&send_transport);
        let recv_opts = transport_to_options(&recv_transport);

        room.participants.insert(
            connection_id.clone(),
            ParticipantMedia {
                user_id,
                send_transport,
                recv_transport,
                producers: Vec::new(),
                consumers: Vec::new(),
            },
        );

        self.connection_rooms.insert(connection_id.clone(), room_id);

        debug!(?room_id, ?user_id, %connection_id, "transports created");

        Ok(TransportPair {
            send_transport: send_opts,
            recv_transport: recv_opts,
        })
    }

    /// Connects a transport with remote DTLS parameters.
    pub async fn connect_transport(
        &self,
        room_id: &ObjectId,
        connection_id: &str,
        transport_id: &str,
        dtls_parameters: DtlsParameters,
    ) -> anyhow::Result<()> {
        let room = self
            .rooms
            .get(room_id)
            .ok_or_else(|| anyhow::anyhow!("Room not found"))?;

        let participant = room
            .participants
            .get(connection_id)
            .ok_or_else(|| anyhow::anyhow!("Participant not found"))?;

        let tid = TransportId::from_str(transport_id)
            .map_err(|e| anyhow::anyhow!("Invalid transport_id: {}", e))?;

        let remote_params = WebRtcTransportRemoteParameters { dtls_parameters };

        let transport = if participant.send_transport.id() == tid {
            participant.send_transport.clone()
        } else if participant.recv_transport.id() == tid {
            participant.recv_transport.clone()
        } else {
            return Err(anyhow::anyhow!("Transport not found for this participant"));
        };
        // Connect on a cloned handle with the shard guards released — holding
        // a DashMap guard across an await can deadlock against join/leave
        // writers on the same shard (see sample_transports).
        drop(participant);
        drop(room);

        transport
            .connect(remote_params)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect transport: {}", e))?;

        debug!(?room_id, %connection_id, transport_id, "transport connected");
        self.spawn_media_path_watchdog(*room_id, connection_id.to_string(), &transport);
        Ok(())
    }

    /// `connect_transport` only records the client's DTLS parameters — it says
    /// nothing about packets. When the announced-IP path is dead (host DNAT /
    /// firewall / RTC port range), every signalling step still succeeds and the
    /// only symptom is black video, which is exactly how the missing RTC-range
    /// DNAT on one node shipped broken and stayed invisible for weeks. This
    /// watchdog turns that state into an operator-actionable log line: if DTLS
    /// still hasn't established shortly after the client said it was dialing,
    /// the media path — not the client — is the suspect.
    fn spawn_media_path_watchdog(
        &self,
        room_id: ObjectId,
        connection_id: String,
        transport: &WebRtcTransport,
    ) {
        const DTLS_ESTABLISH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
        // Weak handle: the watchdog must not extend the transport's lifetime
        // past the participant's leave.
        let weak = transport.downgrade();
        let announced_ip = self.announced_ip.clone();
        tokio::spawn(async move {
            tokio::time::sleep(DTLS_ESTABLISH_DEADLINE).await;
            let Some(transport) = weak.upgrade() else {
                return; // participant already left — nothing to report
            };
            let dtls = transport.dtls_state();
            if matches!(dtls, DtlsState::Connected | DtlsState::Closed) {
                return;
            }
            tracing::warn!(
                ?room_id,
                %connection_id,
                transport_id = %transport.id(),
                ?dtls,
                ice = ?transport.ice_state(),
                announced_ip = ?announced_ip,
                "media transport has no DTLS {}s after connect_transport — signalling is healthy but RTP cannot flow; check the announced-IP path (host DNAT / firewall / RTC port range) toward this pod",
                DTLS_ESTABLISH_DEADLINE.as_secs()
            );
        });
    }

    /// The announced IP this pod resolved for its ICE candidates (S6 per-node
    /// map), which is what clients actually dial — the static settings value
    /// can differ on a multi-pod deployment.
    pub fn announced_ip(&self) -> Option<&str> {
        self.announced_ip.as_deref()
    }

    /// Creates a Producer on the participant's send transport.
    pub async fn produce(
        &self,
        room_id: &ObjectId,
        connection_id: &str,
        kind: MediaKind,
        rtp_parameters: RtpParameters,
        source: String,
    ) -> anyhow::Result<ProducerId> {
        let room = self
            .rooms
            .get(room_id)
            .ok_or_else(|| anyhow::anyhow!("Room not found"))?;

        let mut participant = room
            .participants
            .get_mut(connection_id)
            .ok_or_else(|| anyhow::anyhow!("Participant not found"))?;

        let producer_options = ProducerOptions::new(kind, rtp_parameters);
        let producer = participant
            .send_transport
            .produce(producer_options)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to produce: {}", e))?;

        let producer_id = producer.id();
        participant.producers.push(ProducerEntry {
            producer,
            source: source.clone(),
        });

        debug!(?room_id, %connection_id, %producer_id, ?kind, %source, "producer created");
        Ok(producer_id)
    }

    /// Creates a Consumer on the participant's recv transport for a given producer.
    pub async fn consume(
        &self,
        room_id: &ObjectId,
        connection_id: &str,
        producer_id: ProducerId,
        rtp_capabilities: &RtpCapabilities,
    ) -> anyhow::Result<ConsumerInfo> {
        let room = self
            .rooms
            .get(room_id)
            .ok_or_else(|| anyhow::anyhow!("Room not found"))?;

        // Check if the router can consume this producer
        if !room.router.can_consume(&producer_id, rtp_capabilities) {
            return Err(anyhow::anyhow!("Cannot consume: incompatible capabilities"));
        }

        // FR-30 P4 — read the source producer's pause state HERE, while only
        // `room` is held. ⚠️ Not below: `participants.get_mut()` is taken a few
        // lines down, and iterating the same DashMap while holding a mutable
        // entry deadlocks it.
        let producer_paused = room
            .participants
            .iter()
            .flat_map(|entry| {
                entry
                    .value()
                    .producers
                    .iter()
                    .find(|pe| pe.producer.id() == producer_id)
                    .map(|pe| pe.producer.paused())
            })
            .next()
            .unwrap_or(false);

        let mut participant = room
            .participants
            .get_mut(connection_id)
            .ok_or_else(|| anyhow::anyhow!("Participant not found"))?;

        let consumer_options = ConsumerOptions::new(producer_id, rtp_capabilities.clone());
        let consumer = participant
            .recv_transport
            .consume(consumer_options)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to consume: {}", e))?;

        // mediasoup consumers are created paused — must resume to deliver RTP
        consumer
            .resume()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to resume consumer: {}", e))?;

        let info = ConsumerInfo {
            id: consumer.id().to_string(),
            producer_id: consumer.producer_id().to_string(),
            kind: match consumer.kind() {
                MediaKind::Audio => "audio".to_string(),
                MediaKind::Video => "video".to_string(),
            },
            rtp_parameters: serde_json::to_value(consumer.rtp_parameters())?,
            producer_paused,
        };

        participant.consumers.push(consumer);

        debug!(
            ?room_id,
            %connection_id,
            consumer_id = %info.id,
            %producer_id,
            "consumer created"
        );
        Ok(info)
    }

    /// Closes a specific producer by ID.
    /// FR-30 — pause or resume ONE of a participant's producers.
    ///
    /// ⚠️ Deliberately NOT a sibling of `close_producer` below, which is sync.
    /// `Producer::pause()` is async, and holding a DashMap guard across an
    /// await is how you deadlock the whole room registry — so the handle is
    /// CLONED out first and every guard dropped before we await. A mediasoup
    /// `Producer` is a cheap cloneable handle, so this costs nothing.
    ///
    /// Pausing server-side is half the point on its own: it stops forwarding
    /// to every consumer, so a participant with their camera off stops
    /// shipping black frames to everyone in the room.
    pub async fn set_producer_paused(
        &self,
        room_id: &ObjectId,
        connection_id: &str,
        producer_id: &ProducerId,
        paused: bool,
    ) -> bool {
        let producer = {
            let Some(room) = self.rooms.get(room_id) else {
                return false;
            };
            let Some(participant) = room.participants.get(connection_id) else {
                return false;
            };
            participant
                .producers
                .iter()
                .find(|pe| &pe.producer.id() == producer_id)
                .map(|pe| pe.producer.clone())
        };

        let Some(producer) = producer else {
            return false;
        };

        let result = if paused {
            producer.pause().await
        } else {
            producer.resume().await
        };

        match result {
            Ok(()) => true,
            Err(e) => {
                warn!(?room_id, %connection_id, %paused, error = %e, "failed to set producer paused");
                false
            }
        }
    }

    pub fn close_producer(
        &self,
        room_id: &ObjectId,
        connection_id: &str,
        producer_id: &ProducerId,
    ) -> bool {
        if let Some(room) = self.rooms.get(room_id)
            && let Some(mut participant) = room.participants.get_mut(connection_id)
        {
            let before = participant.producers.len();
            participant
                .producers
                .retain(|pe| &pe.producer.id() != producer_id);
            return participant.producers.len() < before;
        }
        false
    }

    /// Removes a participant's media state from a room.
    pub fn close_participant(&self, room_id: &ObjectId, connection_id: &str) {
        if let Some(room) = self.rooms.get(room_id) {
            // Dropping the ParticipantMedia closes transports/producers/consumers
            room.participants.remove(connection_id);
        }
        self.connection_rooms.remove(connection_id);
        debug!(?room_id, %connection_id, "participant media closed");
    }

    /// Removes ONE connection's media state, but only when that connection
    /// belongs to `user_id`. The connection id may come from an HTTP body, so
    /// a room member must not be able to close another participant's media by
    /// guessing a UUID. Returns whether an entry was removed.
    pub fn close_participant_of_user(
        &self,
        room_id: &ObjectId,
        connection_id: &str,
        user_id: &ObjectId,
    ) -> bool {
        let mut removed = false;
        if let Some(room) = self.rooms.get(room_id) {
            let owned = room
                .participants
                .get(connection_id)
                .map(|p| &p.user_id == user_id)
                .unwrap_or(false);
            if owned {
                room.participants.remove(connection_id);
                removed = true;
            }
        }
        if removed {
            self.connection_rooms.remove(connection_id);
            debug!(?room_id, %connection_id, "participant media closed (ownership-checked)");
        }
        removed
    }

    /// Removes ALL participant entries for a given user_id from a room.
    /// Used by HTTP leave endpoint which doesn't have a connection_id.
    pub fn close_participant_by_user(&self, room_id: &ObjectId, user_id: &ObjectId) {
        if let Some(room) = self.rooms.get(room_id) {
            let conn_ids: Vec<String> = room
                .participants
                .iter()
                .filter(|e| &e.value().user_id == user_id)
                .map(|e| e.key().clone())
                .collect();
            for cid in conn_ids {
                room.participants.remove(&cid);
                self.connection_rooms.remove(&cid);
            }
        }
        debug!(?room_id, ?user_id, "participant media closed (by user_id)");
    }

    /// Returns all producer IDs in a room except those belonging to the given connection.
    pub fn get_producer_ids(
        &self,
        room_id: &ObjectId,
        exclude_connection_id: &str,
    ) -> Vec<(ObjectId, String, ProducerId, MediaKind, String)> {
        let mut result = Vec::new();
        if let Some(room) = self.rooms.get(room_id) {
            for entry in room.participants.iter() {
                if entry.key() != exclude_connection_id {
                    let uid = entry.value().user_id;
                    let conn_id = entry.key().clone();
                    for pe in &entry.value().producers {
                        result.push((
                            uid,
                            conn_id.clone(),
                            pe.producer.id(),
                            pe.producer.kind(),
                            pe.source.clone(),
                        ));
                    }
                }
            }
        }
        result
    }

    /// Returns unique participant user IDs in a room.
    pub fn get_participant_user_ids(&self, room_id: &ObjectId) -> Vec<ObjectId> {
        self.rooms
            .get(room_id)
            .map(|room| {
                let mut ids: Vec<ObjectId> = room
                    .participants
                    .iter()
                    .map(|e| e.value().user_id)
                    .collect();
                ids.sort();
                ids.dedup();
                ids
            })
            .unwrap_or_default()
    }

    /// Returns user IDs of all participants except those with the given connection_id.
    pub fn get_other_participant_user_ids(
        &self,
        room_id: &ObjectId,
        exclude_connection_id: &str,
    ) -> Vec<ObjectId> {
        self.rooms
            .get(room_id)
            .map(|room| {
                let mut ids: Vec<ObjectId> = room
                    .participants
                    .iter()
                    .filter(|e| e.key() != exclude_connection_id)
                    .map(|e| e.value().user_id)
                    .collect();
                ids.sort();
                ids.dedup();
                ids
            })
            .unwrap_or_default()
    }

    /// Returns connection IDs of all participants except the given connection_id.
    /// Unlike get_other_participant_user_ids, this returns connection-level granularity
    /// so broadcasts don't leak to same-user connections in the same room.
    pub fn get_other_connection_ids(
        &self,
        room_id: &ObjectId,
        exclude_connection_id: &str,
    ) -> Vec<String> {
        self.rooms
            .get(room_id)
            .map(|room| {
                room.participants
                    .iter()
                    .filter(|e| e.key() != exclude_connection_id)
                    .map(|e| e.key().clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the room ID that a connection is currently in, if any.
    pub fn get_connection_room(&self, connection_id: &str) -> Option<ObjectId> {
        self.connection_rooms.get(connection_id).map(|v| *v)
    }

    /// Creates a DirectTransport consumer that taps into a producer's RTP stream.
    ///
    /// Returns an mpsc receiver that yields raw RTP packets. The DirectTransport
    /// and Consumer are stored internally and cleaned up when the tap is removed.
    pub async fn create_rtp_tap(
        &self,
        room_id: &ObjectId,
        producer_id: ProducerId,
    ) -> anyhow::Result<mpsc::Receiver<Vec<u8>>> {
        let room = self
            .rooms
            .get(room_id)
            .ok_or_else(|| anyhow::anyhow!("Room not found"))?;

        let direct_transport = room
            .router
            .create_direct_transport(DirectTransportOptions::default())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create DirectTransport: {}", e))?;

        // Convert RtpCapabilitiesFinalized → RtpCapabilities via serde (same JSON schema)
        let caps_finalized = room.router.rtp_capabilities();
        let rtp_capabilities: RtpCapabilities = serde_json::from_value(
            serde_json::to_value(caps_finalized)
                .map_err(|e| anyhow::anyhow!("Failed to serialize capabilities: {}", e))?,
        )
        .map_err(|e| anyhow::anyhow!("Failed to deserialize capabilities: {}", e))?;

        let consumer_options = ConsumerOptions::new(producer_id, rtp_capabilities);
        let consumer = direct_transport
            .consume(consumer_options)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to consume on DirectTransport: {}", e))?;

        // mediasoup consumers are created paused — must resume to receive RTP
        consumer
            .resume()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to resume DirectTransport consumer: {}", e))?;

        let (tx, rx) = mpsc::channel(512);

        // Register RTP callback; detach so it lives as long as the Consumer
        consumer
            .on_rtp(move |data: &[u8]| {
                let _ = tx.try_send(data.to_vec());
            })
            .detach();

        // Store to keep alive
        room.rtp_taps.insert(
            producer_id.to_string(),
            RtpTap {
                _direct_transport: direct_transport,
                _consumer: consumer,
            },
        );

        debug!(?room_id, %producer_id, "RTP tap created and resumed");
        Ok(rx)
    }

    /// Removes an RTP tap for a producer (stops the DirectTransport consumer).
    pub fn remove_rtp_tap(&self, room_id: &ObjectId, producer_id: &str) {
        if let Some(room) = self.rooms.get(room_id)
            && room.rtp_taps.remove(producer_id).is_some()
        {
            debug!(?room_id, %producer_id, "RTP tap removed");
        }
    }

    /// Helper: creates a single WebRtcTransport on the given router.
    async fn create_webrtc_transport(&self, router: &Router) -> anyhow::Result<WebRtcTransport> {
        let udp_info = ListenInfo {
            protocol: Protocol::Udp,
            ip: self.listen_ip,
            announced_address: self.announced_ip.clone(),
            port: None,
            port_range: None,
            flags: None,
            send_buffer_size: None,
            recv_buffer_size: None,
            expose_internal_ip: false,
        };

        // TCP fallback — essential when wsl-vpnkit or similar networking
        // intercepts UDP but TCP localhost forwarding still works.
        let tcp_info = ListenInfo {
            protocol: Protocol::Tcp,
            ip: self.listen_ip,
            announced_address: self.announced_ip.clone(),
            port: None,
            port_range: None,
            flags: None,
            send_buffer_size: None,
            recv_buffer_size: None,
            expose_internal_ip: false,
        };

        let listen_infos = WebRtcTransportListenInfos::new(udp_info).insert(tcp_info);
        let mut transport_options = WebRtcTransportOptions::new(listen_infos);
        transport_options.enable_udp = true;
        transport_options.enable_tcp = true;
        transport_options.prefer_udp = true;

        let transport = router
            .create_webrtc_transport(transport_options)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create WebRtcTransport: {}", e))?;

        Ok(transport)
    }
}

/// Extracts transport connection details for the client.
fn transport_to_options(transport: &WebRtcTransport) -> TransportOptions {
    TransportOptions {
        id: transport.id().to_string(),
        ice_parameters: serde_json::to_value(transport.ice_parameters()).unwrap_or_default(),
        ice_candidates: serde_json::to_value(transport.ice_candidates()).unwrap_or_default(),
        dtls_parameters: serde_json::to_value(transport.dtls_parameters()).unwrap_or_default(),
    }
}

/// Standard SFU media codecs: opus audio + VP8/H264 video.
fn media_codecs() -> Vec<RtpCodecCapability> {
    vec![
        // Opus audio
        RtpCodecCapability::Audio {
            mime_type: MimeTypeAudio::Opus,
            preferred_payload_type: Some(111),
            clock_rate: NonZero::new(48000).unwrap(),
            channels: NonZero::new(2).unwrap(),
            parameters: RtpCodecParametersParameters::default(),
            rtcp_feedback: vec![RtcpFeedback::TransportCc],
        },
        // VP8 video
        RtpCodecCapability::Video {
            mime_type: MimeTypeVideo::Vp8,
            preferred_payload_type: Some(96),
            clock_rate: NonZero::new(90000).unwrap(),
            parameters: RtpCodecParametersParameters::default(),
            rtcp_feedback: vec![
                RtcpFeedback::Nack,
                RtcpFeedback::NackPli,
                RtcpFeedback::CcmFir,
                RtcpFeedback::GoogRemb,
                RtcpFeedback::TransportCc,
            ],
        },
        // H264 video
        RtpCodecCapability::Video {
            mime_type: MimeTypeVideo::H264,
            preferred_payload_type: Some(125),
            clock_rate: NonZero::new(90000).unwrap(),
            parameters: RtpCodecParametersParameters::from([
                ("level-asymmetry-allowed", 1_u32.into()),
                ("packetization-mode", 1_u32.into()),
                ("profile-level-id", "42e01f".into()),
            ]),
            rtcp_feedback: vec![
                RtcpFeedback::Nack,
                RtcpFeedback::NackPli,
                RtcpFeedback::CcmFir,
                RtcpFeedback::GoogRemb,
                RtcpFeedback::TransportCc,
            ],
        },
    ]
}
