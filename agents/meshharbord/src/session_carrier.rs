// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P9c — the carrier a remote-control session rides, recorded once
//! the session reaches Active (spec §3f).
//!
//! **Record, never decide.** Nothing here chooses a path: the nominated ICE
//! pair is read as webrtc-rs reports it, and — when that pair rides the
//! overlay — the overlay runtime's own carrier for the peer behind the
//! remote address is read from LocalAPI, exactly the lookup the adaptive
//! bitrate probe already makes ([`crate::peer`]'s constrained-transport
//! detection). The recorded value travels as an additive field on
//! `rc:session.stats` and lands beside `remote_sessions.stats`.
//!
//! The rule ([`carrier_of`]) is pure and tested for every overlay relay
//! kind. The cases, in the order they are checked:
//!
//! | The nominated pair | Recorded |
//! |---|---|
//! | the remote address is an overlay address and the overlay carries that peer **direct** | `overlay_direct` |
//! | … and the overlay carries it through a **TURN** allocation | `overlay_turn` |
//! | … through **DERP** | `derp` |
//! | … through an FR-19 **org relay** | `org_relay` |
//! | … and the overlay says something else — tunnel, blocked, offline, a relay kind this build does not know, the peer unknown, LocalAPI not answering | `unknown` — **never direct**: `Carrier::is_direct()` reads any new tier as direct, which is the trap this table exists to avoid |
//! | a `relay` candidate at a loopback or overlay address — the device's own fast TURN (`rc_local_turn`), not the far coturn | `turn_local` |
//! | a `relay` candidate anywhere else — coturn | `turn` |
//! | host · srflx · prflx on both sides | `direct` |
//! | a candidate type webrtc-rs could not name | `unknown` |
//!
//! ⚠️ Read **after a short settle**, not at the instant of `Connected`:
//! Chrome nominates a relay pair first and renominates to the host pair a
//! second or two later once the mDNS-resolved candidate succeeds, so the
//! very first pair would record `turn` for sessions that spend their life
//! direct. The pair is read once more [`SETTLE`] after the first nomination,
//! and that is what is recorded — once per session; a later path change is
//! not recorded (the bitrate clamp follows it live, this does not).
//!
//! The spellings are a wire and storage vocabulary: the server stores what
//! it is sent, the growth freeze groups by it. Never rename one.

use std::time::Duration;

use tracing::{debug, info};
use webrtc::peer_connection::RTCPeerConnection;

/// How long to wait for the first nomination after `Connected` (ICE has
/// usually nominated by then; the DC pumps wait the same 3 s).
pub const NOMINATION_WAIT: Duration = Duration::from_secs(3);
/// The settle before the recorded read (Chrome's relay→direct renomination
/// lands inside this).
pub const SETTLE: Duration = Duration::from_secs(2);
/// The LocalAPI budget for the overlay lookup — the same the bitrate probe
/// affords it.
pub const LOCALAPI_BUDGET: Duration = Duration::from_millis(400);

/// What a session rides. The wire spelling is [`SessionCarrier::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionCarrier {
    /// host · srflx · prflx, not over the overlay.
    Direct,
    /// A coturn allocation.
    Turn,
    /// The device's own TURN on a loopback or overlay address
    /// (`rc_local_turn`): a path on this host, not the far coturn.
    TurnLocal,
    /// The pair rides the overlay, whose carrier for the peer is direct UDP.
    OverlayDirect,
    /// The pair rides the overlay, carried through a coturn allocation.
    OverlayTurn,
    /// The pair rides the overlay, carried through the DERP floor.
    Derp,
    /// The pair rides the overlay, carried through an FR-19 org relay.
    OrgRelay,
    /// The agent could not say — never read as any of the above.
    Unknown,
}

impl SessionCarrier {
    /// Every value, for a test that must cover each.
    pub const ALL: [SessionCarrier; 8] = [
        SessionCarrier::Direct,
        SessionCarrier::Turn,
        SessionCarrier::TurnLocal,
        SessionCarrier::OverlayDirect,
        SessionCarrier::OverlayTurn,
        SessionCarrier::Derp,
        SessionCarrier::OrgRelay,
        SessionCarrier::Unknown,
    ];

    /// The wire and storage spelling. ⚠️ A compatibility surface: renaming
    /// one does not fail anywhere, it makes every session on that carrier
    /// read as a new, unexplained kind.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionCarrier::Direct => "direct",
            SessionCarrier::Turn => "turn",
            SessionCarrier::TurnLocal => "turn_local",
            SessionCarrier::OverlayDirect => "overlay_direct",
            SessionCarrier::OverlayTurn => "overlay_turn",
            SessionCarrier::Derp => "derp",
            SessionCarrier::OrgRelay => "org_relay",
            SessionCarrier::Unknown => "unknown",
        }
    }
}

/// An ICE candidate's type, as the rule reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Host,
    Srflx,
    Prflx,
    Relay,
    /// webrtc-rs's `Unspecified`: a type it could not name.
    Unspecified,
}

impl From<webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType> for CandidateKind {
    fn from(t: webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType) -> Self {
        use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType as T;
        match t {
            T::Host => CandidateKind::Host,
            T::Srflx => CandidateKind::Srflx,
            T::Prflx => CandidateKind::Prflx,
            T::Relay => CandidateKind::Relay,
            T::Unspecified => CandidateKind::Unspecified,
        }
    }
}

/// The nominated pair, the four facts the rule reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairView {
    pub local_kind: CandidateKind,
    pub remote_kind: CandidateKind,
    pub local_addr: String,
    pub remote_addr: String,
}

/// What the overlay runtime says about the peer behind an overlay address
/// (LocalAPI `peers` → `connection` and `relay_kind`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayPath {
    Direct,
    /// Relayed; the kind as the daemon labels it (`turn` · `derp` · `org`),
    /// or none from a daemon older than the field.
    Relay(Option<String>),
    /// `tunnel` · `blocked` · `offline`: not a carrier for pixels.
    Other(String),
}

/// The rule. `overlay` is what the overlay said about the remote address,
/// `None` when nothing could be learned (the peer unknown, LocalAPI not
/// answering, the daemon not running); it is consulted only for an overlay
/// remote and must never turn into `direct` by default.
pub fn carrier_of(pair: &PairView, overlay: Option<&OverlayPath>) -> SessionCarrier {
    if crate::peer::addr_is_overlay_range(&pair.remote_addr) {
        return match overlay {
            Some(OverlayPath::Direct) => SessionCarrier::OverlayDirect,
            Some(OverlayPath::Relay(kind)) => match kind.as_deref() {
                Some("turn") => SessionCarrier::OverlayTurn,
                Some("derp") => SessionCarrier::Derp,
                Some("org") => SessionCarrier::OrgRelay,
                _ => SessionCarrier::Unknown,
            },
            Some(OverlayPath::Other(_)) | None => SessionCarrier::Unknown,
        };
    }
    for (kind, addr) in [
        (pair.local_kind, pair.local_addr.as_str()),
        (pair.remote_kind, pair.remote_addr.as_str()),
    ] {
        if kind == CandidateKind::Relay {
            return if crate::encode::relay_addr_is_fast_local(addr) {
                SessionCarrier::TurnLocal
            } else {
                SessionCarrier::Turn
            };
        }
    }
    if pair.local_kind == CandidateKind::Unspecified
        || pair.remote_kind == CandidateKind::Unspecified
    {
        return SessionCarrier::Unknown;
    }
    SessionCarrier::Direct
}

/// The nominated pair, polled every 100 ms for up to `wait`.
async fn nominated_pair(pc: &RTCPeerConnection, wait: Duration) -> Option<PairView> {
    let sctp = pc.sctp();
    let dtls = sctp.transport();
    let ice = dtls.ice_transport();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Some(pair) = ice.get_selected_candidate_pair().await {
            let (local, remote) = (pair.local(), pair.remote());
            return Some(PairView {
                local_kind: local.typ.into(),
                remote_kind: remote.typ.into(),
                local_addr: local.address.clone(),
                remote_addr: remote.address.clone(),
            });
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// What the overlay says about `remote_addr`'s peer, within
/// [`LOCALAPI_BUDGET`]; `None` when nothing could be learned.
async fn overlay_path(remote_addr: &str) -> Option<OverlayPath> {
    use tunnel_core::localapi::ConnectionType;
    let query = async {
        let mut client = tunnel_core::localapi::connect().await.ok()?;
        let peers = client.peers().await.ok()?;
        peers.into_iter().find(|p| {
            p.overlay_ip.as_deref() == Some(remote_addr)
                || p.overlay_ip6.as_deref() == Some(remote_addr)
        })
    };
    let peer = tokio::time::timeout(LOCALAPI_BUDGET, query).await.ok()??;
    Some(match peer.connection {
        ConnectionType::Direct => OverlayPath::Direct,
        ConnectionType::Relay => OverlayPath::Relay(peer.relay_kind.clone()),
        other => OverlayPath::Other(format!("{other:?}").to_lowercase()),
    })
}

/// Observe the carrier of a session that just reached `Connected`: wait for
/// the nomination, settle, read the pair once more, ask the overlay when the
/// remote is one of its addresses, and record what the rule says. Logged at
/// `info` with the pair, so a field read can check the recorded value
/// against the addresses.
pub async fn observe(pc: &RTCPeerConnection, session_id: bson::oid::ObjectId) -> SessionCarrier {
    let Some(first) = nominated_pair(pc, NOMINATION_WAIT).await else {
        debug!(%session_id, "session carrier: no nominated pair within the wait — unknown");
        return SessionCarrier::Unknown;
    };
    tokio::time::sleep(SETTLE).await;
    let pair = nominated_pair(pc, Duration::from_millis(500))
        .await
        .unwrap_or(first);
    let overlay = if crate::peer::addr_is_overlay_range(&pair.remote_addr) {
        overlay_path(&pair.remote_addr).await
    } else {
        None
    };
    let carrier = carrier_of(&pair, overlay.as_ref());
    info!(
        %session_id,
        carrier = carrier.as_str(),
        local_typ = ?pair.local_kind,
        local_addr = %pair.local_addr,
        remote_typ = ?pair.remote_kind,
        remote_addr = %pair.remote_addr,
        overlay = ?overlay,
        "session carrier recorded (FR-102 P9c)"
    );
    carrier
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(
        local: CandidateKind,
        local_addr: &str,
        remote: CandidateKind,
        remote_addr: &str,
    ) -> PairView {
        PairView {
            local_kind: local,
            remote_kind: remote,
            local_addr: local_addr.into(),
            remote_addr: remote_addr.into(),
        }
    }

    /// The spellings are a compatibility surface: locked, one per value,
    /// all distinct.
    #[test]
    fn the_spellings_are_locked_and_distinct() {
        let spellings: Vec<&str> = SessionCarrier::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            spellings,
            [
                "direct",
                "turn",
                "turn_local",
                "overlay_direct",
                "overlay_turn",
                "derp",
                "org_relay",
                "unknown"
            ]
        );
        let distinct: std::collections::HashSet<&str> = spellings.iter().copied().collect();
        assert_eq!(distinct.len(), SessionCarrier::ALL.len());
    }

    /// Every overlay relay kind FR-19's `RelayKind` can name, plus direct,
    /// plus what must never read as direct.
    #[test]
    fn an_overlay_remote_records_the_overlays_own_carrier_and_never_guesses_direct() {
        let p = pair(
            CandidateKind::Host,
            "100.64.0.9",
            CandidateKind::Host,
            "100.64.0.7",
        );
        assert_eq!(
            carrier_of(&p, Some(&OverlayPath::Direct)),
            SessionCarrier::OverlayDirect
        );
        assert_eq!(
            carrier_of(&p, Some(&OverlayPath::Relay(Some("turn".into())))),
            SessionCarrier::OverlayTurn
        );
        assert_eq!(
            carrier_of(&p, Some(&OverlayPath::Relay(Some("derp".into())))),
            SessionCarrier::Derp
        );
        assert_eq!(
            carrier_of(&p, Some(&OverlayPath::Relay(Some("org".into())))),
            SessionCarrier::OrgRelay
        );
        // A relay kind this build does not know, a daemon older than the
        // field, a peer the overlay says is not carried, and nothing learned:
        // each is unknown — the `is_direct()` trap, closed.
        for not_direct in [
            Some(OverlayPath::Relay(Some("quantum".into()))),
            Some(OverlayPath::Relay(None)),
            Some(OverlayPath::Other("tunnel".into())),
            Some(OverlayPath::Other("blocked".into())),
            Some(OverlayPath::Other("offline".into())),
            None,
        ] {
            assert_eq!(
                carrier_of(&p, not_direct.as_ref()),
                SessionCarrier::Unknown,
                "{not_direct:?}"
            );
        }
        // The overlay answer is consulted ONLY for an overlay remote: a
        // public remote with a stray overlay answer is read from the pair.
        let public = pair(
            CandidateKind::Host,
            "100.64.0.9",
            CandidateKind::Srflx,
            "203.0.113.5",
        );
        assert_eq!(
            carrier_of(&public, Some(&OverlayPath::Relay(Some("derp".into())))),
            SessionCarrier::Direct
        );
        // The IPv6 overlay prefix is an overlay remote too.
        let v6 = pair(
            CandidateKind::Host,
            "fd72:6f6f:6d6c::6440:9",
            CandidateKind::Host,
            "fd72:6f6f:6d6c::6440:7",
        );
        assert_eq!(
            carrier_of(&v6, Some(&OverlayPath::Relay(Some("org".into())))),
            SessionCarrier::OrgRelay
        );
    }

    /// A coturn relay on either side is `turn`; the device's own TURN on a
    /// loopback or overlay address is `turn_local`; the plain kinds are
    /// `direct`; a type webrtc-rs could not name is `unknown`.
    #[test]
    fn relay_candidates_and_plain_pairs_read_from_the_pair_itself() {
        assert_eq!(
            carrier_of(
                &pair(
                    CandidateKind::Relay,
                    "5.9.157.221:49152",
                    CandidateKind::Srflx,
                    "203.0.113.5"
                ),
                None
            ),
            SessionCarrier::Turn
        );
        assert_eq!(
            carrier_of(
                &pair(
                    CandidateKind::Host,
                    "192.168.1.9",
                    CandidateKind::Relay,
                    "5.9.157.221"
                ),
                None
            ),
            SessionCarrier::Turn
        );
        assert_eq!(
            carrier_of(
                &pair(
                    CandidateKind::Relay,
                    "127.0.0.1",
                    CandidateKind::Host,
                    "127.0.0.1"
                ),
                None
            ),
            SessionCarrier::TurnLocal
        );
        assert_eq!(
            carrier_of(
                &pair(
                    CandidateKind::Host,
                    "192.168.1.9",
                    CandidateKind::Relay,
                    "::1"
                ),
                None
            ),
            SessionCarrier::TurnLocal
        );
        for (l, r) in [
            (CandidateKind::Host, CandidateKind::Host),
            (CandidateKind::Srflx, CandidateKind::Prflx),
            (CandidateKind::Prflx, CandidateKind::Srflx),
            (CandidateKind::Host, CandidateKind::Srflx),
        ] {
            assert_eq!(
                carrier_of(&pair(l, "192.168.1.9", r, "203.0.113.5"), None),
                SessionCarrier::Direct,
                "{l:?}/{r:?}"
            );
        }
        assert_eq!(
            carrier_of(
                &pair(
                    CandidateKind::Unspecified,
                    "192.168.1.9",
                    CandidateKind::Host,
                    "203.0.113.5"
                ),
                None
            ),
            SessionCarrier::Unknown
        );
        assert_eq!(
            carrier_of(
                &pair(
                    CandidateKind::Host,
                    "192.168.1.9",
                    CandidateKind::Unspecified,
                    "203.0.113.5"
                ),
                None
            ),
            SessionCarrier::Unknown
        );
    }

    #[test]
    fn candidate_kinds_map_one_to_one_from_webrtc() {
        use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType as T;
        assert_eq!(CandidateKind::from(T::Host), CandidateKind::Host);
        assert_eq!(CandidateKind::from(T::Srflx), CandidateKind::Srflx);
        assert_eq!(CandidateKind::from(T::Prflx), CandidateKind::Prflx);
        assert_eq!(CandidateKind::from(T::Relay), CandidateKind::Relay);
        assert_eq!(
            CandidateKind::from(T::Unspecified),
            CandidateKind::Unspecified
        );
    }
}
