#[cfg(test)]
mod association_test;

mod association_internal;
mod association_stats;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::SystemTime;

use association_internal::*;
use association_stats::*;
use bytes::{Bytes, BytesMut};
use portable_atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize};
use rand::random;
use tokio::sync::{broadcast, mpsc, Mutex};
use util::Conn;

use crate::chunk::chunk_abort::ChunkAbort;
use crate::chunk::chunk_cookie_ack::ChunkCookieAck;
use crate::chunk::chunk_cookie_echo::ChunkCookieEcho;
use crate::chunk::chunk_error::ChunkError;
use crate::chunk::chunk_forward_tsn::{ChunkForwardTsn, ChunkForwardTsnStream};
use crate::chunk::chunk_heartbeat::ChunkHeartbeat;
use crate::chunk::chunk_heartbeat_ack::ChunkHeartbeatAck;
use crate::chunk::chunk_init::ChunkInit;
use crate::chunk::chunk_payload_data::{ChunkPayloadData, PayloadProtocolIdentifier};
use crate::chunk::chunk_reconfig::ChunkReconfig;
use crate::chunk::chunk_selective_ack::ChunkSelectiveAck;
use crate::chunk::chunk_shutdown::ChunkShutdown;
use crate::chunk::chunk_shutdown_ack::ChunkShutdownAck;
use crate::chunk::chunk_shutdown_complete::ChunkShutdownComplete;
use crate::chunk::chunk_type::*;
use crate::chunk::Chunk;
use crate::error::{Error, Result};
use crate::error_cause::*;
use crate::packet::Packet;
use crate::param::param_heartbeat_info::ParamHeartbeatInfo;
use crate::param::param_outgoing_reset_request::ParamOutgoingResetRequest;
use crate::param::param_reconfig_response::{ParamReconfigResponse, ReconfigResult};
use crate::param::param_state_cookie::ParamStateCookie;
use crate::param::param_supported_extensions::ParamSupportedExtensions;
use crate::param::Param;
use crate::queue::control_queue::ControlQueue;
use crate::queue::payload_queue::PayloadQueue;
use crate::queue::pending_queue::PendingQueue;
use crate::stream::*;
use crate::timer::ack_timer::*;
use crate::timer::rtx_timer::*;
use crate::util::*;

pub(crate) const RECEIVE_MTU: usize = 8192;
/// MTU for inbound packet (from DTLS)
pub(crate) const INITIAL_MTU: u32 = 1228;
/// initial MTU for outgoing packets (to DTLS)
pub(crate) const INITIAL_RECV_BUF_SIZE: u32 = 1024 * 1024;
pub(crate) const COMMON_HEADER_SIZE: u32 = 12;
pub(crate) const DATA_CHUNK_HEADER_SIZE: u32 = 16;
pub(crate) const DEFAULT_MAX_MESSAGE_SIZE: u32 = 65536;

/// other constants
pub(crate) const ACCEPT_CH_SIZE: usize = 16;

/// meshharbor (#1856): while sends keep failing, log at most this often.
const SEND_FAILURE_LOG_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// meshharbor (#1856): a run of consecutive failed `net_conn` sends. The write
/// loop drops the packet and lets SCTP retransmit it; this only decides what
/// gets logged: the first failure of a run, then at most one line per
/// [`SEND_FAILURE_LOG_EVERY`], and one line when sends recover.
#[derive(Debug, Default)]
struct SendFailureRun {
    dropped: u64,
    since: Option<std::time::Instant>,
    last_log: Option<std::time::Instant>,
}

impl SendFailureRun {
    /// Count one failed send; `true` when this one should be logged.
    fn failed(&mut self, now: std::time::Instant) -> bool {
        self.dropped += 1;
        self.since.get_or_insert(now);
        let log = self
            .last_log
            .is_none_or(|t| now.duration_since(t) >= SEND_FAILURE_LOG_EVERY);
        if log {
            self.last_log = Some(now);
        }
        log
    }

    /// A send went out. `Some((dropped, how long))` when it ended a run.
    fn sent(&mut self, now: std::time::Instant) -> Option<(u64, std::time::Duration)> {
        let since = self.since.take()?;
        let dropped = std::mem::take(&mut self.dropped);
        self.last_log = None;
        Some((dropped, now.duration_since(since)))
    }
}

/// association state enums
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum AssociationState {
    Closed = 0,
    CookieWait = 1,
    CookieEchoed = 2,
    Established = 3,
    ShutdownAckSent = 4,
    ShutdownPending = 5,
    ShutdownReceived = 6,
    ShutdownSent = 7,
}

impl From<u8> for AssociationState {
    fn from(v: u8) -> AssociationState {
        match v {
            1 => AssociationState::CookieWait,
            2 => AssociationState::CookieEchoed,
            3 => AssociationState::Established,
            4 => AssociationState::ShutdownAckSent,
            5 => AssociationState::ShutdownPending,
            6 => AssociationState::ShutdownReceived,
            7 => AssociationState::ShutdownSent,
            _ => AssociationState::Closed,
        }
    }
}

impl fmt::Display for AssociationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            AssociationState::Closed => "Closed",
            AssociationState::CookieWait => "CookieWait",
            AssociationState::CookieEchoed => "CookieEchoed",
            AssociationState::Established => "Established",
            AssociationState::ShutdownPending => "ShutdownPending",
            AssociationState::ShutdownSent => "ShutdownSent",
            AssociationState::ShutdownReceived => "ShutdownReceived",
            AssociationState::ShutdownAckSent => "ShutdownAckSent",
        };
        write!(f, "{s}")
    }
}

/// retransmission timer IDs
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum RtxTimerId {
    #[default]
    T1Init,
    T1Cookie,
    T2Shutdown,
    T3RTX,
    Reconfig,
}

impl fmt::Display for RtxTimerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RtxTimerId::T1Init => "T1Init",
            RtxTimerId::T1Cookie => "T1Cookie",
            RtxTimerId::T2Shutdown => "T2Shutdown",
            RtxTimerId::T3RTX => "T3RTX",
            RtxTimerId::Reconfig => "Reconfig",
        };
        write!(f, "{s}")
    }
}

/// ack mode (for testing)
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum AckMode {
    #[default]
    Normal,
    NoDelay,
    AlwaysDelay,
}

impl fmt::Display for AckMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            AckMode::Normal => "Normal",
            AckMode::NoDelay => "NoDelay",
            AckMode::AlwaysDelay => "AlwaysDelay",
        };
        write!(f, "{s}")
    }
}

/// ack transmission state
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum AckState {
    #[default]
    Idle, // ack timer is off
    Immediate, // will send ack immediately
    Delay,     // ack timer is on (ack is being delayed)
}

impl fmt::Display for AckState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            AckState::Idle => "Idle",
            AckState::Immediate => "Immediate",
            AckState::Delay => "Delay",
        };
        write!(f, "{s}")
    }
}

/// Config collects the arguments to create_association construction into
/// a single structure
pub struct Config {
    pub net_conn: Arc<dyn Conn + Send + Sync>,
    pub max_receive_buffer_size: u32,
    pub max_message_size: u32,
    pub name: String,
}

/// Explicit per-association parameters for the file-only pacing experiment.
/// This is fixed-rate DATA pacing, independent of SCTP congestion control.
pub struct FilePacingConfig {
    /// Byte rate including SCTP packet headers.
    pub rate_bytes_per_second: u64,
    /// Wire-byte burst budget, including DATA padding.
    pub burst_bytes: usize,
}

///Association represents an SCTP association
///13.2.  Parameters Necessary per Association (i.e., the TCB)
///Peer : Tag value to be sent in every packet and is received
///Verification: in the INIT or INIT ACK chunk.
///Tag :
///
///My : Tag expected in every inbound packet and sent in the
///Verification: INIT or INIT ACK chunk.
///
///Tag :
///State : A state variable indicating what state the association
/// : is in, i.e., COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED,
/// : SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED,
/// : SHUTDOWN-ACK-SENT.
///
/// No Closed state is illustrated since if a
/// association is Closed its TCB SHOULD be removed.
pub struct Association {
    name: String,
    state: Arc<AtomicU8>,
    max_message_size: Arc<AtomicU32>,
    inflight_queue_length: Arc<AtomicUsize>,
    will_send_shutdown: Arc<AtomicBool>,
    awake_write_loop_ch: Arc<mpsc::Sender<()>>,
    close_loop_ch_rx: Mutex<broadcast::Receiver<()>>,
    accept_ch_rx: Mutex<mpsc::Receiver<Arc<Stream>>>,
    net_conn: Arc<dyn Conn + Send + Sync>,
    bytes_received: Arc<AtomicUsize>,
    bytes_sent: Arc<AtomicUsize>,

    pub(crate) association_internal: Arc<Mutex<AssociationInternal>>,
}

impl Association {
    /// Opt in this idle established association to a fixed DATA wire-byte rate.
    /// The burst must accommodate its current MTU. Control packets are exempt;
    /// retransmitted DATA consumes the same budget as new DATA. `None` restores
    /// the existing sender immediately, including when DATA is waiting for credit.
    /// Rejections leave the current configuration and queued data unchanged.
    pub async fn set_file_pacing(&self, config: Option<FilePacingConfig>) -> Result<()> {
        {
            let mut ai = self.association_internal.lock().await;
            ai.configure_file_pacing(config)?;
        }
        let _ = self.awake_write_loop_ch.try_send(());
        Ok(())
    }

    /// server accepts a SCTP stream over a conn
    pub async fn server(config: Config) -> Result<Self> {
        let (a, mut handshake_completed_ch_rx) = Association::new(config, false).await?;

        if let Some(err_opt) = handshake_completed_ch_rx.recv().await {
            if let Some(err) = err_opt {
                Err(err)
            } else {
                Ok(a)
            }
        } else {
            Err(Error::ErrAssociationHandshakeClosed)
        }
    }

    /// Client opens a SCTP stream over a conn
    pub async fn client(config: Config) -> Result<Self> {
        let (a, mut handshake_completed_ch_rx) = Association::new(config, true).await?;

        if let Some(err_opt) = handshake_completed_ch_rx.recv().await {
            if let Some(err) = err_opt {
                Err(err)
            } else {
                Ok(a)
            }
        } else {
            Err(Error::ErrAssociationHandshakeClosed)
        }
    }

    /// Shutdown initiates the shutdown sequence. The method blocks until the
    /// shutdown sequence is completed and the connection is closed, or until the
    /// passed context is done, in which case the context's error is returned.
    pub async fn shutdown(&self) -> Result<()> {
        log::debug!("[{}] closing association..", self.name);

        let state = self.get_state();
        if state != AssociationState::Established {
            return Err(Error::ErrShutdownNonEstablished);
        }

        // Attempt a graceful shutdown.
        self.set_state(AssociationState::ShutdownPending);

        if self.inflight_queue_length.load(Ordering::SeqCst) == 0 {
            // No more outstanding, send shutdown.
            self.will_send_shutdown.store(true, Ordering::SeqCst);
            let _ = self.awake_write_loop_ch.try_send(());
            self.set_state(AssociationState::ShutdownSent);
        }

        {
            let mut close_loop_ch_rx = self.close_loop_ch_rx.lock().await;
            let _ = close_loop_ch_rx.recv().await;
        }

        Ok(())
    }

    /// Close ends the SCTP Association and cleans up any state
    pub async fn close(&self) -> Result<()> {
        log::debug!("[{}] closing association..", self.name);

        let _ = self.net_conn.close().await;

        let mut ai = self.association_internal.lock().await;
        ai.close().await
    }

    async fn new(config: Config, is_client: bool) -> Result<(Self, mpsc::Receiver<Option<Error>>)> {
        let net_conn = Arc::clone(&config.net_conn);

        let (awake_write_loop_ch_tx, awake_write_loop_ch_rx) = mpsc::channel(1);
        let (accept_ch_tx, accept_ch_rx) = mpsc::channel(ACCEPT_CH_SIZE);
        let (handshake_completed_ch_tx, handshake_completed_ch_rx) = mpsc::channel(1);
        let (close_loop_ch_tx, close_loop_ch_rx) = broadcast::channel(1);
        let (close_loop_ch_rx1, close_loop_ch_rx2) =
            (close_loop_ch_tx.subscribe(), close_loop_ch_tx.subscribe());
        let awake_write_loop_ch = Arc::new(awake_write_loop_ch_tx);

        let ai = AssociationInternal::new(
            config,
            close_loop_ch_tx,
            accept_ch_tx,
            handshake_completed_ch_tx,
            Arc::clone(&awake_write_loop_ch),
        );

        let bytes_received = Arc::new(AtomicUsize::new(0));
        let bytes_sent = Arc::new(AtomicUsize::new(0));
        let name = ai.name.clone();
        let state = Arc::clone(&ai.state);
        let max_message_size = Arc::clone(&ai.max_message_size);
        let inflight_queue_length = Arc::clone(&ai.inflight_queue_length);
        let will_send_shutdown = Arc::clone(&ai.will_send_shutdown);

        let mut init = ChunkInit {
            initial_tsn: ai.my_next_tsn,
            num_outbound_streams: ai.my_max_num_outbound_streams,
            num_inbound_streams: ai.my_max_num_inbound_streams,
            initiate_tag: ai.my_verification_tag,
            advertised_receiver_window_credit: ai.max_receive_buffer_size,
            ..Default::default()
        };
        init.set_supported_extensions();

        let association_internal = Arc::new(Mutex::new(ai));
        {
            let weak = Arc::downgrade(&association_internal);
            let mut ai = association_internal.lock().await;
            ai.t1init = Some(RtxTimer::new(
                weak.clone(),
                RtxTimerId::T1Init,
                MAX_INIT_RETRANS,
            ));
            ai.t1cookie = Some(RtxTimer::new(
                weak.clone(),
                RtxTimerId::T1Cookie,
                MAX_INIT_RETRANS,
            ));
            ai.t2shutdown = Some(RtxTimer::new(
                weak.clone(),
                RtxTimerId::T2Shutdown,
                NO_MAX_RETRANS,
            )); // retransmit forever
            ai.t3rtx = Some(RtxTimer::new(
                weak.clone(),
                RtxTimerId::T3RTX,
                NO_MAX_RETRANS,
            )); // retransmit forever
            ai.treconfig = Some(RtxTimer::new(
                weak.clone(),
                RtxTimerId::Reconfig,
                NO_MAX_RETRANS,
            )); // retransmit forever
            ai.ack_timer = Some(AckTimer::new(weak, ACK_INTERVAL));

            tokio::spawn(Association::read_loop(
                name.clone(),
                Arc::clone(&bytes_received),
                Arc::clone(&net_conn),
                close_loop_ch_rx1,
                Arc::clone(&association_internal),
            ));

            tokio::spawn(Association::write_loop(
                name.clone(),
                Arc::clone(&bytes_sent),
                Arc::clone(&net_conn),
                close_loop_ch_rx2,
                Arc::clone(&association_internal),
                awake_write_loop_ch_rx,
            ));

            if is_client {
                ai.set_state(AssociationState::CookieWait);
                ai.stored_init = Some(init);
                ai.send_init()?;
                let rto = ai.rto_mgr.get_rto();
                if let Some(t1init) = &ai.t1init {
                    t1init.start(rto).await;
                }
            }
        }

        Ok((
            Association {
                name,
                state,
                max_message_size,
                inflight_queue_length,
                will_send_shutdown,
                awake_write_loop_ch,
                close_loop_ch_rx: Mutex::new(close_loop_ch_rx),
                accept_ch_rx: Mutex::new(accept_ch_rx),
                net_conn,
                bytes_received,
                bytes_sent,
                association_internal,
            },
            handshake_completed_ch_rx,
        ))
    }

    async fn read_loop(
        name: String,
        bytes_received: Arc<AtomicUsize>,
        net_conn: Arc<dyn Conn + Send + Sync>,
        mut close_loop_ch: broadcast::Receiver<()>,
        association_internal: Arc<Mutex<AssociationInternal>>,
    ) {
        log::debug!("[{}] read_loop entered", name);

        let mut buffer = vec![0u8; RECEIVE_MTU];
        let mut done = false;
        let mut n;
        while !done {
            tokio::select! {
                _ = close_loop_ch.recv() => break,
                result = net_conn.recv(&mut buffer) => {
                    match result {
                        Ok(m) => {
                            n=m;
                        }
                        Err(err) => {
                            log::warn!("[{}] failed to read packets on net_conn: {}", name, err);
                            break;
                        }
                    }
                }
            };

            // Make a buffer sized to what we read, then copy the data we
            // read from the underlying transport. We do this because the
            // user data is passed to the reassembly queue without
            // copying.
            log::debug!("[{}] recving {} bytes", name, n);
            let inbound = Bytes::from(buffer[..n].to_vec());
            bytes_received.fetch_add(n, Ordering::SeqCst);

            {
                let mut ai = association_internal.lock().await;
                if let Err(err) = ai.handle_inbound(&inbound).await {
                    log::warn!("[{}] failed to handle_inbound: {:?}", name, err);
                    done = true;
                }
            }
        }

        {
            let mut ai = association_internal.lock().await;
            if let Err(err) = ai.close().await {
                log::warn!("[{}] failed to close association: {:?}", name, err);
            }
        }

        log::debug!("[{}] read_loop exited", name);
    }

    async fn write_loop(
        name: String,
        bytes_sent: Arc<AtomicUsize>,
        net_conn: Arc<dyn Conn + Send + Sync>,
        mut close_loop_ch: broadcast::Receiver<()>,
        association_internal: Arc<Mutex<AssociationInternal>>,
        mut awake_write_loop_ch: mpsc::Receiver<()>,
    ) {
        log::debug!("[{}] write_loop entered", name);
        let done = Arc::new(AtomicBool::new(false));
        let name = Arc::new(name);
        let mut send_failures = SendFailureRun::default();

        'outer: while !done.load(Ordering::Relaxed) {
            //log::debug!("[{}] gather_outbound begin", name);
            let (packets, continue_loop, paced) = {
                let mut ai = association_internal.lock().await;
                let (packets, continue_loop) = ai.gather_outbound().await;
                (packets, continue_loop, ai.file_pacing_enabled())
            };
            let mut dispatched_data = false;
            //log::debug!("[{}] gather_outbound done with {}", name, packets.len());

            let net_conn = Arc::clone(&net_conn);
            let bytes_sent = Arc::clone(&bytes_sent);
            let name2 = Arc::clone(&name);
            let mut buffer = None;
            for raw in packets {
                let paced_data = paced
                    && raw
                        .chunks
                        .iter()
                        .any(|c| c.as_any().is::<ChunkPayloadData>());
                let mut buf = buffer
                    .take()
                    .unwrap_or_else(|| BytesMut::with_capacity(16 * 1024));

                // We do the marshalling work in a blocking task here for a reason:
                // If we don't tokio tends to run the write_loop and read_loop of one connection on the same OS thread
                // This means that even though we release the lock above, the read_loop isn't able to take it, simply because it is not being scheduled by tokio
                // Doing it this way, tokio schedules this work on a dedicated blocking thread, this future is suspended, and the read_loop can make progress
                match tokio::task::spawn_blocking(move || raw.marshal_to(&mut buf).map(|_| buf))
                    .await
                {
                    Ok(Ok(mut buf)) => {
                        let raw = buf.as_ref();
                        // meshharbor (#1856): a failed send is a LOST PACKET, not a
                        // dead association. Upstream ended the loop here, which
                        // closed the association and every stream on it, so one
                        // datagram a route change bounced (EHOSTUNREACH on a
                        // socket bound to an address whose route was briefly
                        // absent; ENOBUFS; an interface going away under a
                        // roam) killed a whole remote-desktop session. SCTP
                        // retransmits what was dropped, the way libwebrtc does.
                        // A transport that is really gone is still caught: its
                        // `recv` fails, and the read loop closes the association.
                        match net_conn.send(raw.as_ref()).await {
                            Ok(_) => {
                                bytes_sent.fetch_add(raw.len(), Ordering::SeqCst);
                                if let Some((dropped, over)) =
                                    send_failures.sent(std::time::Instant::now())
                                {
                                    // meshharbor (#1867): warn, like the failure line it
                                    // closes. The agent keeps `webrtc_sctp` at warn, so
                                    // at info the field saw failures and never this.
                                    log::warn!(
                                        "[{}] net_conn sends recovered — {} packet(s) dropped over {:?}, retransmitted by SCTP",
                                        name2,
                                        dropped,
                                        over
                                    );
                                }
                            }
                            Err(err) => {
                                if send_failures.failed(std::time::Instant::now()) {
                                    log::warn!(
                                        "[{}] failed to write packets on net_conn: {} — dropped, not fatal: SCTP retransmits ({} in this run)",
                                        name2,
                                        err,
                                        send_failures.dropped
                                    );
                                }
                            }
                        }

                        // Reuse allocation. Have to use options, since spawn blocking can't borrow, has to take ownership.
                        buf.clear();
                        buffer = Some(buf);
                    }
                    Ok(Err(err)) => {
                        log::warn!("[{}] failed to serialize a packet: {:?}", name2, err);
                    }
                    Err(err) => {
                        if err.is_cancelled() {
                            log::debug!(
                                "[{}] task cancelled while serializing a packet: {:?}",
                                name,
                                err
                            );
                            break 'outer;
                        } else {
                            log::error!("[{}] panic while serializing a packet: {:?}", name, err);
                        }
                    }
                }
                if paced_data {
                    association_internal.lock().await.file_pacing_dispatched();
                    dispatched_data = true;
                }
                //log::debug!("[{}] sending {} bytes done", name, raw.len());
            }

            if !continue_loop {
                break;
            }

            // A paced gather emits at most one DATA packet. Recheck queues
            // after its dispatch to either send the next funded packet or arm
            // one deadline. No association mutex is held while waiting.
            if dispatched_data {
                continue;
            }
            let deadline = association_internal.lock().await.file_pacing_deadline();
            let pacing_ready = async {
                if let Some(deadline) = deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                _ = awake_write_loop_ch.recv() =>{}
                _ = close_loop_ch.recv() => {
                    done.store(true, Ordering::Relaxed);
                }
                _ = pacing_ready => {}
            };
            //log::debug!("[{}] wait awake_write_loop_ch done", name);
        }

        {
            let mut ai = association_internal.lock().await;
            if let Err(err) = ai.close().await {
                log::warn!("[{}] failed to close association: {:?}", name, err);
            }
        }

        log::debug!("[{}] write_loop exited", name);
    }

    /// bytes_sent returns the number of bytes sent
    pub fn bytes_sent(&self) -> usize {
        self.bytes_sent.load(Ordering::SeqCst)
    }

    /// bytes_received returns the number of bytes received
    pub fn bytes_received(&self) -> usize {
        self.bytes_received.load(Ordering::SeqCst)
    }

    /// open_stream opens a stream
    pub async fn open_stream(
        &self,
        stream_identifier: u16,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Result<Arc<Stream>> {
        let mut ai = self.association_internal.lock().await;
        ai.open_stream(stream_identifier, default_payload_type)
    }

    /// accept_stream accepts a stream
    pub async fn accept_stream(&self) -> Option<Arc<Stream>> {
        let mut accept_ch_rx = self.accept_ch_rx.lock().await;
        accept_ch_rx.recv().await
    }

    /// max_message_size returns the maximum message size you can send.
    pub fn max_message_size(&self) -> u32 {
        self.max_message_size.load(Ordering::SeqCst)
    }

    /// set_max_message_size sets the maximum message size you can send.
    pub fn set_max_message_size(&self, max_message_size: u32) {
        self.max_message_size
            .store(max_message_size, Ordering::SeqCst);
    }

    /// set_state atomically sets the state of the Association.
    fn set_state(&self, new_state: AssociationState) {
        let old_state = AssociationState::from(self.state.swap(new_state as u8, Ordering::SeqCst));
        if new_state != old_state {
            log::debug!(
                "[{}] state change: '{}' => '{}'",
                self.name,
                old_state,
                new_state,
            );
        }
    }

    /// get_state atomically returns the state of the Association.
    fn get_state(&self) -> AssociationState {
        self.state.load(Ordering::SeqCst).into()
    }
}
