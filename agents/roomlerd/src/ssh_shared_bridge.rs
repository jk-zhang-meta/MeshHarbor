// SPDX-License-Identifier: MPL-2.0
//! Target-side typed SSH stream slots. No caller-controlled destination host or
//! port exists; each scoped peer can consume one prepared embedded-SSH stream.
use bson::oid::ObjectId;
use roomler_ai_remote_control::signaling::{ClientMsg, RejectKind, SharedSshSetup};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
struct Target {
    cancel: CancellationToken,
    #[cfg(feature = "ssh-server")]
    stream: Option<crate::ssh_shared_stream::SharedSshStream>,
}
#[derive(Default)]
pub struct SharedSshTargets {
    entries: HashMap<ObjectId, Target>,
}
impl Drop for SharedSshTargets {
    fn drop(&mut self) {
        for e in self.entries.values() {
            e.cancel.cancel();
        }
    }
}
impl SharedSshTargets {
    pub fn contains(&self, sid: ObjectId) -> bool {
        self.entries.contains_key(&sid)
    }
    #[cfg(feature = "ssh-server")]
    pub fn note(
        &mut self,
        sid: ObjectId,
        setup: SharedSshSetup,
        cfg: &crate::config::AgentConfig,
        services: crate::ssh::SessionServices,
    ) -> bool {
        if self.entries.len() >= 64
            || self.entries.contains_key(&sid)
            || setup.device_id.to_hex() != cfg.agent_id
        {
            return false;
        }
        #[cfg(feature = "ssh-server")]
        {
            let spec = crate::ssh_shared_stream::SharedSshSpec {
                grant_id: setup.ssh_grant_id,
                public_key: setup.public_key,
                caller: setup.caller,
                account_mode: setup.account_mode,
                account: setup.account,
                consent_mode: setup.consent_mode,
                expires_at_ms: setup.expires_at_ms,
                session_secs: setup.session_secs,
            };
            let Ok(stream) =
                crate::ssh_shared_stream::SharedSshStream::prepare(cfg, services, spec)
            else {
                return false;
            };
            self.entries.insert(
                sid,
                Target {
                    cancel: CancellationToken::new(),
                    stream: Some(stream),
                },
            );
            true
        }
        #[cfg(not(feature = "ssh-server"))]
        {
            let _ = (setup, services);
            false
        }
    }
    pub fn end(&mut self, sid: ObjectId) {
        if let Some(t) = self.entries.get_mut(&sid) {
            t.cancel.cancel();
            #[cfg(feature = "ssh-server")]
            t.stream.take();
        }
    }
    pub fn stop(
        &self,
        sid: ObjectId,
        peer: Arc<crate::tunnel::peer::AgentTunnelPeer>,
    ) -> Arc<dyn Fn() + Send + Sync> {
        let cancel = self.entries.get(&sid).map(|t| t.cancel.clone());
        Arc::new(move || {
            if let Some(c) = &cancel {
                c.cancel();
            }
            peer.stop_serving();
            let p = peer.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(3), p.close()).await;
            });
        })
    }
    pub fn forward(
        &mut self,
        sid: ObjectId,
        flow: u32,
        peer: Arc<crate::tunnel::peer::AgentTunnelPeer>,
        out: mpsc::Sender<ClientMsg>,
    ) {
        #[cfg(feature = "ssh-server")]
        if let Some(t) = self.entries.get_mut(&sid)
            && !t.cancel.is_cancelled()
            && let Some(stream) = t.stream.take()
        {
            let cancel = t.cancel.clone();
            tokio::spawn(async move {
                match stream.socket_pair(cancel).await {
                    Ok(stream) => {
                        crate::tunnel::acceptor::handle_preopened_forward(
                            sid, flow, stream, &peer, out,
                        )
                        .await
                    }
                    Err(_) => {
                        let _ = out.try_send(ClientMsg::TcpForwardReject {
                            session_id: sid,
                            flow_id: flow,
                            kind: RejectKind::AgentError,
                            reason: "The scoped embedded SSH stream is unavailable".into(),
                        });
                    }
                }
            });
            return;
        }
        let _ = peer;
        let _ = out.try_send(ClientMsg::TcpForwardReject {
            session_id: sid,
            flow_id: flow,
            kind: RejectKind::AclDenied,
            reason: "Missing, expired, or already consumed shared SSH scope".into(),
        });
    }
}

#[cfg(all(test, feature = "ssh-server"))]
mod tests {
    use super::*;
    use roomler_ai_remote_control::signaling::ServerMsg;
    use roomler_ai_remote_control::{
        models::{ConsentMode, SshAccountMode},
        signaling::SharedSessionLease,
    };
    use russh::keys::ssh_key::{PrivateKey, private::Ed25519Keypair};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tunnel_core::{
        driver::{SessionParams, Target, run_tunnel_session},
        signaling_link::{TunnelSignalingSink, TunnelSignalingSource},
    };
    struct Sink(mpsc::Sender<ClientMsg>);
    #[async_trait::async_trait]
    impl TunnelSignalingSink for Sink {
        async fn send(&self, msg: ClientMsg) -> anyhow::Result<()> {
            self.0
                .send(msg)
                .await
                .map_err(|_| anyhow::anyhow!("fixture server ended"))
        }
    }
    struct Source(mpsc::Receiver<ServerMsg>);
    #[async_trait::async_trait]
    impl TunnelSignalingSource for Source {
        async fn recv(&mut self) -> Option<ServerMsg> {
            self.0.recv().await
        }
    }
    struct Client {
        expected: russh::keys::ssh_key::PublicKey,
    }
    impl russh::client::Handler for Client {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(self.expected.key_data() == key.key_data())
        }
    }
    /// Real loopback WebRTC/DC -> typed single stream -> real embedded russh ->
    /// real exec output. No server/PDP is faked as passed by this payload proof;
    /// HTTP/recipient/agent scope enforcement is tested in crates/tests separately.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_ssh_typed_real_webrtc_flow_exec_single_use_and_hard_stop() {
        let sid = ObjectId::new();
        let device = ObjectId::new();
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[81u8; 32]));
        let mut cfg = crate::config::test_fixture();
        cfg.agent_id = device.to_hex();
        cfg.ssh_enabled = true;
        cfg.ssh_host_key = Some(crate::ssh::generate_host_key().unwrap());
        let expected = PrivateKey::from_openssh(cfg.ssh_host_key.as_deref().unwrap())
            .unwrap()
            .public_key()
            .clone();
        let scope = SharedSessionLease {
            grant_id: ObjectId::new(),
            lease_epoch: "11111111-1111-4111-8111-111111111111".into(),
        };
        let setup = SharedSshSetup {
            device_id: device,
            owner_user_id: ObjectId::new(),
            recipient_user_id: ObjectId::new(),
            shared_lease: scope,
            ssh_grant_id: ObjectId::new().to_hex(),
            public_key: key.public_key().to_openssh().unwrap(),
            caller: "approved loopback recipient".into(),
            account_mode: SshAccountMode::Daemon,
            account: None,
            consent_mode: Some(ConsentMode::Auto),
            expires_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 60_000,
            session_secs: 60,
        };
        let services = crate::ssh::SessionServices {
            power_activity: None,
            asker: crate::ssh::Asker::Here {
                broker: crate::consent::ConsentBroker::new(
                    crate::consent::Mode::AutoGrant,
                    tempfile::tempdir().unwrap().keep(),
                )
                .unwrap(),
                indicator: crate::indicator::ViewerIndicator::disabled(),
            },
            activity: None,
        };
        let mut targets = SharedSshTargets::default();
        assert!(targets.note(sid, setup, &cfg, services));
        let targets = Arc::new(tokio::sync::Mutex::new(targets));
        let (requests, mut requests_rx) = mpsc::channel(64);
        let (to_driver, from_server) = mpsc::channel(64);
        let (out, mut target_messages) = mpsc::channel(64);
        let forward_out = out.clone();
        let (event_tx, mut events) = mpsc::channel(32);
        let (target_tx, target_rx) = tokio::sync::oneshot::channel();
        let server_targets = targets.clone();
        // This is only a signaling fixture, NOT a fake passed authorization.
        // Use the production session driver, including dispatcher EOF ->
        // Carrier::dead -> drop -> flow cancellation, instead of a raw pump.
        let drain = tokio::spawn(async move {
            let mut target: Option<Arc<crate::tunnel::peer::AgentTunnelPeer>> = None;
            let mut target_tx = Some(target_tx);
            let mut early_ice = Vec::new();
            loop {
                tokio::select! {
                    msg = requests_rx.recv() => match msg {
                        Some(ClientMsg::TunnelHello {..}) => {},
                        Some(ClientMsg::TunnelOpen {..}) => {
                            to_driver.send(ServerMsg::TunnelOpened {
                                session_id:sid, transport:"webrtc-dc-v1".into(),
                                dc_pool_size:1, sctp_rwnd_bytes:1 << 20, ice_servers:vec![],
                                quic_auth_token:None, open_nonce:None, net_grant_id:None,
                            }).await.unwrap();
                        },
                        Some(ClientMsg::TunnelSdpOffer {sdp,..}) => {
                            let (reap, _) = mpsc::channel(crate::tunnel::reap::TUNNEL_REAP_CAP);
                            let (peer,answer) = crate::tunnel::peer::AgentTunnelPeer::accept_offer(
                                sid,&sdp,vec![],out.clone(),reap,
                            ).await.unwrap();
                            let peer = Arc::new(peer);
                            for ice in early_ice.drain(..) { let _ = peer.add_remote_ice(ice).await; }
                            to_driver.send(ServerMsg::TunnelSdpAnswer {session_id:sid,sdp:answer}).await.unwrap();
                            assert!(target_tx.take().unwrap().send(peer.clone()).is_ok());
                            target = Some(peer);
                        },
                        Some(ClientMsg::TunnelIce {candidate,..}) => {
                            if let Some(peer) = &target { let _ = peer.add_remote_ice(candidate).await; }
                            else { early_ice.push(candidate); }
                        },
                        Some(ClientMsg::TcpForwardRequest {flow_id,dst_host,dst_port,..}) => {
                            assert_eq!((dst_host.as_str(),dst_port),("embedded-ssh",22));
                            server_targets.lock().await.forward(sid,flow_id,target.as_ref().unwrap().clone(),out.clone());
                        },
                        Some(ClientMsg::TunnelTerminate {..}) | None => break,
                        _ => {},
                    },
                    msg = target_messages.recv() => {
                        let Some(msg) = msg else { break; };
                        let response = match msg {
                            ClientMsg::TunnelIce {candidate,..} => ServerMsg::TunnelIce {session_id:sid,candidate},
                            ClientMsg::TcpForwardAccept {flow_id,dc_index,..} => {
                                event_tx.send(ClientMsg::TcpForwardAccept {session_id:sid,flow_id,dc_index}).await.unwrap();
                                ServerMsg::TcpForwardAccept {session_id:sid,flow_id,dc_index}
                            },
                            ClientMsg::TcpForwardReject {flow_id,kind,reason,..} => {
                                event_tx.send(ClientMsg::TcpForwardReject {session_id:sid,flow_id,kind,reason:reason.clone()}).await.unwrap();
                                ServerMsg::TcpForwardReject {session_id:sid,flow_id,kind,reason}
                            },
                            ClientMsg::TcpClosed {flow_id,reason,..} => {
                                to_driver.send(ServerMsg::TcpClosed {session_id:sid,flow_id,reason}).await.unwrap();
                                // Exact center shared_ssh::run behavior: a target
                                // TcpClosed ends this one-flow user's WS/source.
                                break;
                            },
                            _ => continue,
                        };
                        if to_driver.send(response).await.is_err() { break; }
                    }
                }
            }
        });
        let (ready, ready_rx) = tokio::sync::oneshot::channel();
        let ready = std::sync::Mutex::new(Some(ready));
        let driver = tokio::spawn(run_tunnel_session(
            Arc::new(Sink(requests)),
            Box::new(Source(from_server)),
            0,
            SessionParams {
                agent_id: device,
                target: Target::Static {
                    host: "embedded-ssh".into(),
                    port: 22,
                },
                client_version: "shared-ssh-payload-fixture".into(),
                derp: None,
                on_listening: Some(Arc::new(move |addr| {
                    if let Some(tx) = ready.lock().unwrap().take() {
                        let _ = tx.send(addr);
                    }
                })),
                net_grant: None,
            },
            vec!["webrtc-dc-v1".into()],
            "webrtc-dc-v1",
            Arc::new(tunnel_core::forward::SessionThroughput::default()),
        ));
        let addr = tokio::time::timeout(Duration::from_secs(20), ready_rx)
            .await
            .unwrap()
            .unwrap();
        let target = target_rx.await.unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut ssh = tokio::time::timeout(
            Duration::from_secs(5),
            russh::client::connect_stream(
                Arc::new(russh::client::Config::default()),
                client,
                Client { expected },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let hash = ssh.best_supported_rsa_hash().await.unwrap().flatten();
        assert!(
            ssh.authenticate_publickey(
                "roomler",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash)
            )
            .await
            .unwrap()
            .success()
        );
        let mut command = ssh.channel_open_session().await.unwrap();
        command
            .exec(true, "echo meshharbor-typed-shared-flow-fixture")
            .await
            .unwrap();
        let (stdout, status) = tokio::time::timeout(Duration::from_secs(8), async {
            let mut stdout = Vec::new();
            let mut status = None;
            while let Some(msg) = command.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                    _ => {}
                }
            }
            (stdout, status)
        })
        .await
        .unwrap();
        assert!(String::from_utf8_lossy(&stdout).contains("meshharbor-typed-shared-flow-fixture"));
        assert_eq!(status, Some(0));
        let flow = match tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            ClientMsg::TcpForwardAccept { flow_id, .. } => flow_id,
            other => panic!("expected actual driver's accepted flow, got {other:?}"),
        };
        targets
            .lock()
            .await
            .forward(sid, flow + 1, target.clone(), forward_out);
        let rejected = tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(rejected,ClientMsg::TcpForwardReject {flow_id,..} if flow_id==flow+1));
        // Actual target lease hard-stop produces TcpClosed, the real center
        // ends the WS, and the production driver cancels its TCP/DC carrier.
        targets.lock().await.stop(sid, target.clone())();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), ssh.channel_open_session())
                .await
                .expect("production driver must close the local SSH transport")
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(3), driver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        target.close().await;
        drain.abort();
    }
}
