use super::*;

/// Observe real advertised windows without changing the association internals.
/// DATA accounting remains in the existing FilePacingWire fixture.
struct ReceiverWindowWire {
    inner: Arc<dyn Conn + Send + Sync>,
    zero_advertised: Arc<AtomicBool>,
}

#[async_trait]
impl Conn for ReceiverWindowWire {
    async fn connect(&self, addr: SocketAddr) -> UResult<()> {
        self.inner.connect(addr).await
    }
    async fn recv(&self, bytes: &mut [u8]) -> UResult<usize> {
        let n = self.inner.recv(bytes).await?;
        if n == 0 {
            return Ok(n);
        }
        let packet = Packet::unmarshal(&Bytes::copy_from_slice(&bytes[..n]))
            .expect("invalid SCTP input in receiver-window fixture");
        for chunk in packet.chunks {
            if let Some(sack) = chunk.as_any().downcast_ref::<ChunkSelectiveAck>() {
                if sack.advertised_receiver_window_credit == 0 {
                    self.zero_advertised.store(true, Ordering::SeqCst);
                }
            }
        }
        Ok(n)
    }
    async fn recv_from(&self, bytes: &mut [u8]) -> UResult<(usize, SocketAddr)> {
        self.inner.recv_from(bytes).await
    }
    async fn send(&self, bytes: &[u8]) -> UResult<usize> {
        self.inner.send(bytes).await
    }
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> UResult<usize> {
        self.inner.send_to(bytes, target).await
    }
    fn local_addr(&self) -> UResult<SocketAddr> {
        self.inner.local_addr()
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }
    async fn close(&self) -> UResult<()> {
        self.inner.close().await
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[tokio::test]
async fn test_file_pacing_zero_receiver_window_recovers_in_order_within_budget() -> Result<()> {
    const RECEIVE_BYTES: u32 = 8 * 1024;
    const MESSAGE_BYTES: usize = 1024;
    const MESSAGES: usize = 24;
    const RATE: u64 = 64 * 1024;
    const BURST: usize = 1280;

    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let zero_advertised = Arc::new(AtomicBool::new(false));
    let (left, right) = pipe();
    let wire = Arc::new(FilePacingWire {
        inner: Arc::new(left),
        data: events.clone(),
        dropped: Arc::new(tokio::sync::Notify::new()),
        drop_next_data: AtomicBool::new(false),
        data_ready: Arc::new(tokio::sync::Notify::new()),
    });
    let connect = async {
        tokio::try_join!(
            Association::client(Config {
                net_conn: Arc::new(ReceiverWindowWire {
                    inner: wire.clone(),
                    zero_advertised: zero_advertised.clone(),
                }),
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: "paced-window-client".into(),
            }),
            Association::server(Config {
                net_conn: Arc::new(right),
                max_receive_buffer_size: RECEIVE_BYTES,
                max_message_size: 0,
                name: "paced-window-receiver".into(),
            }),
        )
    };
    let (file, remote) = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| Error::Other("paced window handshake timed out".into()))??;
    let (file, remote) = (Arc::new(file), Arc::new(remote));
    // Join a separate task so even an assertion panic reaches both close calls.
    let mut exercise = tokio::spawn({
        let file = file.clone();
        let remote = remote.clone();
        async move {
            let tx = file
                .open_stream(25, PayloadProtocolIdentifier::Binary)
                .await?;
            let rx = remote
                .open_stream(25, PayloadProtocolIdentifier::Binary)
                .await?;
            let acks = file_pacing_ack_signal(&tx);
            let warmup = Bytes::from(vec![0x57; 64]);
            tx.write_sctp(&warmup, PayloadProtocolIdentifier::Binary)
                .await?;
            read_pacing_config_message(&rx, &warmup).await?;
            wait_file_pacing_ack(&tx, &acks, 0).await?;
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let published = wire.data_ready.notified();
                    tokio::pin!(published);
                    published.as_mut().enable();
                    if !events.lock().unwrap().is_empty() {
                        break;
                    }
                    published.await;
                }
            })
            .await
            .map_err(|_| Error::Other("warmup wire record missing".into()))?;
            events.lock().unwrap().clear();
            zero_advertised.store(false, Ordering::SeqCst);
            file.set_file_pacing(Some(FilePacingConfig {
                rate_bytes_per_second: RATE,
                burst_bytes: BURST,
            }))
            .await?;
            let payload = |sequence: usize| {
                let mut bytes = vec![sequence as u8 ^ 0xa5; MESSAGE_BYTES];
                bytes[..4].copy_from_slice(&(sequence as u32).to_be_bytes());
                Bytes::from(bytes)
            };
            for sequence in 0..MESSAGES {
                assert_eq!(
                    tx.write_sctp(&payload(sequence), PayloadProtocolIdentifier::Binary)
                        .await?,
                    MESSAGE_BYTES
                );
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let credit = remote
                        .association_internal
                        .lock()
                        .await
                        .get_my_receiver_window_credit()
                        .await;
                    if credit == 0 && zero_advertised.load(Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .map_err(|_| {
                Error::Other("paced receiver never advertised an actual zero window".into())
            })?;
            assert!(file.association_internal.lock().await.file_pacing_enabled());
            assert!(
                tx.buffered_amount() > 0,
                "zero-window fixture had no remaining transfer"
            );
            eprintln!("X14_PACED_RWND zero_credit=true zero_sack_received=true pacing_enabled=true queued_bytes={}", tx.buffered_amount());

            // Reading is the only recovery action: no pacing reset or forced SACK.
            // Zero-window probes/retransmissions are valid and share the budget.
            for sequence in 0..MESSAGES {
                read_pacing_config_message(&rx, &payload(sequence)).await?;
            }
            wait_file_pacing_ack(&tx, &acks, 0).await?;
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let published = wire.data_ready.notified();
                    tokio::pin!(published);
                    published.as_mut().enable();
                    let unique: std::collections::HashSet<_> = events
                        .lock()
                        .unwrap()
                        .iter()
                        .flat_map(|event| event.tsns.iter().copied())
                        .collect();
                    if unique.len() >= MESSAGES {
                        break;
                    }
                    published.await;
                }
            })
            .await
            .map_err(|_| Error::Other("final DATA wire records missing".into()))?;
            let recorded = events.lock().unwrap().clone();
            assert_file_pacing_wire_budget(&recorded, RATE, BURST);
            assert!(recorded.iter().all(|event| !event.dropped_by_fixture));
            assert_eq!(tx.buffered_amount(), 0);
            assert_eq!(file.inflight_queue_length.load(Ordering::SeqCst), 0);
            assert_eq!(rx.get_num_bytes_in_reassembly_queue().await, 0);
            assert_eq!(
                remote
                    .association_internal
                    .lock()
                    .await
                    .get_my_receiver_window_credit()
                    .await,
                RECEIVE_BYTES
            );
            let t3 = file
                .association_internal
                .lock()
                .await
                .stats
                .get_num_t3timeouts();
            eprintln!("X14_PACED_RWND verified_bytes={} messages={} wire_attempts={} t3={} final_ack=true send_queue_empty=true receiver_queue_empty=true wire_budget=true", MESSAGES * MESSAGE_BYTES, MESSAGES, recorded.len(), t3);
            Ok::<(), Error>(())
        }
    });
    let outcome = match tokio::time::timeout(Duration::from_secs(20), &mut exercise).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(Error::Other(format!("paced window task failed: {error}"))),
        Err(_) => {
            exercise.abort();
            let _ = exercise.await;
            Err(Error::Other(
                "paced window regression exceeded safety bound".into(),
            ))
        }
    };
    let (left, right) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), file.close()),
        tokio::time::timeout(Duration::from_secs(2), remote.close()),
    );
    let closed = matches!(left, Ok(Ok(()))) && matches!(right, Ok(Ok(())));
    eprintln!("X14_PACED_RWND both_associations_closed={closed}");
    if !closed {
        return Err(Error::Other(
            "paced window associations did not close".into(),
        ));
    }
    assert_eq!(file.get_state(), AssociationState::Closed);
    assert_eq!(remote.get_state(), AssociationState::Closed);
    outcome
}
