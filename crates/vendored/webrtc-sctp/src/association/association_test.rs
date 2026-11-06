// Silence warning on `for i in 0..vec.len() { … }`:
#![allow(clippy::needless_range_loop)]

#[path = "file_pacing_flow_control_test.rs"]
mod file_pacing_flow_control_test;

use std::io;
use std::net::{Shutdown, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use util::conn::conn_bridge::*;
use util::conn::conn_pipe::pipe;
use util::conn::*;

use super::*;
use crate::chunk::chunk_selective_ack::GapAckBlock;
use crate::stream::*;

async fn create_new_association_pair(
    br: &Arc<Bridge>,
    ca: Arc<dyn Conn + Send + Sync>,
    cb: Arc<dyn Conn + Send + Sync>,
    ack_mode: AckMode,
    recv_buf_size: u32,
) -> Result<(Association, Association)> {
    let (handshake0ch_tx, mut handshake0ch_rx) = mpsc::channel(1);
    let (handshake1ch_tx, mut handshake1ch_rx) = mpsc::channel(1);
    let (closed_tx, mut closed_rx0) = broadcast::channel::<()>(1);
    let mut closed_rx1 = closed_tx.subscribe();

    // Setup client
    tokio::spawn(async move {
        let client = Association::client(Config {
            net_conn: ca,
            max_receive_buffer_size: recv_buf_size,
            max_message_size: 0,
            name: "client".to_owned(),
        })
        .await;

        let _ = handshake0ch_tx.send(client).await;
        let _ = closed_rx0.recv().await;

        Result::<()>::Ok(())
    });

    // Setup server
    tokio::spawn(async move {
        let server = Association::server(Config {
            net_conn: cb,
            max_receive_buffer_size: recv_buf_size,
            max_message_size: 0,
            name: "server".to_owned(),
        })
        .await;

        let _ = handshake1ch_tx.send(server).await;
        let _ = closed_rx1.recv().await;

        Result::<()>::Ok(())
    });

    let mut client = None;
    let mut server = None;
    let mut a0handshake_done = false;
    let mut a1handshake_done = false;
    let mut i = 0;
    while (!a0handshake_done || !a1handshake_done) && i < 100 {
        br.tick().await;

        let timer = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() =>{},
            r0 = handshake0ch_rx.recv() => {
                if let Ok(c) = r0.unwrap() {
                    client = Some(c);
                }
                a0handshake_done = true;
            },
            r1 = handshake1ch_rx.recv() => {
                if let Ok(s) = r1.unwrap() {
                    server = Some(s);
                }
                a1handshake_done = true;
            },
        };
        i += 1;
    }

    if !a0handshake_done || !a1handshake_done {
        return Err(Error::Other("handshake failed".to_owned()));
    }

    drop(closed_tx);

    let (client, server) = (client.unwrap(), server.unwrap());
    {
        let mut ai = client.association_internal.lock().await;
        ai.ack_mode = ack_mode;
    }
    {
        let mut ai = server.association_internal.lock().await;
        ai.ack_mode = ack_mode;
    }

    Ok((client, server))
}

async fn close_association_pair(br: &Arc<Bridge>, client: Association, server: Association) {
    let (handshake0ch_tx, mut handshake0ch_rx) = mpsc::channel(1);
    let (handshake1ch_tx, mut handshake1ch_rx) = mpsc::channel(1);
    let (closed_tx, mut closed_rx0) = broadcast::channel::<()>(1);
    let mut closed_rx1 = closed_tx.subscribe();

    // Close client
    tokio::spawn(async move {
        client.close().await?;
        let _ = handshake0ch_tx.send(()).await;
        let _ = closed_rx0.recv().await;

        Result::<()>::Ok(())
    });

    // Close server
    tokio::spawn(async move {
        server.close().await?;
        let _ = handshake1ch_tx.send(()).await;
        let _ = closed_rx1.recv().await;

        Result::<()>::Ok(())
    });

    let mut a0handshake_done = false;
    let mut a1handshake_done = false;
    let mut i = 0;
    while (!a0handshake_done || !a1handshake_done) && i < 100 {
        br.tick().await;

        let timer = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() =>{},
            _ = handshake0ch_rx.recv() => {
                a0handshake_done = true;
            },
            _ = handshake1ch_rx.recv() => {
                a1handshake_done = true;
            },
        };
        i += 1;
    }

    drop(closed_tx);
}

async fn flush_buffers(br: &Arc<Bridge>, client: &Association, server: &Association) {
    loop {
        loop {
            let n = br.tick().await;
            if n == 0 {
                break;
            }
        }

        {
            let (a0, a1) = (
                client.association_internal.lock().await,
                server.association_internal.lock().await,
            );
            if a0.buffered_amount() == 0 && a1.buffered_amount() == 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn establish_session_pair(
    br: &Arc<Bridge>,
    client: &Association,
    server: &mut Association,
    si: u16,
) -> Result<(Arc<Stream>, Arc<Stream>)> {
    let hello_msg = Bytes::from_static(b"Hello");
    let s0 = client
        .open_stream(si, PayloadProtocolIdentifier::Binary)
        .await?;
    let _ = s0
        .write_sctp(&hello_msg, PayloadProtocolIdentifier::Dcep)
        .await?;

    flush_buffers(br, client, server).await;

    let s1 = server.accept_stream().await.unwrap();
    if s0.stream_identifier != s1.stream_identifier {
        return Err(Error::Other("SI should match".to_owned()));
    }

    br.process().await;

    let mut buf = vec![0u8; 1024];
    let (n, ppi) = s1.read_sctp(&mut buf).await?;

    if n != hello_msg.len() {
        return Err(Error::Other("received data must by 3 bytes".to_owned()));
    }

    if ppi != PayloadProtocolIdentifier::Dcep {
        return Err(Error::Other("unexpected ppi".to_owned()));
    }

    if buf[..n] != hello_msg {
        return Err(Error::Other("received data mismatch".to_owned()));
    }

    flush_buffers(br, client, server).await;

    Ok((s0, s1))
}

//use std::io::Write;

#[cfg(not(target_os = "windows"))] // this times out in CI on windows.
#[tokio::test]
async fn test_assoc_reliable_simple() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    static MSG: Bytes = Bytes::from_static(b"ABC");

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), 0, "incorrect bufferedAmount");
    }

    let n = s0
        .write_sctp(&MSG, PayloadProtocolIdentifier::Binary)
        .await?;
    assert_eq!(n, MSG.len(), "unexpected length of received data");
    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), MSG.len(), "incorrect bufferedAmount");
    }

    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 32];
    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, MSG.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), 0, "incorrect bufferedAmount");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

// NB: This is ignored on Windows due to flakiness with timing/IO interactions.
// TODO: Refactor this and other tests that are disabled for similar reason to not have such issues
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_assoc_reliable_ordered_reordered() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 2;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }
    let mut sbufl = vec![0u8; 2000];
    for i in 0..sbufl.len() {
        sbufl[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), 0, "incorrect bufferedAmount");
    }

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    tokio::time::sleep(Duration::from_millis(10)).await;
    br.reorder(0).await;
    br.process().await;

    let mut buf = vec![0u8; 2000];

    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        0,
        "unexpected received data"
    );

    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_reliable_ordered_fragmented_then_defragmented() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 3;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }
    let mut sbufl = vec![0u8; 2000];
    for i in 0..sbufl.len() {
        sbufl[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    s0.set_reliability_params(false, ReliabilityType::Reliable, 0);
    s1.set_reliability_params(false, ReliabilityType::Reliable, 0);

    let n = s0
        .write_sctp(
            &Bytes::from(sbufl.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbufl.len(), "unexpected length of received data");

    flush_buffers(&br, &a0, &a1).await;

    let mut rbuf = vec![0u8; 2000];
    let (n, ppi) = s1.read_sctp(&mut rbuf).await?;
    assert_eq!(n, sbufl.len(), "unexpected length of received data");
    assert_eq!(&rbuf[..n], &sbufl, "unexpected received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_reliable_unordered_fragmented_then_defragmented() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 4;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }
    let mut sbufl = vec![0u8; 2000];
    for i in 0..sbufl.len() {
        sbufl[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    s0.set_reliability_params(true, ReliabilityType::Reliable, 0);
    s1.set_reliability_params(true, ReliabilityType::Reliable, 0);

    let n = s0
        .write_sctp(
            &Bytes::from(sbufl.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbufl.len(), "unexpected length of received data");

    flush_buffers(&br, &a0, &a1).await;

    let mut rbuf = vec![0u8; 2000];
    let (n, ppi) = s1.read_sctp(&mut rbuf).await?;
    assert_eq!(n, sbufl.len(), "unexpected length of received data");
    assert_eq!(&rbuf[..n], &sbufl, "unexpected received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_reliable_unordered_ordered() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 5;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }
    let mut sbufl = vec![0u8; 2000];
    for i in 0..sbufl.len() {
        sbufl[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    s0.set_reliability_params(true, ReliabilityType::Reliable, 0);
    s1.set_reliability_params(true, ReliabilityType::Reliable, 0);

    br.reorder_next_nwrites(0, 2);

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 2000];

    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        0,
        "unexpected received data"
    );

    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

// NB: This is ignored on Windows due to flakiness with timing/IO interactions.
// TODO: Refactor this and other tests that are disabled for similar reason to not have such issues
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_assoc_reliable_retransmission() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 6;
    static MSG1: Bytes = Bytes::from_static(b"ABC");
    static MSG2: Bytes = Bytes::from_static(b"DEFG");

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;
    {
        let mut a = a0.association_internal.lock().await;
        a.rto_mgr.set_rto(100, true);
    }

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    let n = s0
        .write_sctp(&MSG1, PayloadProtocolIdentifier::Binary)
        .await?;
    assert_eq!(n, MSG1.len(), "unexpected length of received data");

    let n = s0
        .write_sctp(&MSG2, PayloadProtocolIdentifier::Binary)
        .await?;
    assert_eq!(n, MSG2.len(), "unexpected length of received data");

    tokio::time::sleep(Duration::from_millis(10)).await;
    log::debug!("dropping packet");
    br.drop_offset(0, 0, 1).await; // drop the first packet (second one should be sacked)

    // process packets for 200 msec
    for _ in 0..20 {
        br.tick().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut buf = vec![0u8; 32];

    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, MSG1.len(), "unexpected length of received data");
    assert_eq!(&buf[..n], &MSG1, "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, MSG2.len(), "unexpected length of received data");
    assert_eq!(&buf[..n], &MSG2, "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_reliable_short_buffer() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    static MSG: Bytes = Bytes::from_static(b"Hello");

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), 0, "incorrect bufferedAmount");
    }

    let n = s0
        .write_sctp(&MSG, PayloadProtocolIdentifier::Binary)
        .await?;
    assert_eq!(n, MSG.len(), "unexpected length of received data");
    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), MSG.len(), "incorrect bufferedAmount");
    }

    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 3];
    let result = s1.read_sctp(&mut buf).await;
    assert!(result.is_err(), "expected error to be ErrShortBuffer");
    if let Err(err) = result {
        assert_eq!(
            err,
            Error::ErrShortBuffer { size: 3 },
            "expected error to be ErrShortBuffer"
        );
    }

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), 0, "incorrect bufferedAmount");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_unreliable_rexmit_ordered_no_fragment() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    // When we set the reliability value to 0 [times], then it will cause
    // the chunk to be abandoned immediately after the first transmission.
    s0.set_reliability_params(false, ReliabilityType::Rexmit, 0);
    s1.set_reliability_params(false, ReliabilityType::Rexmit, 0); // doesn't matter

    br.drop_next_nwrites(0, 1); // drop the first packet (second one should be sacked)

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    log::debug!("flush_buffers");
    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 2000];

    log::debug!("read_sctp");
    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    log::debug!("process");
    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_unreliable_rexmit_ordered_fragment() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    let mut sbuf = vec![0u8; 2000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        // lock RTO value at 100 [msec]
        let mut a = a0.association_internal.lock().await;
        a.rto_mgr.set_rto(100, true);
    }
    // When we set the reliability value to 0 [times], then it will cause
    // the chunk to be abandoned immediately after the first transmission.
    s0.set_reliability_params(false, ReliabilityType::Rexmit, 0);
    s1.set_reliability_params(false, ReliabilityType::Rexmit, 0); // doesn't matter

    br.drop_next_nwrites(0, 1); // drop the first packet (second one should be sacked)

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    //log::debug!("flush_buffers");
    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 2000];

    //log::debug!("read_sctp");
    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    //log::debug!("process");
    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_unreliable_rexmit_unordered_no_fragment() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 2;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    // When we set the reliability value to 0 [times], then it will cause
    // the chunk to be abandoned immediately after the first transmission.
    s0.set_reliability_params(true, ReliabilityType::Rexmit, 0);
    s1.set_reliability_params(true, ReliabilityType::Rexmit, 0); // doesn't matter

    br.drop_next_nwrites(0, 1); // drop the first packet (second one should be sacked)

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    //log::debug!("flush_buffers");
    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 2000];

    //log::debug!("read_sctp");
    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    //log::debug!("process");
    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

// NB: This is ignored on Windows and macOS due to flakiness with timing/IO interactions.
// TODO: Refactor this and other tests that are disabled for similar reason to not have such issues
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[tokio::test]
async fn test_assoc_unreliable_rexmit_unordered_fragment() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    let mut sbuf = vec![0u8; 2000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    // When we set the reliability value to 0 [times], then it will cause
    // the chunk to be abandoned immediately after the first transmission.
    s0.set_reliability_params(true, ReliabilityType::Rexmit, 0);
    s1.set_reliability_params(true, ReliabilityType::Rexmit, 0); // doesn't matter

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    //log::debug!("flush_buffers");
    tokio::time::sleep(Duration::from_millis(10)).await;
    br.drop_offset(0, 0, 2).await; // drop the second fragment of the first chunk (second chunk should be sacked)
    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 2000];

    //log::debug!("read_sctp");
    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    //log::debug!("process");
    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
        assert_eq!(
            q.unordered.len(),
            0,
            "should be nothing in the unordered queue"
        );
        assert_eq!(
            q.unordered_chunks.len(),
            0,
            "should be nothing in the unorderedChunks list"
        );
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_unreliable_rexmit_timed_ordered() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 3;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    // When we set the reliability value to 0 [times], then it will cause
    // the chunk to be abandoned immediately after the first transmission.
    s0.set_reliability_params(false, ReliabilityType::Timed, 0);
    s1.set_reliability_params(false, ReliabilityType::Timed, 0); // doesn't matter

    br.drop_next_nwrites(0, 1); // drop the first packet (second one should be sacked)

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    //log::debug!("flush_buffers");
    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 2000];

    //log::debug!("read_sctp");
    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    //log::debug!("process");
    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_unreliable_rexmit_timed_unordered() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 3;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    // When we set the reliability value to 0 [times], then it will cause
    // the chunk to be abandoned immediately after the first transmission.
    s0.set_reliability_params(true, ReliabilityType::Timed, 0);
    s1.set_reliability_params(true, ReliabilityType::Timed, 0); // doesn't matter

    br.drop_next_nwrites(0, 1); // drop the first packet (second one should be sacked)

    sbuf[0..4].copy_from_slice(&0u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    sbuf[0..4].copy_from_slice(&1u32.to_be_bytes());
    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )
        .await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    //log::debug!("flush_buffers");
    flush_buffers(&br, &a0, &a1).await;

    let mut buf = vec![0u8; 2000];

    //log::debug!("read_sctp");
    let (n, ppi) = s1.read_sctp(&mut buf).await?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
    assert_eq!(
        u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        1,
        "unexpected received data"
    );

    //log::debug!("process");
    br.process().await;

    {
        let q = s0.reassembly_queue.lock().await;
        assert!(!q.is_readable(), "should no longer be readable");
        assert_eq!(
            q.unordered.len(),
            0,
            "should be nothing in the unordered queue"
        );
        assert_eq!(
            q.unordered_chunks.len(),
            0,
            "should be nothing in the unorderedChunks list"
        );
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//TODO: TestAssocT1InitTimer
//TODO: TestAssocT1CookieTimer
//TODO: TestAssocT3RtxTimer

//use std::io::Write;

// 1) Send 4 packets. drop the first one.
// 2) Last 3 packet will be received, which triggers fast-retransmission
// 3) The first one is retransmitted, which makes s1 readable
// Above should be done before RTO occurs (fast recovery)
#[tokio::test]
async fn test_assoc_congestion_control_fast_retransmission() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 6;
    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::Normal, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    br.drop_next_nwrites(0, 1); // drop the first packet (second one should be sacked)

    for i in 0..4u32 {
        sbuf[0..4].copy_from_slice(&i.to_be_bytes());
        let n = s0
            .write_sctp(
                &Bytes::from(sbuf.clone()),
                PayloadProtocolIdentifier::Binary,
            )
            .await?;
        assert_eq!(n, sbuf.len(), "unexpected length of received data");
    }

    // process packets for 500 msec, assuming that the fast retrans/recover
    // should complete within 500 msec.
    for _ in 0..50 {
        br.tick().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut buf = vec![0u8; 3000];

    // Try to read all 4 packets
    for i in 0..4 {
        {
            let q = s1.reassembly_queue.lock().await;
            assert!(q.is_readable(), "should be readable");
        }

        let (n, ppi) = s1.read_sctp(&mut buf).await?;
        assert_eq!(n, sbuf.len(), "unexpected length of received data");
        assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
        assert_eq!(
            u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            i,
            "unexpected received data"
        );
    }

    //br.process().await;

    {
        let a = a0.association_internal.lock().await;
        let b = a1.association_internal.lock().await;
        assert!(!a.in_fast_recovery, "should not be in fast-recovery");

        log::debug!("nDATAs      : {}", b.stats.get_num_datas());
        log::debug!("nSACKs      : {}", a.stats.get_num_sacks());
        log::debug!("nAckTimeouts: {}", b.stats.get_num_ack_timeouts());
        log::debug!("nFastRetrans: {}", a.stats.get_num_fast_retrans());

        assert_eq!(a.stats.get_num_fast_retrans(), 1, "should be 1");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_congestion_control_congestion_avoidance() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const MAX_RECEIVE_BUFFER_SIZE: u32 = 64 * 1024;
    const SI: u16 = 6;
    const N_PACKETS_TO_SEND: u32 = 2000;

    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) = create_new_association_pair(
        &br,
        Arc::new(ca),
        Arc::new(cb),
        AckMode::Normal,
        MAX_RECEIVE_BUFFER_SIZE,
    )
    .await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        let a = a0.association_internal.lock().await;
        let b = a1.association_internal.lock().await;
        a.stats.reset();
        b.stats.reset();
    }

    for i in 0..N_PACKETS_TO_SEND {
        sbuf[0..4].copy_from_slice(&i.to_be_bytes());
        let n = s0
            .write_sctp(
                &Bytes::from(sbuf.clone()),
                PayloadProtocolIdentifier::Binary,
            )
            .await?;
        assert_eq!(n, sbuf.len(), "unexpected length of received data");
    }

    let mut rbuf = vec![0u8; 3000];

    // Repeat calling br.Tick() until the buffered amount becomes 0
    let mut n_packets_received = 0u32;
    while s0.buffered_amount() > 0 && n_packets_received < N_PACKETS_TO_SEND {
        loop {
            let n = br.tick().await;
            if n == 0 {
                break;
            }
        }

        loop {
            let readable = {
                let q = s1.reassembly_queue.lock().await;
                q.is_readable()
            };
            if !readable {
                break;
            }
            let (n, ppi) = s1.read_sctp(&mut rbuf).await?;
            assert_eq!(n, sbuf.len(), "unexpected length of received data");
            assert_eq!(
                n_packets_received,
                u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]),
                "unexpected length of received data"
            );
            assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

            n_packets_received += 1;
        }
    }

    br.process().await;

    assert_eq!(
        n_packets_received, N_PACKETS_TO_SEND,
        "unexpected num of packets received"
    );

    {
        let a = a0.association_internal.lock().await;
        let b = a1.association_internal.lock().await;

        assert!(!a.in_fast_recovery, "should not be in fast-recovery");
        assert!(
            a.cwnd > a.ssthresh,
            "should be in congestion avoidance mode"
        );
        assert!(
            a.ssthresh >= MAX_RECEIVE_BUFFER_SIZE,
            "{} should not be less than the initial size of 128KB {}",
            a.ssthresh,
            MAX_RECEIVE_BUFFER_SIZE
        );

        assert_eq!(
            0,
            s1.get_num_bytes_in_reassembly_queue().await,
            "reassembly queue should be empty"
        );

        log::debug!("nDATAs      : {}", b.stats.get_num_datas());
        log::debug!("nSACKs      : {}", a.stats.get_num_sacks());
        log::debug!("nT3Timeouts: {}", a.stats.get_num_t3timeouts());

        assert_eq!(
            b.stats.get_num_datas(),
            N_PACKETS_TO_SEND as u64,
            "packet count mismatch"
        );
        assert!(
            a.stats.get_num_sacks() <= N_PACKETS_TO_SEND as u64 / 2,
            "too many sacks"
        );
        assert_eq!(a.stats.get_num_t3timeouts(), 0, "should be no retransmit");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_congestion_control_slow_reader() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const MAX_RECEIVE_BUFFER_SIZE: u32 = 64 * 1024;
    const SI: u16 = 6;
    const N_PACKETS_TO_SEND: u32 = 130;

    let mut sbuf = vec![0u8; 1000];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) = create_new_association_pair(
        &br,
        Arc::new(ca),
        Arc::new(cb),
        AckMode::Normal,
        MAX_RECEIVE_BUFFER_SIZE,
    )
    .await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    for i in 0..N_PACKETS_TO_SEND {
        sbuf[0..4].copy_from_slice(&i.to_be_bytes());
        let n = s0
            .write_sctp(
                &Bytes::from(sbuf.clone()),
                PayloadProtocolIdentifier::Binary,
            )
            .await?;
        assert_eq!(n, sbuf.len(), "unexpected length of received data");
    }

    let mut rbuf = vec![0u8; 3000];

    // 1. First forward packets to receiver until rwnd becomes 0
    // 2. Wait until the sender's cwnd becomes 1*MTU (RTO occurred)
    // 3. Stat reading a1's data
    let mut n_packets_received = 0u32;
    let mut has_rtoed = false;
    while s0.buffered_amount() > 0 && n_packets_received < N_PACKETS_TO_SEND {
        loop {
            let n = br.tick().await;
            if n == 0 {
                break;
            }
        }

        if !has_rtoed {
            let a = a0.association_internal.lock().await;
            let b = a1.association_internal.lock().await;

            let rwnd = b.get_my_receiver_window_credit().await;
            let cwnd = a.cwnd;
            if cwnd > a.mtu || rwnd > 0 {
                // Do not read until a1.getMyReceiverWindowCredit() becomes zero
                continue;
            }

            has_rtoed = true;
        }

        loop {
            let readable = {
                let q = s1.reassembly_queue.lock().await;
                q.is_readable()
            };
            if !readable {
                break;
            }
            let (n, ppi) = s1.read_sctp(&mut rbuf).await?;
            assert_eq!(n, sbuf.len(), "unexpected length of received data");
            assert_eq!(
                n_packets_received,
                u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]),
                "unexpected length of received data"
            );
            assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

            n_packets_received += 1;
        }

        tokio::time::sleep(Duration::from_millis(4)).await;
    }

    br.process().await;

    assert_eq!(
        n_packets_received, N_PACKETS_TO_SEND,
        "unexpected num of packets received"
    );
    assert_eq!(
        s1.get_num_bytes_in_reassembly_queue().await,
        0,
        "reassembly queue should be empty"
    );

    {
        let a = a0.association_internal.lock().await;
        let b = a1.association_internal.lock().await;

        log::debug!("nDATAs      : {}", b.stats.get_num_datas());
        log::debug!("nSACKs      : {}", a.stats.get_num_sacks());
        log::debug!("nAckTimeouts: {}", b.stats.get_num_ack_timeouts());
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

/*FIXME
use std::io::Write;

#[tokio::test]
async fn test_assoc_delayed_ack() -> Result<()> {
    env_logger::Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{}:{} [{}] {} - {}",
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.level(),
                chrono::Local::now().format("%H:%M:%S.%6f"),
                record.args()
            )
        })
        .filter(None, log::LevelFilter::Trace)
        .init();

    const SI: u16 = 6;
    let mut sbuf = vec![0u8; 1000];
    let mut rbuf = vec![0u8; 1500];
    for i in 0..sbuf.len() {
        sbuf[i] = (i & 0xff) as u8;
    }

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::AlwaysDelay, 0)
            .await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        let a = a0.association_internal.lock().await;
        let b = a1.association_internal.lock().await;
        a.stats.reset();
        b.stats.reset();
    }

    let n = s0
        .write_sctp(
            &Bytes::from(sbuf.clone()),
            PayloadProtocolIdentifier::Binary,
        )?;
    assert_eq!(n, sbuf.len(), "unexpected length of received data");

    // Repeat calling br.Tick() until the buffered amount becomes 0
    let since = SystemTime::now();
    let mut n_packets_received = 0;
    while s0.buffered_amount() > 0 {
        loop {
            let n = br.tick().await;
            if n == 0 {
                break;
            }
        }

        loop {
            let readable = {
                let q = s1.reassembly_queue.lock().await;
                q.is_readable()
            };
            if !readable {
                break;
            }
            let (n, ppi) = s1.read_sctp(&mut rbuf).await?;
            assert_eq!(n, sbuf.len(), "unexpected length of received data");
            assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");

            n_packets_received += 1;
        }
    }
    let delay = (SystemTime::now().duration_since(since).unwrap().as_millis() as f64) / 1000.0;
    log::debug!("received in {} seconds", delay);
    assert!(delay >= 0.2, "should be >= 200msec");

    br.process().await;

    assert_eq!(n_packets_received, 1, "unexpected num of packets received");
    assert_eq!(
        s1.get_num_bytes_in_reassembly_queue().await,
        0,
        "reassembly queue should be empty"
    );

    {
        let a = a0.association_internal.lock().await;
        let b = a1.association_internal.lock().await;

        log::debug!("nDATAs      : {}", b.stats.get_num_datas());
        log::debug!("nSACKs      : {}", a.stats.get_num_sacks());
        log::debug!("nAckTimeouts: {}", b.stats.get_num_ack_timeouts());

        assert_eq!(b.stats.get_num_datas(), 1, "DATA chunk count mismatch");
        assert_eq!(
            a.stats.get_num_sacks(),
            b.stats.get_num_datas(),
            "sack count should be equal to the number of data chunks"
        );
        assert_eq!(
            b.stats.get_num_ack_timeouts(),
            1,
            "ackTimeout count mismatch"
        );
        assert_eq!(a.stats.get_num_t3timeouts(), 0, "should be no retransmit");
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}
*/

//use std::io::Write;

#[tokio::test]
async fn test_assoc_reset_close_one_way() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    static MSG: Bytes = Bytes::from_static(b"ABC");

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        let a = a0.association_internal.lock().await;
        assert_eq!(0, a.buffered_amount(), "incorrect bufferedAmount");
    }

    let n = s0
        .write_sctp(&MSG, PayloadProtocolIdentifier::Binary)
        .await?;
    assert_eq!(n, MSG.len(), "unexpected length of received data");
    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), MSG.len(), "incorrect bufferedAmount");
    }

    log::debug!("s0.shutdown");
    s0.shutdown(Shutdown::Both).await?; // send reset

    let (done_ch_tx, mut done_ch_rx) = mpsc::channel(1);
    let mut buf = vec![0u8; 32];

    tokio::spawn(async move {
        loop {
            log::debug!("s1.read_sctp begin");
            match s1.read_sctp(&mut buf).await {
                Ok((0, PayloadProtocolIdentifier::Unknown)) => {
                    log::debug!("s1.read_sctp EOF");
                    let _ = done_ch_tx.send(Some(Error::ErrEof)).await;
                    break;
                }
                Ok((n, ppi)) => {
                    log::debug!("s1.read_sctp done with {:?}", &buf[..n]);
                    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
                    assert_eq!(n, MSG.len(), "unexpected length of received data");
                    let _ = done_ch_tx.send(None).await;
                }
                Err(err) => {
                    log::debug!("s1.read_sctp err {:?}", err);
                    let _ = done_ch_tx.send(Some(err)).await;
                    break;
                }
            }
        }
    });

    loop {
        br.process().await;

        let timer = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() =>{},
            result = done_ch_rx.recv() => {
                log::debug!("s1. {:?}", result);
                if let Some(err_opt) = result {
                    if err_opt.is_some() {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_reset_close_both_ways() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    static MSG: Bytes = Bytes::from_static(b"ABC");

    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    {
        let a = a0.association_internal.lock().await;
        assert_eq!(0, a.buffered_amount(), "incorrect bufferedAmount");
    }

    let n = s0
        .write_sctp(&MSG, PayloadProtocolIdentifier::Binary)
        .await?;
    assert_eq!(n, MSG.len(), "unexpected length of received data");
    {
        let a = a0.association_internal.lock().await;
        assert_eq!(a.buffered_amount(), MSG.len(), "incorrect bufferedAmount");
    }

    log::debug!("s0.shutdown");
    s0.shutdown(Shutdown::Both).await?; // send reset

    let (done_ch_tx, mut done_ch_rx) = mpsc::channel(1);
    let done_ch_tx = Arc::new(done_ch_tx);

    let done_ch_tx1 = Arc::clone(&done_ch_tx);
    let ss1 = Arc::clone(&s1);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32];
        loop {
            log::debug!("s1.read_sctp begin");
            match ss1.read_sctp(&mut buf).await {
                Ok((0, PayloadProtocolIdentifier::Unknown)) => {
                    log::debug!("s1.read_sctp EOF");
                    let _ = done_ch_tx1.send(Some(Error::ErrEof)).await;
                    break;
                }
                Ok((n, ppi)) => {
                    log::debug!("s1.read_sctp done with {:?}", &buf[..n]);
                    assert_eq!(ppi, PayloadProtocolIdentifier::Binary, "unexpected ppi");
                    assert_eq!(n, MSG.len(), "unexpected length of received data");
                    let _ = done_ch_tx1.send(None).await;
                }
                Err(err) => {
                    log::debug!("s1.read_sctp err {:?}", err);
                    let _ = done_ch_tx1.send(Some(err)).await;
                    break;
                }
            }
        }
    });

    loop {
        br.process().await;

        let timer = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() =>{},
            result = done_ch_rx.recv() => {
                log::debug!("s1. {:?}", result);
                if let Some(err_opt) = result {
                    if err_opt.is_some() {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    log::debug!("s1.shutdown");
    s1.shutdown(Shutdown::Both).await?; // send reset

    let done_ch_tx0 = Arc::clone(&done_ch_tx);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32];

        log::debug!("s.read_sctp begin");
        match s0.read_sctp(&mut buf).await {
            Ok((0, PayloadProtocolIdentifier::Unknown)) => {
                log::debug!("s0.read_sctp EOF");
                let _ = done_ch_tx0.send(Some(Error::ErrEof)).await;
            }
            Ok(_) => {
                panic!("must be error");
            }
            Err(err) => {
                log::debug!("s0.read_sctp err {:?}", err);
                let _ = done_ch_tx0.send(Some(err)).await;
            }
        }
    });

    loop {
        br.process().await;

        let timer = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(timer);

        tokio::select! {
            _ = timer.as_mut() =>{},
            result = done_ch_rx.recv() => {
                log::debug!("s0. {:?}", result);
                if let Some(err_opt) = result {
                    if err_opt.is_some() {
                        break;
                    } else {
                        panic!("must be error");
                    }
                } else {
                    break;
                }
            }
        }
    }

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_assoc_abort() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    const SI: u16 = 1;
    let (br, ca, cb) = Bridge::new(0, None, None);

    let (a0, mut a1) =
        create_new_association_pair(&br, Arc::new(ca), Arc::new(cb), AckMode::NoDelay, 0).await?;

    let abort = ChunkAbort {
        error_causes: vec![ErrorCauseProtocolViolation {
            code: PROTOCOL_VIOLATION,
            ..Default::default()
        }],
    };

    let packet = {
        let a = a0.association_internal.lock().await;
        a.create_packet(vec![Box::new(abort)]).marshal()?
    };

    let (_s0, _s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    // Both associations are established
    assert_eq!(a0.get_state(), AssociationState::Established);
    assert_eq!(a1.get_state(), AssociationState::Established);

    let result = a0.net_conn.send(&packet).await;
    assert!(result.is_ok(), "must be ok");

    flush_buffers(&br, &a0, &a1).await;

    // There is a little delay before changing the state to closed
    tokio::time::sleep(Duration::from_millis(10)).await;

    // The receiving association should be closed because it got an ABORT
    assert_eq!(a0.get_state(), AssociationState::Established);
    assert_eq!(a1.get_state(), AssociationState::Closed);

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

struct FakeEchoConn {
    wr_tx: Mutex<mpsc::Sender<Vec<u8>>>,
    rd_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    bytes_sent: AtomicUsize,
    bytes_received: AtomicUsize,
}

impl FakeEchoConn {
    fn type_erased() -> impl Conn {
        Self::default()
    }
}

impl Default for FakeEchoConn {
    fn default() -> Self {
        let (wr_tx, rd_rx) = mpsc::channel(1);
        FakeEchoConn {
            wr_tx: Mutex::new(wr_tx),
            rd_rx: Mutex::new(rd_rx),
            bytes_sent: AtomicUsize::new(0),
            bytes_received: AtomicUsize::new(0),
        }
    }
}

type UResult<T> = std::result::Result<T, util::Error>;

#[async_trait]
impl Conn for FakeEchoConn {
    async fn connect(&self, _addr: SocketAddr) -> UResult<()> {
        Err(io::Error::new(io::ErrorKind::Other, "Not applicable").into())
    }

    async fn recv(&self, b: &mut [u8]) -> UResult<usize> {
        let mut rd_rx = self.rd_rx.lock().await;
        let v = match rd_rx.recv().await {
            Some(v) => v,
            None => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF").into())
            }
        };
        let l = std::cmp::min(v.len(), b.len());
        b[..l].copy_from_slice(&v[..l]);
        self.bytes_received.fetch_add(l, Ordering::SeqCst);
        Ok(l)
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> UResult<(usize, SocketAddr)> {
        Err(io::Error::new(io::ErrorKind::Other, "Not applicable").into())
    }

    async fn send(&self, b: &[u8]) -> UResult<usize> {
        let wr_tx = self.wr_tx.lock().await;
        match wr_tx.send(b.to_vec()).await {
            Ok(_) => {}
            Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string()).into()),
        };
        self.bytes_sent.fetch_add(b.len(), Ordering::SeqCst);
        Ok(b.len())
    }

    async fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> UResult<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "Not applicable").into())
    }

    fn local_addr(&self) -> UResult<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Addr Not Available").into())
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> UResult<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

//use std::io::Write;

#[tokio::test]
async fn test_stats() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    let conn = Arc::new(FakeEchoConn::type_erased());
    let a = Association::client(Config {
        net_conn: Arc::clone(&conn) as Arc<dyn Conn + Send + Sync>,
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: "client".to_owned(),
    })
    .await?;

    if let Some(conn) = conn.as_any().downcast_ref::<FakeEchoConn>() {
        assert_eq!(
            conn.bytes_received.load(Ordering::SeqCst),
            a.bytes_received()
        );
        assert_eq!(conn.bytes_sent.load(Ordering::SeqCst), a.bytes_sent());
    } else {
        panic!("must be FakeEchoConn");
    }

    Ok(())
}

async fn create_assocs() -> Result<(Association, Association)> {
    let addr1 = SocketAddr::from_str("0.0.0.0:0").unwrap();
    let addr2 = SocketAddr::from_str("0.0.0.0:0").unwrap();

    let udp1 = UdpSocket::bind(addr1).await.unwrap();
    let udp2 = UdpSocket::bind(addr2).await.unwrap();

    udp1.connect(udp2.local_addr().unwrap()).await.unwrap();
    udp2.connect(udp1.local_addr().unwrap()).await.unwrap();

    let (a1chan_tx, mut a1chan_rx) = mpsc::channel(1);
    let (a2chan_tx, mut a2chan_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let a = Association::client(Config {
            net_conn: Arc::new(udp1),
            max_receive_buffer_size: 0,
            max_message_size: 0,
            name: "client".to_owned(),
        })
        .await?;

        let _ = a1chan_tx.send(a).await;

        Result::<()>::Ok(())
    });

    tokio::spawn(async move {
        let a = Association::server(Config {
            net_conn: Arc::new(udp2),
            max_receive_buffer_size: 0,
            max_message_size: 0,
            name: "server".to_owned(),
        })
        .await?;

        let _ = a2chan_tx.send(a).await;

        Result::<()>::Ok(())
    });

    let timer1 = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(timer1);
    let a1 = tokio::select! {
        _ = timer1.as_mut() =>{
            panic!("timed out waiting for a1");
        },
        a1 = a1chan_rx.recv() => {
            a1.unwrap()
        }
    };

    let timer2 = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(timer2);
    let a2 = tokio::select! {
        _ = timer2.as_mut() =>{
            panic!("timed out waiting for a2");
        },
        a2 = a2chan_rx.recv() => {
            a2.unwrap()
        }
    };

    Ok((a1, a2))
}

//use std::io::Write;
//TODO: remove this conditional test
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_association_shutdown() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    let (a1, a2) = create_assocs().await?;

    let s11 = a1.open_stream(1, PayloadProtocolIdentifier::String).await?;
    let s21 = a2.open_stream(1, PayloadProtocolIdentifier::String).await?;

    let test_data = Bytes::from_static(b"test");

    let n = s11.write(&test_data).await?;
    assert_eq!(n, test_data.len());

    let mut buf = vec![0u8; test_data.len()];
    let n = s21.read(&mut buf).await?;
    assert_eq!(n, test_data.len());
    assert_eq!(&buf[0..n], &test_data);

    if let Ok(result) = tokio::time::timeout(Duration::from_secs(1), a1.shutdown()).await {
        assert!(result.is_ok(), "shutdown should be ok");
    } else {
        panic!("shutdown timeout");
    }

    {
        let mut close_loop_ch_rx = a2.close_loop_ch_rx.lock().await;

        // Wait for close read loop channels to prevent flaky tests.
        let timer2 = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(timer2);
        tokio::select! {
            _ = timer2.as_mut() =>{
                panic!("timed out waiting for a2 read loop to close");
            },
            _ = close_loop_ch_rx.recv() => {
                log::debug!("recv a2.close_loop_ch_rx");
            }
        };
    }
    Ok(())
}

//use std::io::Write;
//TODO: remove this conditional test
#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn test_association_shutdown_during_write() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    let (a1, a2) = create_assocs().await?;

    let s11 = a1.open_stream(1, PayloadProtocolIdentifier::String).await?;
    let s21 = a2.open_stream(1, PayloadProtocolIdentifier::String).await?;

    let (writing_done_tx, mut writing_done_rx) = mpsc::channel::<()>(1);
    let ss21 = Arc::clone(&s21);
    tokio::spawn(async move {
        let mut i = 0;
        while ss21.write(&Bytes::from(vec![i])).await.is_ok() {
            if i == 255 {
                i = 0;
            } else {
                i += 1;
            }

            if i % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        drop(writing_done_tx);
    });

    let test_data = Bytes::from_static(b"test");

    let n = s11.write(&test_data).await?;
    assert_eq!(n, test_data.len());

    let mut buf = vec![0u8; test_data.len()];
    let n = s21.read(&mut buf).await?;
    assert_eq!(n, test_data.len());
    assert_eq!(&buf[0..n], &test_data);

    {
        let mut close_loop_ch_rx = a1.close_loop_ch_rx.lock().await;
        tokio::select! {
            res = tokio::time::timeout(Duration::from_secs(1), a1.shutdown()) => {
                if let Ok(result) = res {
                    assert!(result.is_ok(), "shutdown should be ok");
                } else {
                    panic!("shutdown timeout");
                }
            }
            _ = writing_done_rx.recv() => {
                log::debug!("writing_done_rx");
                let result = close_loop_ch_rx.recv().await;
                log::debug!("a1.close_loop_ch_rx.recv: {:?}", result);
            },
        };
    }

    {
        let mut close_loop_ch_rx = a2.close_loop_ch_rx.lock().await;
        // Wait for close read loop channels to prevent flaky tests.
        let timer2 = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(timer2);
        tokio::select! {
            _ = timer2.as_mut() =>{
                panic!("timed out waiting for a2 read loop to close");
            },
            _ = close_loop_ch_rx.recv() => {
                log::debug!("recv a2.close_loop_ch_rx");
            }
        };
    }

    Ok(())
}

//use std::io::Write;

#[tokio::test]
async fn test_association_handle_packet_before_init() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, log::LevelFilter::Trace)
    .init();*/

    let tests = vec![
        (
            "InitAck",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::new(ChunkInit {
                    is_ack: true,
                    initiate_tag: 1,
                    num_inbound_streams: 1,
                    num_outbound_streams: 1,
                    advertised_receiver_window_credit: 1500,
                    ..Default::default()
                })],
            },
        ),
        (
            "Abort",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkAbort>::default()],
            },
        ),
        (
            "CoockeEcho",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkCookieEcho>::default()],
            },
        ),
        (
            "HeartBeat",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkHeartbeat>::default()],
            },
        ),
        (
            "PayloadData",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkPayloadData>::default()],
            },
        ),
        (
            "Sack",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::new(ChunkSelectiveAck {
                    cumulative_tsn_ack: 1000,
                    advertised_receiver_window_credit: 1500,
                    gap_ack_blocks: vec![GapAckBlock {
                        start: 100,
                        end: 200,
                    }],
                    ..Default::default()
                })],
            },
        ),
        (
            "Reconfig",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::new(ChunkReconfig {
                    param_a: Some(Box::<ParamOutgoingResetRequest>::default()),
                    param_b: Some(Box::<ParamReconfigResponse>::default()),
                })],
            },
        ),
        (
            "ForwardTSN",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::new(ChunkForwardTsn {
                    new_cumulative_tsn: 100,
                    ..Default::default()
                })],
            },
        ),
        (
            "Error",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkError>::default()],
            },
        ),
        (
            "Shutdown",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkShutdown>::default()],
            },
        ),
        (
            "ShutdownAck",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkShutdownAck>::default()],
            },
        ),
        (
            "ShutdownComplete",
            Packet {
                source_port: 1,
                destination_port: 1,
                verification_tag: 0,
                chunks: vec![Box::<ChunkShutdownComplete>::default()],
            },
        ),
    ];

    for (name, packet) in tests {
        log::debug!("testing {}", name);

        let (a_conn, charlie_conn) = pipe();

        let (a, _) = Association::new(
            Config {
                net_conn: Arc::new(a_conn),
                max_message_size: 0,
                max_receive_buffer_size: 0,
                name: "client".to_owned(),
            },
            true,
        )
        .await
        .unwrap();

        let packet = packet.marshal()?;
        let result = charlie_conn.send(&packet).await;
        assert!(result.is_ok(), "{name} charlie_conn.send should be ok");

        // Should not panic.
        tokio::time::sleep(Duration::from_millis(100)).await;

        a.close().await.unwrap();
    }

    Ok(())
}

/// meshharbor (#1856) — delegates to `inner`, failing the next N sends the way a
/// UDP socket does when its route vanishes underneath it.
struct FailNextSends {
    inner: Arc<dyn Conn + Send + Sync>,
    fail_next: AtomicUsize,
    failed: AtomicUsize,
}

impl FailNextSends {
    fn new(inner: Arc<dyn Conn + Send + Sync>) -> Self {
        FailNextSends {
            inner,
            fail_next: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Conn for FailNextSends {
    async fn connect(&self, addr: SocketAddr) -> UResult<()> {
        self.inner.connect(addr).await
    }

    async fn recv(&self, b: &mut [u8]) -> UResult<usize> {
        self.inner.recv(b).await
    }

    async fn recv_from(&self, b: &mut [u8]) -> UResult<(usize, SocketAddr)> {
        self.inner.recv_from(b).await
    }

    async fn send(&self, b: &[u8]) -> UResult<usize> {
        if self
            .fail_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.failed.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::from(io::ErrorKind::HostUnreachable).into());
        }
        self.inner.send(b).await
    }

    async fn send_to(&self, b: &[u8], target: SocketAddr) -> UResult<usize> {
        self.inner.send_to(b, target).await
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

/// meshharbor (#1856): one failed send is a lost packet, not a dead association.
/// A remote-desktop peer whose overlay route vanished for ~3 ms got a single
/// `EHOSTUNREACH`; the write loop treated it as fatal, closed the association
/// and every data channel on it, and the session died. The dropped DATA chunk
/// must instead arrive by retransmission, on an association still established.
#[tokio::test]
async fn test_assoc_survives_a_failed_send() -> Result<()> {
    const SI: u16 = 1;
    static MSG: Bytes = Bytes::from_static(b"after the hole");

    let (br, ca, cb) = Bridge::new(0, None, None);
    let flaky = Arc::new(FailNextSends::new(Arc::new(ca)));
    let (a0, mut a1) = create_new_association_pair(
        &br,
        Arc::clone(&flaky) as Arc<dyn Conn + Send + Sync>,
        Arc::new(cb),
        AckMode::NoDelay,
        0,
    )
    .await?;
    let (s0, s1) = establish_session_pair(&br, &a0, &mut a1, SI).await?;

    flaky.fail_next.store(1, Ordering::SeqCst);
    s0.write_sctp(&MSG, PayloadProtocolIdentifier::Binary)
        .await?;

    // Keep the bridge moving until the T3 retransmission lands (RTO >= 1 s).
    let mut buf = vec![0u8; 64];
    let read = async {
        loop {
            br.tick().await;
            if let Ok(r) =
                tokio::time::timeout(Duration::from_millis(10), s1.read_sctp(&mut buf)).await
            {
                break r;
            }
        }
    };
    let (n, ppi) = tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .map_err(|_| Error::Other("the dropped message was never retransmitted".to_owned()))??;

    assert_eq!(
        flaky.failed.load(Ordering::SeqCst),
        1,
        "the injected send failure must have fired, or this proves nothing"
    );
    assert_eq!(&buf[..n], &MSG[..], "retransmitted payload");
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary);
    assert_eq!(a0.get_state(), AssociationState::Established);

    close_association_pair(&br, a0, a1).await;

    Ok(())
}

#[test]
fn test_send_failure_run_logs_first_then_rate_limited_then_recovery() {
    let t0 = std::time::Instant::now();
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    let mut run = SendFailureRun::default();

    // A send with no failures before it reports nothing.
    assert_eq!(run.sent(at(0)), None);

    // The first failure of a run is logged; the next ones only every 5 s.
    assert!(run.failed(at(0)));
    assert!(!run.failed(at(1)));
    assert!(!run.failed(at(4_999)));
    assert!(run.failed(at(5_000)));
    assert_eq!(run.dropped, 4);

    // The first success ends the run and reports it once.
    assert_eq!(run.sent(at(5_500)), Some((4, Duration::from_millis(5_500))));
    assert_eq!(run.sent(at(5_600)), None);

    // A new run logs its first failure again, whatever the last log's age.
    assert!(run.failed(at(6_000)));
    assert_eq!(run.dropped, 1);
}

/// Verify a complete message through the real SCTP stream. The timeout is
/// only a stalled-IO guard; no throughput or scheduling deadline is asserted.
async fn read_pacing_config_message(stream: &Stream, expected: &[u8]) -> Result<()> {
    let mut buffer = vec![0; expected.len()];
    let (n, ppi) = tokio::time::timeout(Duration::from_secs(5), stream.read_sctp(&mut buffer))
        .await
        .map_err(|_| Error::Other("configuration probe real-pipe read timed out".into()))??;
    assert_eq!(ppi, PayloadProtocolIdentifier::Binary);
    assert_eq!(
        &buffer[..n],
        expected,
        "default SCTP message was truncated or corrupted"
    );
    Ok(())
}

/// Configuration safety only. This deliberately does not claim to exercise
/// pacing deadlines, queue/T3 timing, fairness or cancellation. The earlier
/// Bridge/paused-clock harness failures are retained in their run evidence.
#[tokio::test]
async fn test_file_pacing_rejects_invalid_config_without_breaking_default_io() -> Result<()> {
    let (left, right) = pipe();
    let connect = async {
        tokio::try_join!(
            Association::client(Config {
                net_conn: Arc::new(left),
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: "config-safety-client".into(),
            }),
            Association::server(Config {
                net_conn: Arc::new(right),
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: "config-safety-server".into(),
            }),
        )
    };
    let (client, server) = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| Error::Other("configuration probe real-pipe handshake timed out".into()))??;
    let tx = client
        .open_stream(17, PayloadProtocolIdentifier::Binary)
        .await?;
    let payload = |seed: u8| -> Bytes {
        Bytes::from(
            (0..4096)
                .map(|i| (i % 251) as u8 ^ seed)
                .collect::<Vec<_>>(),
        )
    };
    let initial = payload(0x51);
    assert_eq!(
        tx.write_sctp(&initial, PayloadProtocolIdentifier::Binary)
            .await?,
        initial.len()
    );
    let rx = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .map_err(|_| {
            Error::Other("configuration probe real-pipe stream acceptance timed out".into())
        })?
        .ok_or_else(|| {
            Error::Other("configuration probe stream closed before acceptance".into())
        })?;
    read_pacing_config_message(&rx, &initial).await?;
    eprintln!(
        "X14_CONFIG_SAFETY initial_default_io verified_bytes={}",
        initial.len()
    );

    for (name, config, reason, seed) in [
        (
            "zero-rate",
            FilePacingConfig {
                rate_bytes_per_second: 0,
                burst_bytes: 1280,
            },
            "rate_bytes_per_second must be nonzero",
            0xa6,
        ),
        // SCTP common + DATA headers alone cannot carry one payload byte.
        (
            "header-only-burst",
            FilePacingConfig {
                rate_bytes_per_second: 128,
                burst_bytes: (COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE) as usize,
            },
            "burst_bytes must fit an SCTP DATA frame",
            0x33,
        ),
    ] {
        let result = client.set_file_pacing(Some(config)).await;
        assert!(
            result.is_err(),
            "illegal file pacing configuration was accepted: {name}"
        );
        assert!(result.unwrap_err().to_string().contains(reason));
        // Do not reset to None here: that could hide a rejected call that
        // nevertheless mutated the association's default sending state.
        let after_rejection = payload(seed);
        assert_eq!(
            tx.write_sctp(&after_rejection, PayloadProtocolIdentifier::Binary)
                .await?,
            after_rejection.len()
        );
        read_pacing_config_message(&rx, &after_rejection).await?;
        assert_eq!(client.get_state(), AssociationState::Established);
        eprintln!(
            "X14_CONFIG_SAFETY rejected={name} default_io_verified_bytes={}",
            after_rejection.len()
        );
    }
    let acks = file_pacing_ack_signal(&tx);
    wait_file_pacing_ack(&tx, &acks, 0).await?;
    client
        .set_file_pacing(Some(FilePacingConfig {
            rate_bytes_per_second: 128,
            burst_bytes: 1280,
        }))
        .await?;
    client.set_file_pacing(None).await?;
    let unchanged = payload(0x19);
    assert_eq!(
        tx.write_sctp(&unchanged, PayloadProtocolIdentifier::Binary)
            .await?,
        unchanged.len()
    );
    read_pacing_config_message(&rx, &unchanged).await?;
    assert_eq!(client.get_state(), AssociationState::Established);
    eprintln!(
        "X14_CONFIG_SAFETY mode=explicit-default default_io_verified_bytes={}",
        unchanged.len()
    );
    client.close().await?;
    server.close().await?;
    Ok(())
}

/// Independent of pacing: each isolated message must be acknowledged by a
/// newly armed delayed-ACK timer, without an RTO/duplicate DATA rescuing it.
#[tokio::test]
async fn test_assoc_delayed_ack_rearms_after_each_timer_generated_sack() -> Result<()> {
    let scenario = async {
        let (left, right) = pipe();
        let (client, server) = tokio::try_join!(
            Association::client(Config {
                net_conn: Arc::new(left),
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: "delayed-ack-client".into(),
            }),
            Association::server(Config {
                net_conn: Arc::new(right),
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: "delayed-ack-server".into(),
            }),
        )?;
        let tx = client
            .open_stream(21, PayloadProtocolIdentifier::Binary)
            .await?;
        let rx = server
            .open_stream(21, PayloadProtocolIdentifier::Binary)
            .await?;
        let acks = file_pacing_ack_signal(&tx);
        for n in 1..=2 {
            let message = Bytes::from(vec![n as u8; 64]);
            tx.write_sctp(&message, PayloadProtocolIdentifier::Binary)
                .await?;
            read_pacing_config_message(&rx, &message).await?;
            wait_file_pacing_ack(&tx, &acks, 0).await?;
            assert_eq!(
                server
                    .association_internal
                    .lock()
                    .await
                    .stats
                    .get_num_ack_timeouts(),
                n,
                "each isolated message needs its own delayed-ACK timer"
            );
            assert_eq!(
                client
                    .association_internal
                    .lock()
                    .await
                    .stats
                    .get_num_t3timeouts(),
                0,
                "retransmission must not rescue a missing delayed ACK"
            );
        }
        client.close().await?;
        server.close().await?;
        Ok::<(), Error>(())
    };
    tokio::time::timeout(Duration::from_secs(10), scenario)
        .await
        .map_err(|_| Error::Other("isolated delayed-ACK regression exceeded safety bound".into()))?
}

#[derive(Clone, Debug)]
struct FilePacingDispatch {
    started: std::time::Instant,
    completed: std::time::Instant,
    bytes: usize,
    tsns: Vec<u32>,
    dropped_by_fixture: bool,
}

struct FilePacingWire {
    inner: Arc<dyn Conn + Send + Sync>,
    data: Arc<std::sync::Mutex<Vec<FilePacingDispatch>>>,
    dropped: Arc<tokio::sync::Notify>,
    drop_next_data: AtomicBool,
    data_ready: Arc<tokio::sync::Notify>,
}

impl Drop for FilePacingWire {
    fn drop(&mut self) {
        self.dropped.notify_waiters();
    }
}

#[async_trait]
impl Conn for FilePacingWire {
    async fn connect(&self, addr: SocketAddr) -> UResult<()> {
        self.inner.connect(addr).await
    }
    async fn recv(&self, b: &mut [u8]) -> UResult<usize> {
        self.inner.recv(b).await
    }
    async fn recv_from(&self, b: &mut [u8]) -> UResult<(usize, SocketAddr)> {
        self.inner.recv_from(b).await
    }
    async fn send(&self, b: &[u8]) -> UResult<usize> {
        let started = std::time::Instant::now();
        let packet = Packet::unmarshal(&Bytes::copy_from_slice(b))
            .expect("invalid SCTP output in file pacing probe");
        let tsns: Vec<_> = packet
            .chunks
            .iter()
            .filter_map(|chunk| {
                chunk
                    .as_any()
                    .downcast_ref::<ChunkPayloadData>()
                    .map(|data| data.tsn)
            })
            .collect();
        // Only an explicitly armed DATA attempt is discarded. Returning its
        // full length models packet loss after submission, not a send error.
        // Handshake, ACK and all other control packets always reach the pipe.
        let data_only = !tsns.is_empty() && tsns.len() == packet.chunks.len();
        let dropped_by_fixture = data_only && self.drop_next_data.swap(false, Ordering::SeqCst);
        let sent = if dropped_by_fixture {
            b.len()
        } else {
            self.inner.send(b).await?
        };
        let completed = std::time::Instant::now();
        if sent == b.len() && !tsns.is_empty() {
            // Include the discarded encoded datagram in the attempt budget:
            // network loss does not refund bytes to the sender's token bucket.
            self.data.lock().unwrap().push(FilePacingDispatch {
                started,
                completed,
                bytes: sent,
                tsns,
                dropped_by_fixture,
            });
            self.data_ready.notify_waiters();
        }
        Ok(sent)
    }
    async fn send_to(&self, b: &[u8], target: SocketAddr) -> UResult<usize> {
        self.inner.send_to(b, target).await
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

fn file_pacing_ack_signal(stream: &Stream) -> Arc<tokio::sync::Notify> {
    let signal = Arc::new(tokio::sync::Notify::new());
    let notify = signal.clone();
    stream.on_buffered_amount_low(Box::new(move || {
        let notify = notify.clone();
        Box::pin(async move {
            notify.notify_waiters();
        })
    }));
    signal
}

async fn wait_file_pacing_ack(
    stream: &Stream,
    signal: &tokio::sync::Notify,
    remaining: usize,
) -> Result<()> {
    stream.set_buffered_amount_low_threshold(remaining);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let notified = signal.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if stream.buffered_amount() <= remaining {
                return;
            }
            notified.await;
        }
    })
    .await
    .map_err(|_| {
        Error::Other(format!(
            "real file pacing ACK timeout: buffered={} target={remaining}",
            stream.buffered_amount()
        ))
    })
}

fn assert_file_pacing_wire_budget(events: &[FilePacingDispatch], rate: u64, burst: usize) {
    assert!(!events.is_empty(), "no successful DATA dispatch observed");
    for (start, first) in events.iter().enumerate() {
        let mut bytes = 0usize;
        for last in &events[start..] {
            // Bound the actual departure interval conservatively by both
            // ends of Conn::send; a blocked pipe cannot masquerade as pacing.
            assert!(
                last.completed.duration_since(last.started) < Duration::from_secs(1),
                "fixture pipe blocked, so dispatch timing is inconclusive"
            );
            bytes += last.bytes;
            let elapsed = last.completed.duration_since(first.started).as_nanos();
            let allowed = burst as u128 + rate as u128 * elapsed / 1_000_000_000 + 32;
            assert!(
                bytes as u128 <= allowed,
                "DATA wire budget exceeded: bytes={bytes} allowed={allowed} events={events:?}"
            );
        }
    }
}

/// Real-clock, real-pipe contract, not a throughput/fairness benchmark.
/// The first recorded RED stopped at unsupported enable. Only a complete run
/// reaches and proves the wire/T3/isolation/close assertions below.
#[tokio::test]
async fn test_file_pacing_real_wire_budget_isolation_queue_and_close() -> Result<()> {
    let scenario = async {
        const RATE: u64 = 128;
        const BURST: usize = 1280;
        let data = Arc::new(std::sync::Mutex::new(Vec::new()));
        let dropped = Arc::new(tokio::sync::Notify::new());
        let (left, right) = pipe();
        let wire = Arc::new(FilePacingWire {
            inner: Arc::new(left),
            data: data.clone(),
            dropped: dropped.clone(),
            drop_next_data: AtomicBool::new(false),
            data_ready: Arc::new(tokio::sync::Notify::new()),
        });
        let connect_file = async {
            tokio::try_join!(
                Association::client(Config {
                    net_conn: wire.clone(),
                    max_receive_buffer_size: 0,
                    max_message_size: 0,
                    name: "paced-file".into(),
                }),
                Association::server(Config {
                    net_conn: Arc::new(right),
                    max_receive_buffer_size: 0,
                    max_message_size: 0,
                    name: "paced-file-remote".into(),
                }),
            )
        };
        let (file, file_remote) = tokio::time::timeout(Duration::from_secs(5), connect_file)
            .await
            .map_err(|_| Error::Other("file pipe handshake stalled".into()))??;
        let (left, right) = pipe();
        let connect_default = async {
            tokio::try_join!(
                Association::client(Config {
                    net_conn: Arc::new(left),
                    max_receive_buffer_size: 0,
                    max_message_size: 0,
                    name: "unpaced-control".into(),
                }),
                Association::server(Config {
                    net_conn: Arc::new(right),
                    max_receive_buffer_size: 0,
                    max_message_size: 0,
                    name: "unpaced-control-remote".into(),
                }),
            )
        };
        let (control, control_remote) =
            tokio::time::timeout(Duration::from_secs(5), connect_default)
                .await
                .map_err(|_| Error::Other("default pipe handshake stalled".into()))??;
        let file_tx = file
            .open_stream(17, PayloadProtocolIdentifier::Binary)
            .await?;
        let file_rx = file_remote
            .open_stream(17, PayloadProtocolIdentifier::Binary)
            .await?;
        let control_tx = control
            .open_stream(18, PayloadProtocolIdentifier::Binary)
            .await?;
        let control_rx = control_remote
            .open_stream(18, PayloadProtocolIdentifier::Binary)
            .await?;
        let file_acks = file_pacing_ack_signal(&file_tx);
        let control_acks = file_pacing_ack_signal(&control_tx);
        let warmup = Bytes::from(vec![0x71; 4096]);
        for (tx, rx, acks) in [
            (&file_tx, &file_rx, &file_acks),
            (&control_tx, &control_rx, &control_acks),
        ] {
            tx.write_sctp(&warmup, PayloadProtocolIdentifier::Binary)
                .await?;
            read_pacing_config_message(rx, &warmup).await?;
            wait_file_pacing_ack(tx, acks, 0).await?;
        }
        data.lock().unwrap().clear();
        let baseline_t3 = file
            .association_internal
            .lock()
            .await
            .stats
            .get_num_t3timeouts();
        let baseline_fast = file
            .association_internal
            .lock()
            .await
            .stats
            .get_num_fast_retrans();
        assert_eq!(
            (baseline_t3, baseline_fast),
            (0, 0),
            "fixture warmup retransmitted on a loss-free pipe"
        );
        eprintln!("X14_REAL_PACING warmup_verified_bytes=8192 engine_not_yet_enabled=true");
        if let Err(error) = file
            .set_file_pacing(Some(FilePacingConfig {
                rate_bytes_per_second: RATE,
                burst_bytes: BURST,
            }))
            .await
        {
            panic!("file pacing is not enableable: {error}; wire budget/T3/isolation/close were NOT exercised");
        }

        file_tx.set_buffered_amount_low_threshold(1000);
        let first = Bytes::from(vec![0x51; 1000]);
        let second = Bytes::from(vec![0xa6; 1000]);
        file_tx
            .write_sctp(&first, PayloadProtocolIdentifier::Binary)
            .await?;
        file_tx
            .write_sctp(&second, PayloadProtocolIdentifier::Binary)
            .await?;
        read_pacing_config_message(&file_rx, &first).await?;
        wait_file_pacing_ack(&file_tx, &file_acks, 1000).await?;
        assert_file_pacing_wire_budget(&data.lock().unwrap(), RATE, BURST);
        assert_eq!(
            file_tx.buffered_amount(),
            1000,
            "fixture failed to observe acknowledged first DATA with another message still queued"
        );
        file_tx.set_buffered_amount_low_threshold(0);
        let read_second = {
            let rx = file_rx.clone();
            let second = second.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; second.len()];
                let (n, ppi) =
                    tokio::time::timeout(Duration::from_secs(10), rx.read_sctp(&mut buf))
                        .await
                        .map_err(|_| Error::Other("paced second DATA never arrived".into()))??;
                assert_eq!(ppi, PayloadProtocolIdentifier::Binary);
                assert_eq!(&buf[..n], second.as_ref());
                Ok::<(), Error>(())
            })
        };
        let control_message = Bytes::from(vec![0x24; 4096]);
        control_tx
            .write_sctp(&control_message, PayloadProtocolIdentifier::Binary)
            .await?;
        let default_completed = async {
            read_pacing_config_message(&control_rx, &control_message).await?;
            wait_file_pacing_ack(&control_tx, &control_acks, 0)
                .await
                .map_err(|e| Error::Other(format!("independent default association ACK: {e}")))?;
            Ok::<_, Error>(std::time::Instant::now())
        };
        // This is an intentional real elapsed window beyond initial T3=3s,
        // not a guessed IO-completion delay. Other IO proceeds concurrently.
        let (default_completed, _) = tokio::join!(
            default_completed,
            tokio::time::sleep(Duration::from_secs(4))
        );
        let default_completed = default_completed?;
        assert_eq!(
            file.association_internal
                .lock()
                .await
                .stats
                .get_num_t3timeouts(),
            baseline_t3,
            "queued, unsent DATA caused a false T3 timeout"
        );
        read_second.await.unwrap()?;
        wait_file_pacing_ack(&file_tx, &file_acks, 0)
            .await
            .map_err(|e| Error::Other(format!("second delivered paced DATA ACK: {e}")))?;
        {
            let events = data.lock().unwrap();
            assert_file_pacing_wire_budget(&events, RATE, BURST);
            assert_eq!(events.len(), 2, "loss-free file DATA was retransmitted");
            let unique: std::collections::HashSet<_> =
                events.iter().flat_map(|e| e.tsns.iter().copied()).collect();
            assert_eq!(unique.len(), 2);
            assert!(
                default_completed < events[1].started,
                "default association did not finish while the file association waited for budget"
            );
        }
        assert_eq!(
            file.association_internal
                .lock()
                .await
                .stats
                .get_num_t3timeouts(),
            baseline_t3
        );
        assert_eq!(
            file.association_internal
                .lock()
                .await
                .stats
                .get_num_fast_retrans(),
            baseline_fast
        );
        file_tx
            .write_sctp(
                &Bytes::from(vec![0x33; 1000]),
                PayloadProtocolIdentifier::Binary,
            )
            .await?;
        // A real control round trip is the scheduling checkpoint; no paused clock
        // or yield-count assumption is used to settle the queued file write.
        control_tx
            .write_sctp(&control_message, PayloadProtocolIdentifier::Binary)
            .await?;
        read_pacing_config_message(&control_rx, &control_message).await?;
        wait_file_pacing_ack(&control_tx, &control_acks, 0).await?;
        assert_eq!(
            data.lock().unwrap().len(),
            2,
            "third file DATA escaped its budget"
        );
        assert!(file_tx.buffered_amount() > 0);
        let writer = Arc::downgrade(&wire);
        let close = async move {
            file.close().await?;
            drop(file);
            drop(file_tx);
            drop(file_rx);
            drop(wire);
            loop {
                let notified = dropped.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if writer.upgrade().is_none() {
                    break;
                }
                notified.await;
            }
            Ok::<(), Error>(())
        };
        tokio::time::timeout(Duration::from_secs(2), close)
            .await
            .map_err(|_| {
                Error::Other("close retained the writer until a pacing deadline".into())
            })??;
        assert_eq!(
            data.lock().unwrap().len(),
            2,
            "closed writer sent queued DATA"
        );
        file_remote.close().await?;
        control.close().await?;
        control_remote.close().await?;
        eprintln!("X14_REAL_PACING wire_budget_verified=true default_io=true t3_delta=0 retransmissions=0 close_released=true");
        Ok::<(), Error>(())
    };
    tokio::time::timeout(Duration::from_secs(15), scenario)
        .await
        .map_err(|_| {
            Error::Other("real-clock pacing contract exceeded its 15-second safety bound".into())
        })?
}

/// One genuine DATA loss with pacing explicitly enabled. This exercises T3
/// retransmission and the final ACK on a real pipe, not complete cwnd/rwnd,
/// fairness or throughput behavior. The discarded encoded attempt is charged
/// alongside its retransmission; control packets are never discarded.
#[tokio::test]
async fn test_file_pacing_real_pipe_lost_data_retransmits_within_budget() -> Result<()> {
    let scenario = async {
        const RATE: u64 = 256;
        const BURST: usize = 1280;
        let data = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (left, right) = pipe();
        let wire = Arc::new(FilePacingWire {
            inner: Arc::new(left),
            data: data.clone(),
            dropped: Arc::new(tokio::sync::Notify::new()),
            drop_next_data: AtomicBool::new(false),
            data_ready: Arc::new(tokio::sync::Notify::new()),
        });
        let (file, remote) = tokio::try_join!(
            Association::client(Config {
                net_conn: wire.clone(),
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: "paced-loss-client".into(),
            }),
            Association::server(Config {
                net_conn: Arc::new(right),
                max_receive_buffer_size: 0,
                max_message_size: 0,
                name: "paced-loss-remote".into(),
            }),
        )?;
        let tx = file
            .open_stream(23, PayloadProtocolIdentifier::Binary)
            .await?;
        let rx = remote
            .open_stream(23, PayloadProtocolIdentifier::Binary)
            .await?;
        let acks = file_pacing_ack_signal(&tx);
        let warmup = Bytes::from(vec![0x73; 64]);
        tx.write_sctp(&warmup, PayloadProtocolIdentifier::Binary)
            .await?;
        read_pacing_config_message(&rx, &warmup).await?;
        wait_file_pacing_ack(&tx, &acks, 0).await?;
        let (baseline_t3, baseline_fast, baseline_sacks) = {
            let ai = file.association_internal.lock().await;
            (
                ai.stats.get_num_t3timeouts(),
                ai.stats.get_num_fast_retrans(),
                ai.stats.get_num_sacks(),
            )
        };
        assert_eq!(
            (baseline_t3, baseline_fast),
            (0, 0),
            "warmup unexpectedly retransmitted"
        );
        data.lock().unwrap().clear();
        file.set_file_pacing(Some(FilePacingConfig {
            rate_bytes_per_second: RATE,
            burst_bytes: BURST,
        }))
        .await?;
        wire.drop_next_data.store(true, Ordering::SeqCst);
        let message = Bytes::from(
            (0..1000)
                .map(|i| (i % 251) as u8 ^ 0xa6)
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            tx.write_sctp(&message, PayloadProtocolIdentifier::Binary)
                .await?,
            message.len()
        );
        read_pacing_config_message(&rx, &message).await?;

        // Publish the real send-completion records before checking their
        // byte budget; receiver delivery can race Conn::send's return.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let recorded = wire.data_ready.notified();
                tokio::pin!(recorded);
                recorded.as_mut().enable();
                if data.lock().unwrap().len() >= 2 {
                    break;
                }
                recorded.await;
            }
        })
        .await
        .map_err(|_| Error::Other("DATA retry wire observation was not published".into()))?;
        {
            let events = data.lock().unwrap();
            assert_eq!(
                events.len(),
                2,
                "expected one lost DATA attempt and one retry"
            );
            assert!(events[0].dropped_by_fixture, "DATA loss was not injected");
            assert!(
                !events[1].dropped_by_fixture,
                "retry must reach the real pipe"
            );
            assert_eq!(
                events[0].tsns.len(),
                1,
                "the loss scenario must contain one DATA chunk"
            );
            assert_eq!(
                events[0].tsns, events[1].tsns,
                "retry must retransmit the lost TSN"
            );
            assert_eq!(events[0].bytes, events[1].bytes, "retry wire size changed");
            assert_file_pacing_wire_budget(&events, RATE, BURST);
        }
        // Wire-byte accounting above and final protocol acknowledgement are
        // separate oracles. Delivery alone cannot satisfy this ACK check.
        wait_file_pacing_ack(&tx, &acks, 0).await?;
        {
            let ai = file.association_internal.lock().await;
            assert!(
                ai.stats.get_num_t3timeouts() > baseline_t3,
                "T3 path was not exercised"
            );
            assert_eq!(
                ai.stats.get_num_fast_retrans(),
                baseline_fast,
                "single-TSN loss should use T3"
            );
            assert!(
                ai.stats.get_num_sacks() > baseline_sacks,
                "final SACK was not processed"
            );
        }
        assert_eq!(
            tx.buffered_amount(),
            0,
            "delivered DATA must be acknowledged"
        );
        assert_eq!(file.get_state(), AssociationState::Established);
        file.close().await?;
        remote.close().await?;
        eprintln!("X14_PACED_LOSS dropped_data=1 same_tsn_retry=true full_delivery=true final_ack=true wire_budget=true t3_exercised=true");
        Ok::<(), Error>(())
    };
    tokio::time::timeout(Duration::from_secs(10), scenario)
        .await
        .map_err(|_| Error::Other("paced DATA loss regression exceeded safety bound".into()))?
}
