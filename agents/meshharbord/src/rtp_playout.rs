// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-98 C6 — tell the browser's jitter buffer to render the RTP video
//! track as soon as it can: the `playout-delay` header extension with
//! min = max = 0.
//!
//! Chrome's `<video>` holds frames in a jitter buffer, whatever
//! `jitterBufferTarget` the page asks for (the open Known Issue). A sender
//! that puts `playout-delay` 0/0 on its packets moves Chrome to its
//! low-latency path, the one game-streaming services use. Only the RTP
//! fallback track goes through that buffer: data-channel sessions decode in
//! a worker and never meet it.
//!
//! On by default since FR-98 P5's field A/B (2026-10-16): on a vmtest guest,
//! with OpenH264 on the track, Chrome's buffer went from an average of 193 ms
//! (and growing) to 0.1 ms, and L4 input to photon from p50 78–362 ms to
//! 35–40 ms. `ROOMLERD_RTP_PLAYOUT_DELAY_ZERO=0` turns it off, read once per
//! session. Off, the extension is not even registered, so the answer SDP and
//! every packet stay byte-identical to the agents before it. On, it is
//! registered on the media engine, negotiated only if the browser offers it
//! (Chrome does), and written on every video packet; a browser that does
//! not offer it never sees it.

use anyhow::{Context, Result};
use webrtc::api::media_engine::MediaEngine;
use webrtc::rtp::extension::HeaderExtension;
use webrtc::rtp::extension::playout_delay_extension::PlayoutDelayExtension;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpHeaderExtensionCapability, RTPCodecType};

/// The extension's URI, as browsers offer it.
pub const URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay";

/// Is the switch on? It defaults ON: only an explicit off (`0`, `false`,
/// `no`, `off`, the spellings `ROOMLERD_HW_AUTO` reads) turns it off. An
/// unset, empty or unrecognised value keeps the default, so a typo cannot
/// take a host back to the buffered path.
pub fn parse(raw: Option<&str>) -> bool {
    !matches!(
        raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("0" | "false" | "no" | "off")
    )
}

/// Does this session send `playout-delay` 0/0? Read at session open: once
/// where the media engine is built, once where the pump starts.
pub fn enabled() -> bool {
    #[cfg(feature = "synthetic-frame-source")]
    if let Some(forced) = test_override() {
        return forced;
    }
    parse(tunnel_core::env::node_env("RTP_PLAYOUT_DELAY_ZERO").as_deref())
}

/// Register the extension for video, so an answer can negotiate it.
pub fn register(engine: &mut MediaEngine) -> Result<()> {
    engine
        .register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: URI.to_owned(),
            },
            RTPCodecType::Video,
            None,
        )
        .context("register the playout-delay header extension")
}

/// The extension to put on every video packet: render as soon as decoded.
pub fn zero() -> HeaderExtension {
    HeaderExtension::PlayoutDelay(PlayoutDelayExtension {
        min_delay: 0,
        max_delay: 0,
    })
}

/// FR-16 L0's cells switch this per session in one test process, where the
/// environment cannot change under running threads. 0 = read the env,
/// 1 = forced off, 2 = forced on. Compiled only into the test-only
/// `synthetic-frame-source` build.
#[cfg(feature = "synthetic-frame-source")]
static TEST_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(feature = "synthetic-frame-source")]
pub fn set_test_override(on: Option<bool>) {
    let v = match on {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    TEST_OVERRIDE.store(v, std::sync::atomic::Ordering::Release);
}

#[cfg(feature = "synthetic-frame-source")]
fn test_override() -> Option<bool> {
    match TEST_OVERRIDE.load(std::sync::atomic::Ordering::Acquire) {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_explicit_off_turns_it_off() {
        for off in ["0", "false", "NO", " off "] {
            assert!(!parse(Some(off)), "{off:?}");
        }
        // Unset, empty, on, or a typo: the default, which is on.
        for on in [
            None,
            Some(""),
            Some("1"),
            Some("true"),
            Some("2"),
            Some("of"),
        ] {
            assert!(parse(on), "{on:?}");
        }
    }

    #[test]
    fn the_extension_is_zero_zero_on_the_right_uri() {
        let ext = zero();
        assert_eq!(ext.uri(), URI);
        match ext {
            HeaderExtension::PlayoutDelay(p) => {
                assert_eq!((p.min_delay, p.max_delay), (0, 0));
            }
            other => panic!("not a playout-delay extension: {:?}", other.uri()),
        }
    }

    #[test]
    fn registering_it_puts_the_uri_on_the_engine() {
        let mut engine = MediaEngine::default();
        register(&mut engine).expect("register");
    }
}
