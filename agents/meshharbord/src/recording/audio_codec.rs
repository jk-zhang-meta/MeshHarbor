// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P4 — a recording's audio encoder: AAC where this build's FFmpeg
//! carries its encoder, Opus everywhere else.
//!
//! - **AAC is what every player opens.** Opus-in-MP4 plays in browsers and
//!   VLC but not in QuickTime, nor in Movies & TV without an extension;
//!   AAC-LC plays wherever a recording is likely to be opened. It is FFmpeg's
//!   native `aac` encoder (LGPL, vendored from P4), so a build without FFmpeg
//!   (Linux arm64) or with an FFmpeg that lacks it keeps Opus — picked at
//!   runtime, never a refusal.
//! - **The encoder takes any number of samples.** The mixer makes 20 ms
//!   (960-sample) frames on the recorder's clock and AAC codes 1024-sample
//!   ones: samples wait here until a whole frame of the codec's size is in,
//!   and the last one is padded with silence.
//! - **AAC's priming is paid at the source, never signalled.** A decoder puts
//!   out [`AudioEncoder::unsignalled_delay`] samples (1024 for FFmpeg's
//!   encoder) BEFORE input sample 0, and players disagree about the edit list
//!   that would tell them to drop those. So a caller feeds the encoder from
//!   that many samples PAST time zero: decoded sample k is time k in every
//!   player, edit list or not, and what it costs is the first ~21 ms of
//!   sound. Opus says its own `pre_skip` in `dOps`, which every Opus decoder
//!   honours, so its delay here is 0.

use anyhow::Result;
#[cfg(feature = "ffmpeg-encoder")]
use anyhow::{Context, anyhow, bail};

use super::audio::{CHANNELS, RATE, RecordingOpus};
use super::mp4;

/// Where each packet goes: its bytes and its duration in 48 kHz samples.
pub type PacketSink<'a> = dyn FnMut(Vec<u8>, u32) -> Result<()> + 'a;

/// AAC-LC bitrate for a recording's stereo track. FFmpeg's native encoder
/// needs more than Opus's 128 kb/s for the same transparency.
#[cfg(feature = "ffmpeg-encoder")]
const AAC_BPS: usize = 192_000;

/// The recording's audio encoder, one codec for the whole file.
pub struct AudioEncoder {
    codec: Codec,
    /// Samples per channel in one packet: 960 (Opus, 20 ms) or 1024 (AAC).
    frame: usize,
    /// Interleaved stereo still short of a whole frame.
    pending: Vec<i16>,
}

enum Codec {
    Opus(RecordingOpus),
    #[cfg(feature = "ffmpeg-encoder")]
    Aac(Aac),
}

impl AudioEncoder {
    /// AAC when this build's FFmpeg has its encoder and it opens; Opus
    /// otherwise. Why AAC was passed over is said in the log, never an error.
    pub fn best() -> Result<Self> {
        #[cfg(feature = "ffmpeg-encoder")]
        match Self::aac() {
            Ok(e) => return Ok(e),
            Err(e) => {
                tracing::info!(error = %format!("{e:#}"), "recording: AAC unavailable — recording audio as Opus")
            }
        }
        Self::opus()
    }

    /// Opus, 20 ms frames — every build with `audio` has it.
    pub fn opus() -> Result<Self> {
        Ok(Self {
            codec: Codec::Opus(RecordingOpus::new()?),
            frame: super::audio::FRAME,
            pending: Vec::new(),
        })
    }

    /// AAC-LC through FFmpeg, or why not.
    #[cfg(feature = "ffmpeg-encoder")]
    pub fn aac() -> Result<Self> {
        let aac = Aac::open()?;
        Ok(Self {
            frame: aac.frame,
            codec: Codec::Aac(aac),
            pending: Vec::new(),
        })
    }

    /// The sidecar's name for it: `aac` or `opus`.
    pub fn name(&self) -> &'static str {
        match &self.codec {
            Codec::Opus(_) => "opus",
            #[cfg(feature = "ffmpeg-encoder")]
            Codec::Aac(_) => "aac",
        }
    }

    /// What the MP4 track's sample entry says.
    pub fn track_codec(&self) -> mp4::AudioCodec {
        match &self.codec {
            Codec::Opus(o) => mp4::AudioCodec::Opus {
                pre_skip: o.pre_skip,
            },
            #[cfg(feature = "ffmpeg-encoder")]
            Codec::Aac(a) => mp4::AudioCodec::Aac {
                asc: a.asc.clone(),
                bitrate: AAC_BPS as u32,
            },
        }
    }

    /// The MP4 audio track this encoder writes.
    pub fn track(&self) -> mp4::AudioTrack {
        mp4::AudioTrack {
            sample_rate: RATE,
            channels: CHANNELS as u8,
            codec: self.track_codec(),
        }
    }

    /// Samples per channel in one packet.
    pub fn frame_samples(&self) -> usize {
        self.frame
    }

    /// Samples a decoder puts out before input sample 0 that nothing in the
    /// file tells a player to drop: the caller starts feeding this far past
    /// time zero (see the module docs).
    pub fn unsignalled_delay(&self) -> u64 {
        match &self.codec {
            Codec::Opus(_) => 0,
            #[cfg(feature = "ffmpeg-encoder")]
            Codec::Aac(a) => a.delay,
        }
    }

    /// Take interleaved 48 kHz stereo; every whole frame is encoded and its
    /// packets handed to `sink`.
    pub fn push(&mut self, pcm: &[i16], sink: &mut PacketSink<'_>) -> Result<()> {
        self.pending.extend_from_slice(pcm);
        let n = self.frame * CHANNELS;
        let mut at = 0;
        while self.pending.len() - at >= n {
            let frame = &self.pending[at..at + n];
            match &mut self.codec {
                Codec::Opus(o) => sink(o.encode(frame)?, self.frame as u32)?,
                #[cfg(feature = "ffmpeg-encoder")]
                Codec::Aac(a) => a.encode(frame, sink)?,
            }
            at += n;
        }
        self.pending.drain(..at);
        Ok(())
    }

    /// The last partial frame, padded with silence, and whatever the codec
    /// still holds. The encoder takes nothing after this.
    pub fn finish(&mut self, sink: &mut PacketSink<'_>) -> Result<()> {
        if !self.pending.is_empty() {
            let n = self.frame * CHANNELS;
            let short = n - self.pending.len() % n;
            if short < n {
                let silence = vec![0i16; short];
                self.push(&silence, sink)?;
            }
        }
        match &mut self.codec {
            Codec::Opus(_) => Ok(()),
            #[cfg(feature = "ffmpeg-encoder")]
            Codec::Aac(a) => a.flush(sink),
        }
    }
}

/// FFmpeg's native AAC-LC encoder: 48 kHz stereo, planar float in.
#[cfg(feature = "ffmpeg-encoder")]
struct Aac {
    enc: ffmpeg_next::encoder::Audio,
    /// Input samples sent so far: the next frame's pts (time base 1/48000).
    pts: i64,
    /// The AudioSpecificConfig for the `esds`.
    asc: Vec<u8>,
    /// Decoder output ahead of input sample 0 (`initial_padding`).
    delay: u64,
    frame: usize,
}

#[cfg(feature = "ffmpeg-encoder")]
impl Aac {
    fn open() -> Result<Self> {
        use ffmpeg_next::format::{Sample, sample::Type};
        use ffmpeg_next::{ChannelLayout, codec};
        ffmpeg_next::init().context("FFmpeg init")?;
        let codec = codec::encoder::find(codec::Id::AAC)
            .ok_or_else(|| anyhow!("this build's FFmpeg has no AAC encoder"))?;
        let mut enc = codec::Context::new_with_codec(codec)
            .encoder()
            .audio()
            .context("an AAC encoder context")?;
        enc.set_rate(RATE as i32);
        enc.set_channel_layout(ChannelLayout::STEREO);
        enc.set_format(Sample::F32(Type::Planar));
        enc.set_bit_rate(AAC_BPS);
        enc.set_time_base((1, RATE as i32));
        // The AudioSpecificConfig belongs in the `esds`, not in-band.
        enc.set_flags(codec::Flags::GLOBAL_HEADER);
        let enc = enc.open_as(codec).context("open the AAC encoder")?;
        let frame = enc.frame_size() as usize;
        if frame == 0 {
            bail!("the AAC encoder reports no frame size");
        }
        // SAFETY: `enc` is an opened context this function owns; both fields
        // are plain data `avcodec_open2` set, and `extradata` holds
        // `extradata_size` bytes for as long as the context lives.
        let (delay, extradata) = unsafe {
            let ctx = &*enc.as_ptr();
            let extradata = if ctx.extradata.is_null() || ctx.extradata_size <= 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(ctx.extradata, ctx.extradata_size as usize).to_vec()
            };
            (u64::try_from(ctx.initial_padding).unwrap_or(0), extradata)
        };
        let asc = if extradata.len() >= 2 {
            extradata
        } else {
            mp4::aac_lc_asc(RATE, CHANNELS as u8)
                .ok_or_else(|| anyhow!("no AudioSpecificConfig for {RATE} Hz"))?
        };
        Ok(Self {
            enc,
            pts: 0,
            asc,
            delay,
            frame,
        })
    }

    /// One whole frame of interleaved stereo.
    fn encode(&mut self, pcm: &[i16], sink: &mut PacketSink<'_>) -> Result<()> {
        use ffmpeg_next::ChannelLayout;
        use ffmpeg_next::format::{Sample, sample::Type};
        let n = pcm.len() / CHANNELS;
        // A fresh frame each time: the encoder may still hold a reference to
        // the last one's buffer, which must not be written under it.
        let mut f =
            ffmpeg_next::frame::Audio::new(Sample::F32(Type::Planar), n, ChannelLayout::STEREO);
        f.set_rate(RATE);
        for c in 0..CHANNELS {
            for (i, s) in f.plane_mut::<f32>(c).iter_mut().enumerate().take(n) {
                *s = f32::from(pcm[i * CHANNELS + c]) / 32_768.0;
            }
        }
        f.set_pts(Some(self.pts));
        self.pts += n as i64;
        self.enc.send_frame(&f).context("AAC: send a frame")?;
        self.drain(sink)
    }

    fn flush(&mut self, sink: &mut PacketSink<'_>) -> Result<()> {
        self.enc.send_eof().context("AAC: flush")?;
        self.drain(sink)
    }

    fn drain(&mut self, sink: &mut PacketSink<'_>) -> Result<()> {
        let mut packet = ffmpeg_next::Packet::empty();
        loop {
            match self.enc.receive_packet(&mut packet) {
                Ok(()) => {
                    let data = packet.data().unwrap_or(&[]).to_vec();
                    // The last packet may carry fewer real samples than a
                    // frame: its duration says so (the rest is padding).
                    let d = packet.duration();
                    let duration = if d > 0 {
                        d.min(self.frame as i64) as u32
                    } else {
                        self.frame as u32
                    };
                    if !data.is_empty() {
                        sink(data, duration)?;
                    }
                }
                Err(ffmpeg_next::Error::Other { errno }) if errno == ffmpeg_next::error::EAGAIN => {
                    return Ok(());
                }
                Err(ffmpeg_next::Error::Eof) => return Ok(()),
                Err(e) => bail!("AAC: {e}"),
            }
        }
    }
}

/// Whether the tests of this lane REQUIRE AAC (`ROOMLER_EXPECT_FFMPEG_AAC=1`):
/// set where the vendored FFmpeg carries the encoder, so a lane that quietly
/// fell back to Opus fails instead of passing on the wrong codec.
pub fn aac_expected() -> bool {
    std::env::var("ROOMLER_EXPECT_FFMPEG_AAC").is_ok_and(|v| v == "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(enc: &mut AudioEncoder, chunks: &[usize]) -> Vec<(Vec<u8>, u32)> {
        let mut out = Vec::new();
        for &n in chunks {
            let pcm = vec![0i16; n * CHANNELS];
            enc.push(&pcm, &mut |p, d| {
                out.push((p, d));
                Ok(())
            })
            .unwrap();
        }
        enc.finish(&mut |p, d| {
            out.push((p, d));
            Ok(())
        })
        .unwrap();
        out
    }

    /// Odd-sized pushes come out as whole 20 ms packets, and the tail is
    /// padded into one more — nothing is lost, nothing is invented.
    #[test]
    fn opus_takes_any_chunking_and_codes_whole_frames() {
        let mut enc = AudioEncoder::opus().unwrap();
        assert_eq!(enc.name(), "opus");
        assert_eq!(enc.frame_samples(), 960);
        assert_eq!(enc.unsignalled_delay(), 0, "dOps carries pre_skip");
        // 1000 + 7 + 3000 = 4007 samples = 4 whole frames + 167 → 5 packets.
        let packets = collect(&mut enc, &[1000, 7, 3000]);
        assert_eq!(packets.len(), 5);
        assert!(packets.iter().all(|(p, d)| !p.is_empty() && *d == 960));
        assert!(matches!(enc.track_codec(), mp4::AudioCodec::Opus { .. }));
    }

    #[test]
    fn a_whole_number_of_frames_is_not_padded() {
        let mut enc = AudioEncoder::opus().unwrap();
        assert_eq!(collect(&mut enc, &[960, 960, 960]).len(), 3);
    }

    /// Without FFmpeg, "the best encoder" is Opus — there is nothing else.
    #[cfg(not(feature = "ffmpeg-encoder"))]
    #[test]
    fn without_ffmpeg_the_best_is_opus() {
        assert_eq!(AudioEncoder::best().unwrap().name(), "opus");
    }

    /// The AAC encoder, where this lane's FFmpeg carries it: 1024-sample
    /// frames, the priming delay FFmpeg declares, the standard config, and
    /// `best()` choosing it. Where it is absent the test says so and passes —
    /// unless the lane declared it must be there (`aac_expected`).
    #[cfg(feature = "ffmpeg-encoder")]
    #[test]
    fn aac_codes_1024_sample_frames_with_its_declared_priming() {
        let mut enc = match AudioEncoder::aac() {
            Ok(e) => e,
            Err(e) => {
                assert!(
                    !aac_expected(),
                    "ROOMLER_EXPECT_FFMPEG_AAC=1 but AAC did not open: {e:#}"
                );
                eprintln!("skipped: this FFmpeg has no AAC encoder ({e:#})");
                return;
            }
        };
        assert_eq!(enc.name(), "aac");
        assert_eq!(enc.frame_samples(), 1024);
        assert_eq!(enc.unsignalled_delay(), 1024, "FFmpeg's initial_padding");
        let mp4::AudioCodec::Aac { asc, bitrate } = enc.track_codec() else {
            panic!("an AAC encoder describes an AAC track");
        };
        assert_eq!(bitrate, AAC_BPS as u32);
        // AAC-LC, 48 kHz, stereo: the standard two bytes first. FFmpeg's own
        // config goes on (`56 E5 00`: the explicit "no SBR" extension), and it
        // is the encoder's config that is written, never a guess.
        assert_eq!(asc.get(..2), Some(&[0x11, 0x90][..]), "{asc:02x?}");
        // One second: 46.875 frames of input → 47 frames with the padded
        // tail, plus the priming frame the flush releases.
        let packets = collect(&mut enc, &[48_000]);
        assert!(
            (47..=49).contains(&packets.len()),
            "{} packets for one second",
            packets.len()
        );
        assert!(packets.iter().all(|(p, d)| !p.is_empty() && *d <= 1024));
        assert_eq!(AudioEncoder::best().unwrap().name(), "aac");
    }
}
