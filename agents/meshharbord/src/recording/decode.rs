// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P4 — the decoder an export reads a recording's video with.
//!
//! - **openh264 reads what the software encoder writes** (Constrained
//!   Baseline, profile 66), on every build — Linux arm64 included, which has
//!   no FFmpeg at all.
//! - **FFmpeg's `h264` reads everything else** — the hardware encoders' High
//!   profile (100) and 4:4:4 (244) — where the build links an FFmpeg that
//!   carries it (the `-h264dec-aac` vendored assets, P4a). Whether it does is
//!   a property of the linked library, not of the code, so it is asked at
//!   runtime ([`can_decode`]); a recording nothing here can read is refused
//!   `decoder_unavailable` by name, never exported garbled.
//! - **One picture per access unit, in order.** The recorder writes no
//!   B-frames, so decode order is display order: FFmpeg runs with
//!   `LOW_DELAY` and slice threads only (frame threads hold pictures back).
//!   Every packet carries its sample index as its pts, and a picture that
//!   comes back with another index is an error, never a frame shown in the
//!   wrong place.
//! - **YUV → BGRA with the matrix the stream says** (BT.601 unless it says
//!   BT.709; limited unless it says full) — the inverse of what the recorder's
//!   FFmpeg path did going in (`dcv-color-primitives`, `ColorSpace::Bt601`).

use crate::capture::{Damage, Frame, PixelFormat};

/// H.264 `profile_idc` 66: what openh264's decoder reads.
pub const BASELINE: u8 = 66;

/// Whether this build can decode a recording whose video is H.264 profile
/// `profile`.
pub fn can_decode(profile: u8) -> bool {
    profile == BASELINE || h264_decoder_available()
}

/// Whether the linked FFmpeg carries its `h264` decoder (always `false`
/// without `ffmpeg-encoder`).
pub fn h264_decoder_available() -> bool {
    #[cfg(feature = "ffmpeg-encoder")]
    {
        ffmpeg_next::init().is_ok()
            && ffmpeg_next::decoder::find(ffmpeg_next::codec::Id::H264).is_some()
    }
    #[cfg(not(feature = "ffmpeg-encoder"))]
    {
        false
    }
}

/// Whether the tests of this lane REQUIRE FFmpeg's H.264 decoder
/// (`ROOMLER_EXPECT_FFMPEG_H264_DECODER=1`): set where the vendored FFmpeg
/// carries it, so a lane that lost it fails instead of passing on the
/// refusal path.
pub fn h264_decoder_expected() -> bool {
    std::env::var("ROOMLER_EXPECT_FFMPEG_H264_DECODER").is_ok_and(|v| v == "1")
}

/// An export's video decoder.
pub enum VideoDecoder {
    Openh264(openh264::decoder::Decoder),
    #[cfg(feature = "ffmpeg-encoder")]
    Ffmpeg(ffmpeg::H264),
}

impl VideoDecoder {
    /// The decoder for H.264 profile `profile`, or why there is none.
    pub fn for_profile(profile: u8) -> Result<Self, String> {
        if profile == BASELINE {
            return openh264::decoder::Decoder::new()
                .map(Self::Openh264)
                .map_err(|e| format!("openh264 decoder: {e}"));
        }
        #[cfg(feature = "ffmpeg-encoder")]
        {
            ffmpeg::H264::open().map(Self::Ffmpeg)
        }
        #[cfg(not(feature = "ffmpeg-encoder"))]
        {
            Err("this build of roomlerd has no FFmpeg".into())
        }
    }

    /// `openh264` or `ffmpeg-h264`, for logs and the tests.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Openh264(_) => "openh264",
            #[cfg(feature = "ffmpeg-encoder")]
            Self::Ffmpeg(_) => "ffmpeg-h264",
        }
    }

    /// Decode access unit `index` (Annex-B, parameter sets in front on a
    /// keyframe). With `want`, its picture as BGRA; a wanted access unit
    /// that gives no picture is an error.
    pub fn decode(&mut self, au: &[u8], index: usize, want: bool) -> Result<Option<Frame>, String> {
        match self {
            Self::Openh264(dec) => {
                let pic = dec.decode(au).map_err(|e| format!("sample {index}: {e}"))?;
                if !want {
                    return Ok(None);
                }
                let pic = pic.ok_or_else(|| format!("sample {index} produced no picture"))?;
                Ok(Some(openh264_bgra(&pic)))
            }
            #[cfg(feature = "ffmpeg-encoder")]
            Self::Ffmpeg(dec) => dec.decode(au, index, want),
        }
    }
}

/// An openh264 picture as the BGRA frame every recording encoder takes.
fn openh264_bgra(pic: &openh264::decoder::DecodedYUV<'_>) -> Frame {
    use openh264::formats::YUVSource;
    let (w, h) = pic.dimensions();
    let mut data = vec![0u8; w * h * 4];
    pic.write_rgba8(&mut data);
    for px in data.chunks_exact_mut(4) {
        px.swap(0, 2);
    }
    bgra_frame(w as u32, h as u32, data)
}

fn bgra_frame(width: u32, height: u32, data: Vec<u8>) -> Frame {
    Frame {
        width,
        height,
        stride: width * 4,
        pixel_format: PixelFormat::Bgra,
        data,
        monotonic_us: 0,
        monitor: 0,
        damage: Damage::Unknown,
        source: None,
    }
}

#[cfg(feature = "ffmpeg-encoder")]
pub mod ffmpeg {
    //! FFmpeg's software `h264` decoder.

    use ffmpeg_next::codec::{self, threading};
    use ffmpeg_next::format::Pixel;
    use ffmpeg_next::util::color;

    /// An opened `h264` decoder and the frame it decodes into.
    pub struct H264 {
        dec: ffmpeg_next::decoder::Video,
        frame: ffmpeg_next::frame::Video,
    }

    impl H264 {
        pub fn open() -> Result<Self, String> {
            ffmpeg_next::init().map_err(|e| format!("FFmpeg init: {e}"))?;
            let codec = ffmpeg_next::decoder::find(codec::Id::H264)
                .ok_or("this build's FFmpeg has no H.264 decoder")?;
            let mut ctx = codec::Context::new_with_codec(codec);
            // One picture per access unit, as it arrives: the recorder writes
            // no B-frames, and frame threads would hold pictures back.
            ctx.set_threading(threading::Config::kind(threading::Type::Slice));
            ctx.set_flags(codec::Flags::LOW_DELAY);
            let dec = ctx
                .decoder()
                .video()
                .map_err(|e| format!("open the H.264 decoder: {e}"))?;
            Ok(Self {
                dec,
                frame: ffmpeg_next::frame::Video::empty(),
            })
        }

        pub fn decode(
            &mut self,
            au: &[u8],
            index: usize,
            want: bool,
        ) -> Result<Option<super::Frame>, String> {
            let mut packet = ffmpeg_next::Packet::copy(au);
            packet.set_pts(Some(index as i64));
            packet.set_dts(Some(index as i64));
            self.dec
                .send_packet(&packet)
                .map_err(|e| format!("sample {index}: {e}"))?;
            let mut shown = None;
            loop {
                match self.dec.receive_frame(&mut self.frame) {
                    Ok(()) => {
                        let at = self.frame.pts();
                        if at != Some(index as i64) {
                            return Err(format!(
                                "sample {index}: the decoder gave back the picture of {at:?}"
                            ));
                        }
                        if want {
                            shown = Some(
                                to_bgra(&self.frame).map_err(|e| format!("sample {index}: {e}"))?,
                            );
                        }
                    }
                    Err(ffmpeg_next::Error::Other { errno })
                        if errno == ffmpeg_next::error::EAGAIN =>
                    {
                        break;
                    }
                    Err(ffmpeg_next::Error::Eof) => break,
                    Err(e) => return Err(format!("sample {index}: {e}")),
                }
            }
            if want && shown.is_none() {
                return Err(format!("sample {index} produced no picture"));
            }
            Ok(shown)
        }
    }

    /// A decoded picture as BGRA, with the matrix and range it says it has.
    fn to_bgra(f: &ffmpeg_next::frame::Video) -> Result<super::Frame, String> {
        use dcv_color_primitives::{ColorSpace, ImageFormat, PixelFormat, convert_image};
        let (pixel_format, full) = match f.format() {
            Pixel::YUV420P => (PixelFormat::I420, false),
            Pixel::YUVJ420P => (PixelFormat::I420, true),
            Pixel::YUV444P => (PixelFormat::I444, false),
            Pixel::YUVJ444P => (PixelFormat::I444, true),
            other => return Err(format!("the decoder gave {other:?} pictures")),
        };
        let full = full || f.color_range() == color::Range::JPEG;
        let bt709 = f.color_space() == color::Space::BT709;
        let color_space = match (bt709, full) {
            (false, false) => ColorSpace::Bt601,
            (false, true) => ColorSpace::Bt601FR,
            (true, false) => ColorSpace::Bt709,
            (true, true) => ColorSpace::Bt709FR,
        };
        let (w, h) = (f.width(), f.height());
        let src = ImageFormat {
            pixel_format,
            color_space,
            num_planes: 3,
        };
        let dst = ImageFormat {
            pixel_format: PixelFormat::Bgra,
            color_space: ColorSpace::Rgb,
            num_planes: 1,
        };
        let mut data = vec![0u8; w as usize * h as usize * 4];
        convert_image(
            w,
            h,
            &src,
            Some(&[f.stride(0), f.stride(1), f.stride(2)]),
            &[f.data(0), f.data(1), f.data(2)],
            &dst,
            Some(&[w as usize * 4]),
            &mut [&mut data[..]],
        )
        .map_err(|e| format!("YUV → BGRA: {e:?}"))?;
        Ok(super::bgra_frame(w, h, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_always_readable() {
        assert!(can_decode(BASELINE));
        assert_eq!(
            VideoDecoder::for_profile(BASELINE).unwrap().name(),
            "openh264"
        );
    }

    /// High profile is readable exactly where FFmpeg's `h264` is linked in —
    /// and a lane that declares it (`h264_decoder_expected`) must have it.
    #[test]
    fn high_profile_needs_ffmpegs_decoder() {
        let available = h264_decoder_available();
        assert!(
            available || !h264_decoder_expected(),
            "ROOMLER_EXPECT_FFMPEG_H264_DECODER=1 but the linked FFmpeg has no H.264 decoder"
        );
        assert_eq!(can_decode(100), available);
        match VideoDecoder::for_profile(100) {
            Ok(d) => {
                assert!(available);
                assert_eq!(d.name(), "ffmpeg-h264");
            }
            Err(e) => assert!(!available, "{e}"),
        }
    }
}
