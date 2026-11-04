// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P5a — the export engine: a recording and its edit list in, a new
//! file out, beside it. The recording itself is never written.
//!
//! ```text
//! demux (ProgressiveFile) → decode (openh264 | FFmpeg h264) → pick the frame each output
//! tick shows (edit::Plan) → encode (the recording profile) → fragmented MP4
//! staged in .roomler-partial → finalize (moov-first)
//! ```
//!
//! - **The sound (P5b)** is [`super::export_audio`]'s: the recording's own
//!   audio through the same plan (muted under a speed-up) and music under it,
//!   one track interleaved with the video — AAC where this build's FFmpeg
//!   has the encoder, Opus otherwise (P4). A build without `audio`
//!   carries none and says so (`not_carried`), and refuses music
//!   (`audio_unavailable`): a caller never presents a silent file as complete.
//! - **openh264 decodes what the software encoder writes** (Constrained
//!   Baseline); **FFmpeg's `h264` decodes a hardware encoder's High profile**
//!   where the build's FFmpeg carries it (FR-85 P4, [`super::decode`]).
//!   Anything this build cannot read is refused by name
//!   (`decoder_unavailable`): never a garbled export.
//! - **It decodes forward**, jumping to the keyframe before the next frame
//!   it needs when that keyframe is ahead. A cut costs at most one GOP (2 s) of
//!   decoding, never the whole stretch it removes. H.264 needs every frame
//!   since the last keyframe, so a speed-up still decodes every source frame
//!   it passes over; only the frames it SHOWS are converted and encoded.
//! - The output's partial holds the same liveness lock as a recording's, so
//!   a recorder starting beside a running export never reconciles it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::annexb::length_prefixed_to_annexb;
use super::decode::VideoDecoder;
use super::edit::{EditList, Invalid, Plan};
use super::folder::{PARTIAL_DIR, PARTIAL_SUFFIX};
use super::mp4::{self, ColorInfo, FragmentedWriter, ProgressiveFile, VideoTrack};
use super::pacer::{Cadence, TickFifo};
use super::recorder::{EncoderFactory, PartialLock, group_access_units};
use crate::capture::Frame;

/// A finished export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    pub path: PathBuf,
    pub frames: u64,
    pub duration_ms: u64,
    pub bytes: u64,
    pub encoder: String,
    /// `none`, `original`, `music`, `original_and_music`, or `not_carried`
    /// (the recording had audio and this build cannot encode any).
    pub audio: &'static str,
}

/// Why an export did not happen, as a closed code and a sentence.
#[derive(Debug)]
pub enum ExportError {
    /// The recording cannot be read as one.
    Source(String),
    /// Its video needs a decoder this build does not carry.
    DecoderUnavailable {
        profile: u8,
    },
    /// The edit list is not one this build can follow.
    EditList(Invalid),
    Encoder(String),
    Decode(String),
    Write(String),
    Cancelled,
    /// The music file does not open or decode.
    Music(String),
    /// Music was asked for and this build has no audio encoder.
    AudioUnavailable,
}

impl ExportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Source(_) => "source_unreadable",
            Self::DecoderUnavailable { .. } => "decoder_unavailable",
            Self::EditList(_) => "bad_edit_list",
            Self::Encoder(_) => "encoder_unavailable",
            Self::Decode(_) => "decode_failed",
            Self::Write(_) => "write_failed",
            Self::Cancelled => "cancelled",
            Self::Music(_) => "music_unreadable",
            Self::AudioUnavailable => "audio_unavailable",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Source(d) | Self::Encoder(d) | Self::Decode(d) | Self::Write(d) => d.clone(),
            Self::Music(d) => d.clone(),
            Self::AudioUnavailable => {
                "this build of roomlerd has no audio encoder, so it cannot add music".into()
            }
            Self::DecoderUnavailable { profile } => format!(
                "this recording's video is H.264 profile {profile} (a hardware encoder's), and \
                 this build of roomlerd has no decoder for it (its FFmpeg carries no H.264 \
                 decoder). Recordings made with the software encoder (profile 66) can be edited"
            ),
            Self::EditList(e) => e.to_string(),
            Self::Cancelled => "the export was cancelled".into(),
        }
    }
}

/// Where an export of `source` goes: `<stem> (edited).mp4` beside it, then
/// ` (edited 2)`, ` (edited 3)` … — an export never replaces a file.
pub fn edited_name(source: &Path) -> Option<PathBuf> {
    let dir = source.parent()?;
    let stem = source.file_stem()?.to_str()?;
    let first = dir.join(format!("{stem} (edited).mp4"));
    if !first.exists() {
        return Some(first);
    }
    (2u32..1000)
        .map(|n| dir.join(format!("{stem} (edited {n}).mp4")))
        .find(|p| !p.exists())
}

/// The source's frame rate from its sample durations (the most common one):
/// a recording is constant-rate, and a gap left by a slow encoder is one long
/// sample, not a different rate.
pub fn source_fps(samples: &[mp4::ProgressiveSample], timescale: u32) -> u32 {
    let mut counts = std::collections::HashMap::<u32, usize>::new();
    for s in samples {
        *counts.entry(s.duration).or_default() += 1;
    }
    counts
        .into_iter()
        .filter(|(d, _)| *d > 0)
        .max_by_key(|(d, n)| (*n, std::cmp::Reverse(*d)))
        .map(|(d, _)| ((u64::from(timescale) + u64::from(d) / 2) / u64::from(d)) as u32)
        .unwrap_or(30)
        .clamp(1, 60)
}

/// P5b — a sound failure, said by the part that failed.
#[cfg(feature = "audio")]
fn audio_failed(e: super::export_audio::AudioError) -> ExportError {
    use super::export_audio::AudioError;
    match e {
        AudioError::Music(d) => ExportError::Music(d),
        AudioError::Original(d) => ExportError::Decode(format!("the recording's audio: {d}")),
        AudioError::Encode(d) => ExportError::Encoder(format!("the audio encoder: {d}")),
        AudioError::Write(d) => ExportError::Write(d),
    }
}

/// Export `source` through `edits` to `dest` (which must not exist).
/// `progress(done, total)` is called as frames are written; `cancel` is
/// polled once per frame.
pub async fn export(
    source: &Path,
    edits: &EditList,
    dest: &Path,
    make_encoder: EncoderFactory,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<ExportSummary, ExportError> {
    let src = ProgressiveFile::open(source).map_err(|e| ExportError::Source(format!("{e:#}")))?;
    let format = src
        .video_format()
        .map_err(|e| ExportError::Source(format!("{e:#}")))?;
    // P4 — openh264 for the software encoder's Baseline, FFmpeg's decoder
    // for everything else where this build carries it (`decode` module).
    let mut decoder = VideoDecoder::for_profile(format.profile).map_err(|e| {
        tracing::info!(profile = format.profile, %e, "export: no decoder for this recording");
        ExportError::DecoderUnavailable {
            profile: format.profile,
        }
    })?;
    let samples = src
        .samples(mp4::VIDEO_TRACK_ID)
        .map_err(|e| ExportError::Source(format!("{e:#}")))?;
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return Err(ExportError::Source("the recording has no video".into()));
    };
    // Source times on the 90 kHz clock the plan speaks.
    let ts = u64::from(format.timescale);
    let to_90k = |t: u64| t * u64::from(mp4::VIDEO_TIMESCALE) / ts;
    let dts: Vec<u64> = samples.iter().map(|s| to_90k(s.dts - first.dts)).collect();
    let duration_ms = (last.dts - first.dts + u64::from(last.duration)) * 1000 / ts;
    let plan: Plan = edits.plan(duration_ms).map_err(ExportError::EditList)?;

    // P5b — the export's sound, when it has any.
    #[cfg(feature = "audio")]
    let mut audio =
        super::export_audio::ExportAudio::new(source, &plan, edits).map_err(audio_failed)?;
    #[cfg(not(feature = "audio"))]
    if edits.music.is_some() {
        return Err(ExportError::AudioUnavailable);
    }
    #[cfg(feature = "audio")]
    let audio_carried = audio
        .as_ref()
        .map(|a| a.carries().as_str())
        .unwrap_or("none");
    #[cfg(not(feature = "audio"))]
    let audio_carried = match src.audio_format() {
        Ok(Some(_)) => "not_carried",
        _ => "none",
    };

    let fps = source_fps(&samples, format.timescale);
    let cadence = Cadence::new(fps);
    let total = plan.frames(fps);
    // The source frame every output frame shows: the last one presented at
    // or before its source time.
    let shown: Vec<usize> = (0..total)
        .map(|n| {
            let t = plan.source_time(cadence.pts(n)).unwrap_or(u64::MAX);
            dts.partition_point(|d| *d <= t).saturating_sub(1)
        })
        .collect();
    let key_at_or_before = |i: usize| (0..=i).rev().find(|&k| samples[k].sync).unwrap_or(0);

    let params = src
        .avc_parameter_sets_annexb()
        .map_err(|e| ExportError::Source(format!("{e:#}")))?;
    let mut file = std::fs::File::open(source)
        .map_err(|e| ExportError::Source(format!("{}: {e}", source.display())))?;

    // Staged beside the destination, locked like a recording's partial.
    let dest_dir = dest
        .parent()
        .ok_or_else(|| ExportError::Write(format!("{} has no folder", dest.display())))?;
    let dest_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ExportError::Write(format!("{} has no name", dest.display())))?;
    let staging = dest_dir.join(PARTIAL_DIR);
    std::fs::create_dir_all(&staging)
        .map_err(|e| ExportError::Write(format!("{}: {e}", staging.display())))?;
    let partial = staging.join(format!("{dest_name}{PARTIAL_SUFFIX}"));
    let _lock = PartialLock::try_take(&partial)
        .map_err(|e| ExportError::Write(format!("{}: {e}", partial.display())))?
        .ok_or_else(|| ExportError::Write("another export is writing that file".into()))?;

    let mut make_encoder = Some(make_encoder);
    let mut encoder: Option<Box<dyn crate::encode::VideoEncoder>> = None;
    let mut encoder_name = String::new();
    let mut writer: Option<FragmentedWriter> = None;
    let mut fifo = TickFifo::default();
    let mut decoded: Option<usize> = None;
    let mut picture: Option<Arc<Frame>> = None;
    let mut written = 0u64;

    let result: Result<(), ExportError> = async {
        for (n, &want) in shown.iter().enumerate() {
            if cancel.load(Ordering::Acquire) {
                return Err(ExportError::Cancelled);
            }
            if decoded != Some(want) {
                // Forward from where the decoder is, unless the frame's GOP
                // starts ahead of it (a cut): then jump to that keyframe.
                let key = key_at_or_before(want);
                let from = match decoded {
                    Some(d) if d < want && key <= d + 1 => d + 1,
                    _ => key,
                };
                for (i, sample) in samples.iter().enumerate().take(want + 1).skip(from) {
                    let raw = src
                        .read_sample(&mut file, sample)
                        .map_err(|e| ExportError::Source(format!("{e:#}")))?;
                    let nals = length_prefixed_to_annexb(&raw).ok_or_else(|| {
                        ExportError::Source(format!("sample {i} is not length-prefixed H.264"))
                    })?;
                    let mut au = Vec::with_capacity(params.len() + nals.len());
                    if sample.sync {
                        au.extend_from_slice(&params);
                    }
                    au.extend_from_slice(&nals);
                    if let Some(pic) = decoder
                        .decode(&au, i, i == want)
                        .map_err(ExportError::Decode)?
                    {
                        picture = Some(Arc::new(pic));
                    }
                }
                decoded = Some(want);
            }
            let frame = picture.clone().expect("decoded above");

            if encoder.is_none() {
                let make = make_encoder.take().expect("made once");
                let e = make(frame.width, frame.height)
                    .map_err(|e| ExportError::Encoder(format!("{e:#}")))?;
                encoder_name = e.name().to_string();
                encoder = Some(e);
                #[cfg(feature = "audio")]
                let audio_track = audio.as_ref().map(|a| a.track());
                #[cfg(not(feature = "audio"))]
                let audio_track = None;
                writer = Some(
                    FragmentedWriter::create(
                        &partial,
                        VideoTrack {
                            width: frame.width,
                            height: frame.height,
                            fps,
                            color: ColorInfo::BT601_LIMITED,
                        },
                        audio_track,
                    )
                    .map_err(|e| ExportError::Write(format!("{e:#}")))?,
                );
            }
            let (Some(enc), Some(w)) = (encoder.as_mut(), writer.as_mut()) else {
                unreachable!("made above");
            };
            fifo.submitted(n as u64);
            let packets = enc
                .encode(frame)
                .await
                .map_err(|e| ExportError::Encoder(format!("frame {n}: {e:#}")))?;
            for (au, key) in group_access_units(&encoder_name, packets) {
                let pts = cadence.pts(fifo.finished());
                match w.push_video(pts, &au, key) {
                    Ok(mp4::PushOutcome::Written) => written += 1,
                    Ok(mp4::PushOutcome::DroppedBeforeKeyframe) => {}
                    Err(e) => return Err(ExportError::Write(format!("{e:#}"))),
                }
            }
            // The sound up to the end of this frame, so the file interleaves
            // as a recording does.
            #[cfg(feature = "audio")]
            if let Some(a) = audio.as_mut() {
                let frame_end = cadence.pts(n as u64 + 1) * u64::from(super::audio::RATE)
                    / u64::from(mp4::VIDEO_TIMESCALE);
                a.produce_until(frame_end, &mut |packet, duration| {
                    w.push_audio(&packet, duration)
                })
                .map_err(audio_failed)?;
            }
            if (n as u64 + 1).is_multiple_of(30) || n as u64 + 1 == total {
                progress(n as u64 + 1, total);
            }
        }
        Ok(())
    }
    .await;

    // The rest of the sound, to the export's end.
    #[cfg(feature = "audio")]
    let result = match (result, audio.as_mut(), writer.as_mut()) {
        (Ok(()), Some(a), Some(w)) => a
            .finish(&mut |packet, duration| w.push_audio(&packet, duration))
            .map_err(audio_failed),
        (r, _, _) => r,
    };

    // A failed or cancelled export leaves nothing behind.
    let writer = match (result, writer) {
        (Ok(()), Some(w)) => w,
        (Ok(()), None) => {
            let _ = std::fs::remove_file(&partial);
            return Err(ExportError::EditList(Invalid::NothingKept));
        }
        (Err(e), w) => {
            drop(w);
            let _ = std::fs::remove_file(&partial);
            return Err(e);
        }
    };
    let finished = writer.finish();
    if let Err(e) = finished {
        let _ = std::fs::remove_file(&partial);
        return Err(ExportError::Write(format!("{e:#}")));
    }
    // `finalize` leaves its source in place; the staged partial is ours to
    // remove, whichever way it went.
    let finalized = mp4::finalize(&partial, dest);
    let _ = std::fs::remove_file(&partial);
    let summary = finalized.map_err(|e| ExportError::Write(format!("{e:#}")))?;
    Ok(ExportSummary {
        path: dest.to_path_buf(),
        frames: written,
        duration_ms: summary.duration_ms,
        bytes: summary.bytes,
        encoder: encoder_name,
        audio: audio_carried,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(duration: u32) -> mp4::ProgressiveSample {
        mp4::ProgressiveSample {
            offset: 0,
            size: 1,
            dts: 0,
            duration,
            sync: false,
        }
    }

    #[test]
    fn the_rate_is_the_common_sample_duration_not_a_gap() {
        let mut s: Vec<_> = (0..100).map(|_| sample(3000)).collect();
        s.push(sample(90_000)); // a one-second stall
        assert_eq!(source_fps(&s, 90_000), 30);
        let s: Vec<_> = (0..10).map(|_| sample(1500)).collect();
        assert_eq!(source_fps(&s, 90_000), 60);
    }

    #[test]
    fn an_export_never_replaces_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("Roomler Recording 1.mp4");
        let first = edited_name(&src).unwrap();
        assert!(first.ends_with("Roomler Recording 1 (edited).mp4"));
        std::fs::write(&first, b"x").unwrap();
        let second = edited_name(&src).unwrap();
        assert!(
            second.ends_with("Roomler Recording 1 (edited 2).mp4"),
            "{}",
            second.display()
        );
    }
}
