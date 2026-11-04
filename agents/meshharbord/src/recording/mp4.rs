// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — the recorder's MP4 layer.
//!
//! Two shapes of the same file, for two different jobs:
//!
//! - **Fragmented MP4 while recording** ([`FragmentedWriter`]): `ftyp`, an
//!   empty-tabled `moov` with `mvex`, then one `moof`+`mdat` pair per GOP
//!   (a fragment always starts on a keyframe, ~2 s). Every fragment is
//!   self-describing, so a recorder that dies — `kill -9`, a pushed update's
//!   Restart Manager, a power cut after the last `sync` — leaves a file that
//!   is readable up to its last complete fragment. That is the crash-safety
//!   budget the spec promises: at most one fragment.
//! - **Progressive MP4 on stop** ([`finalize`]): `ftyp`, a full `moov`
//!   (sample tables, `stss`, `stco`/`co64`) FIRST, then one `mdat` — what
//!   QuickTime, Movies & TV and every editor open without complaint. It is a
//!   remux: fragment payloads are copied verbatim, nothing is re-encoded.
//!
//! The same [`finalize`] is the boot reconciler's tool for a partial that a
//! dead recorder left behind: it reads what is there and stops at the first
//! incomplete fragment.
//!
//! ⚠️ Box-level only (`mp4-atom`), no FFmpeg muxer — deliberately, so the
//! recorder works on the arm64 build that has no FFmpeg at all, and so no
//! libavformat component has to be vendored for it.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use mp4_atom::{
    Audio, Avc1, Avcc, Co64, Codec, Colr, Decode as _, Dinf, Dops, Dref, Encode as _, Esds,
    FixedPoint, Ftyp, Hdlr, Matrix, Mdhd, Mdia, Mfhd, Minf, Moof, Moov, Mp4a, Mvex, Mvhd, Opus,
    Pasp, Smhd, Stbl, Stco, Stsc, StscEntry, Stsd, Stss, Stsz, StszSamples, Stts, SttsEntry, Tfdt,
    Tfhd, Tkhd, Traf, Trak, Trex, Trun, TrunEntry, Url, Visual, Vmhd, esds,
};

use super::annexb::AccessUnit;

/// Track id of the video track in every file this module writes.
pub const VIDEO_TRACK_ID: u32 = 1;
/// Track id of the (optional) audio track.
pub const AUDIO_TRACK_ID: u32 = 2;
/// `mvhd` / `tkhd` timescale: milliseconds.
pub const MOVIE_TIMESCALE: u32 = 1000;
/// Video media timescale. 90 kHz divides evenly by 24, 25, 30, 50 and 60 fps.
pub const VIDEO_TIMESCALE: u32 = 90_000;

/// A fragment is cut at the next keyframe; this is the backstop for an
/// encoder that stops producing them, so a crash never loses more than this.
const MAX_FRAGMENT_TICKS: u64 = 10 * VIDEO_TIMESCALE as u64;
/// `sync_data` every N fragments (~10 s at a 2 s GOP). `flush` happens after
/// every fragment, which is all a *process* crash needs; the periodic sync is
/// for power loss, and costs one flush of the page cache per ten seconds.
const SYNC_EVERY_FRAGMENTS: u32 = 5;

/// ISO/IEC 14496-12 §8.8.3.1 sample flags.
const FLAGS_SYNC: u32 = 0x0200_0000; // sample_depends_on = 2 (depends on nothing)
const FLAGS_NON_SYNC: u32 = 0x0101_0000; // sample_depends_on = 1, sample_is_non_sync_sample = 1

/// The colour description written into the `colr` (nclx) box. It MUST match
/// the matrix and range the encoder's BGRA→YUV conversion actually used, or an
/// HD player assumes BT.709 and every colour shifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ColorInfo {
    pub primaries: u16,
    pub transfer: u16,
    pub matrix: u16,
    pub full_range: bool,
}

impl ColorInfo {
    /// BT.601 (SMPTE 170M), studio swing — what `openh264_backend`'s
    /// `bgra_to_yuv_buffer` produces.
    pub const BT601_LIMITED: Self = Self {
        primaries: 6,
        transfer: 6,
        matrix: 6,
        full_range: false,
    };
    /// BT.709, studio swing.
    pub const BT709_LIMITED: Self = Self {
        primaries: 1,
        transfer: 1,
        matrix: 1,
        full_range: false,
    };
}

/// The video track of a recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoTrack {
    pub width: u32,
    pub height: u32,
    /// Nominal frame rate — only used for the last sample's duration.
    pub fps: u32,
    pub color: ColorInfo,
}

impl VideoTrack {
    fn tick(&self) -> u32 {
        VIDEO_TIMESCALE / self.fps.max(1)
    }
}

/// The audio track of a recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioTrack {
    /// Media timescale = sample rate.
    pub sample_rate: u32,
    pub channels: u8,
    pub codec: AudioCodec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioCodec {
    /// Opus in ISOBMFF (`Opus` + `dOps`). `pre_skip` in 48 kHz samples.
    Opus { pre_skip: u16 },
    /// FR-85 P4 — AAC-LC (`mp4a` + `esds`, object type 0x40): what every
    /// player and editor opens, where Opus-in-MP4 does not play in QuickTime.
    /// `asc` is the encoder's AudioSpecificConfig; `bitrate` is informative
    /// (the `esds` average).
    ///
    /// ⚠️ No priming delay is written anywhere: the recorder feeds the encoder
    /// from `delay` samples past the first video frame
    /// (`audio_codec::AudioEncoder::unsignalled_delay`), so decoded sample k
    /// IS recording time k in every player, edit list or not.
    Aac { asc: Vec<u8>, bitrate: u32 },
}

/// ISO/IEC 14496-1 `objectTypeIndication` for MPEG-4 Audio (AAC).
const OTI_MPEG4_AUDIO: u8 = 0x40;
/// ISO/IEC 14496-1 `streamType` for an audio stream.
const STREAM_TYPE_AUDIO: u8 = 0x05;

/// What happened to a pushed video access unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Written,
    /// Nothing before the first keyframe can be decoded; it is dropped.
    DroppedBeforeKeyframe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingSample {
    duration: u32,
    size: u32,
    sync: bool,
}

/// Counters a caller can report while recording.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterStats {
    pub video_samples: u64,
    pub audio_samples: u64,
    pub fragments: u32,
    /// Bytes in the file so far (headers included).
    pub bytes: u64,
    /// Media time covered by the video track, in [`VIDEO_TIMESCALE`] units.
    pub video_ticks: u64,
}

/// Writes a fragmented MP4 while recording. See the module docs.
pub struct FragmentedWriter {
    out: BufWriter<File>,
    video: VideoTrack,
    audio: Option<AudioTrack>,
    sps: Vec<Vec<u8>>,
    pps: Vec<Vec<u8>>,
    header_written: bool,
    sequence: u32,
    // The open fragment.
    v_samples: Vec<PendingSample>,
    v_data: Vec<u8>,
    v_base: u64,
    a_samples: Vec<PendingSample>,
    a_data: Vec<u8>,
    a_base: u64,
    // Timing.
    last_video_pts: Option<u64>,
    next_video_dts: u64,
    next_audio_dts: u64,
    stats: WriterStats,
}

impl FragmentedWriter {
    /// Create (never overwrite) `path` and prepare to write. Nothing reaches
    /// the file until the first keyframe supplies the parameter sets.
    pub fn create(path: &Path, video: VideoTrack, audio: Option<AudioTrack>) -> Result<Self> {
        if video.width == 0 || video.height == 0 || video.fps == 0 {
            bail!("recording: invalid video track {video:?}");
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("recording: cannot create {}", path.display()))?;
        Ok(Self {
            out: BufWriter::with_capacity(1 << 20, file),
            video,
            audio,
            sps: Vec::new(),
            pps: Vec::new(),
            header_written: false,
            sequence: 1,
            v_samples: Vec::new(),
            v_data: Vec::new(),
            v_base: 0,
            a_samples: Vec::new(),
            a_data: Vec::new(),
            a_base: 0,
            last_video_pts: None,
            next_video_dts: 0,
            next_audio_dts: 0,
            stats: WriterStats::default(),
        })
    }

    pub fn stats(&self) -> WriterStats {
        self.stats
    }

    /// Push one encoded H.264 access unit (Annex-B) presented at `pts`
    /// ([`VIDEO_TIMESCALE`] units since the recording's start). PTS must be
    /// strictly increasing; the recorder's pacer guarantees it.
    ///
    /// `keyframe_hint` is the encoder's own opinion; an IDR slice in the data
    /// makes the sample a sync sample either way.
    pub fn push_video(
        &mut self,
        pts: u64,
        annexb: &[u8],
        keyframe_hint: bool,
    ) -> Result<PushOutcome> {
        let au = AccessUnit::from_annexb_h264(annexb);
        if au.sample.is_empty() {
            // Parameter sets / AUD only — nothing to present. Keep the
            // parameter sets if we have none yet; they precede the IDR.
            if !self.header_written {
                if !au.sps.is_empty() {
                    self.sps = au.sps;
                }
                if !au.pps.is_empty() {
                    self.pps = au.pps;
                }
            }
            return Ok(PushOutcome::DroppedBeforeKeyframe);
        }
        let sync = au.has_idr || keyframe_hint;
        if !self.header_written {
            if !au.sps.is_empty() {
                self.sps = au.sps.clone();
            }
            if !au.pps.is_empty() {
                self.pps = au.pps.clone();
            }
            if !sync || self.sps.is_empty() || self.pps.is_empty() {
                return Ok(PushOutcome::DroppedBeforeKeyframe);
            }
            self.write_header()?;
            self.v_base = pts;
            self.next_video_dts = pts;
        } else if au.param_sets_differ(&self.sps, &self.pps) {
            bail!("recording: the encoder changed its parameter sets mid-recording");
        }

        if let Some(prev) = self.last_video_pts {
            if pts <= prev {
                bail!("recording: non-increasing video pts ({pts} after {prev})");
            }
            // The previous sample lasts until this one is presented.
            let d = pts - prev;
            if let Some(last) = self.v_samples.last_mut() {
                last.duration = u32::try_from(d).unwrap_or(u32::MAX);
            }
            self.stats.video_ticks += d;
        }

        let fragment_ticks = pts.saturating_sub(self.v_base);
        if !self.v_samples.is_empty() && (sync || fragment_ticks >= MAX_FRAGMENT_TICKS) {
            self.flush_fragment()?;
        }
        if self.v_samples.is_empty() {
            self.v_base = pts;
        }
        self.v_samples.push(PendingSample {
            duration: self.video.tick(),
            size: au.sample.len() as u32,
            sync,
        });
        self.v_data.extend_from_slice(&au.sample);
        self.last_video_pts = Some(pts);
        self.next_video_dts = pts;
        self.stats.video_samples += 1;
        Ok(PushOutcome::Written)
    }

    /// Push one encoded audio packet of `duration` samples. Audio decode time
    /// is the running sum of durations — the recorder keeps it aligned to the
    /// video clock by filling silence or dropping, not by stamping.
    pub fn push_audio(&mut self, data: &[u8], duration: u32) -> Result<()> {
        if self.audio.is_none() {
            bail!("recording: audio pushed to a video-only writer");
        }
        if !self.header_written {
            // Before the first keyframe there is no file yet; the recorder
            // aligns both clocks to the first video frame, so this is only
            // the audio that raced ahead of it.
            return Ok(());
        }
        if self.a_samples.is_empty() {
            self.a_base = self.next_audio_dts;
        }
        self.a_samples.push(PendingSample {
            duration,
            size: data.len() as u32,
            sync: true,
        });
        self.a_data.extend_from_slice(data);
        self.next_audio_dts += u64::from(duration);
        self.stats.audio_samples += 1;
        Ok(())
    }

    /// Flush the open fragment and close the file. The fragmented file stays
    /// valid on its own; [`finalize`] turns it into the progressive one.
    pub fn finish(mut self) -> Result<WriterStats> {
        if !self.v_samples.is_empty() {
            // The last sample has no successor: it keeps its nominal tick.
            self.stats.video_ticks += u64::from(self.video.tick());
            self.flush_fragment()?;
        } else if !self.a_samples.is_empty() {
            self.flush_fragment()?;
        }
        self.out.flush().context("recording: flush")?;
        self.out.get_ref().sync_all().context("recording: sync")?;
        Ok(self.stats)
    }

    fn write_header(&mut self) -> Result<()> {
        let ftyp = Ftyp {
            major_brand: b"isom".into(),
            minor_version: 0x200,
            compatible_brands: vec![
                b"isom".into(),
                b"iso6".into(),
                b"iso2".into(),
                b"avc1".into(),
                b"mp41".into(),
            ],
        };
        let mut traks = vec![video_trak(
            &self.video,
            &self.sps,
            &self.pps,
            0,
            empty_stbl_tables(),
        )?];
        let mut trex = vec![trex_for(VIDEO_TRACK_ID)];
        if let Some(a) = &self.audio {
            traks.push(audio_trak(a, 0, empty_stbl_tables()));
            trex.push(trex_for(AUDIO_TRACK_ID));
        }
        let moov = Moov {
            mvhd: mvhd(0, traks.len() as u32 + 1),
            mvex: Some(Mvex { mehd: None, trex }),
            trak: traks,
            ..Default::default()
        };
        let mut buf = Vec::new();
        ftyp.encode(&mut buf).map_err(mp4_err)?;
        moov.encode(&mut buf).map_err(mp4_err)?;
        self.out
            .write_all(&buf)
            .context("recording: write header")?;
        self.out.flush().context("recording: flush header")?;
        self.stats.bytes += buf.len() as u64;
        self.header_written = true;
        Ok(())
    }

    fn flush_fragment(&mut self) -> Result<()> {
        if self.v_samples.is_empty() && self.a_samples.is_empty() {
            return Ok(());
        }
        let mut trafs = Vec::new();
        if !self.v_samples.is_empty() {
            trafs.push(traf_for(VIDEO_TRACK_ID, self.v_base, &self.v_samples));
        }
        if !self.a_samples.is_empty() {
            trafs.push(traf_for(AUDIO_TRACK_ID, self.a_base, &self.a_samples));
        }
        let mut moof = Moof {
            mfhd: Mfhd {
                sequence_number: self.sequence,
            },
            traf: trafs,
        };
        // Two passes: the data offsets are fixed-width, so the size does not
        // depend on their values — encode once to learn it, then for real.
        let moof_len = encoded_len(&moof)?;
        let payload_len = (self.v_data.len() + self.a_data.len()) as u64;
        let mdat_header_len: u64 = if payload_len + 8 > u64::from(u32::MAX) {
            16
        } else {
            8
        };
        let mut offset = moof_len + mdat_header_len;
        for traf in &mut moof.traf {
            let len = if traf.tfhd.track_id == VIDEO_TRACK_ID {
                self.v_data.len()
            } else {
                self.a_data.len()
            };
            traf.trun[0].data_offset =
                Some(i32::try_from(offset).map_err(|_| anyhow!("recording: fragment too large"))?);
            offset += len as u64;
        }
        let mut buf = Vec::with_capacity(moof_len as usize + 16);
        moof.encode(&mut buf).map_err(mp4_err)?;
        debug_assert_eq!(buf.len() as u64, moof_len);
        write_box_header(&mut buf, b"mdat", payload_len);
        self.out.write_all(&buf).context("recording: write moof")?;
        self.out
            .write_all(&self.v_data)
            .context("recording: write video data")?;
        self.out
            .write_all(&self.a_data)
            .context("recording: write audio data")?;
        self.out.flush().context("recording: flush fragment")?;
        self.stats.bytes += buf.len() as u64 + payload_len;
        self.stats.fragments += 1;
        if self.stats.fragments.is_multiple_of(SYNC_EVERY_FRAGMENTS) {
            self.out.get_ref().sync_data().context("recording: sync")?;
        }
        self.sequence += 1;
        self.v_samples.clear();
        self.v_data.clear();
        self.a_samples.clear();
        self.a_data.clear();
        Ok(())
    }
}

fn mp4_err(e: mp4_atom::Error) -> anyhow::Error {
    anyhow!("mp4: {e}")
}

fn encoded_len<T: mp4_atom::Encode>(atom: &T) -> Result<u64> {
    let mut buf = Vec::new();
    atom.encode(&mut buf).map_err(mp4_err)?;
    Ok(buf.len() as u64)
}

/// A box header for a payload of `payload_len` bytes (large-size form when it
/// does not fit 32 bits).
fn write_box_header(buf: &mut Vec<u8>, kind: &[u8; 4], payload_len: u64) {
    if payload_len + 8 > u64::from(u32::MAX) {
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(kind);
        buf.extend_from_slice(&(payload_len + 16).to_be_bytes());
    } else {
        buf.extend_from_slice(&((payload_len + 8) as u32).to_be_bytes());
        buf.extend_from_slice(kind);
    }
}

fn trex_for(track_id: u32) -> Trex {
    Trex {
        track_id,
        default_sample_description_index: 1,
        default_sample_duration: 0,
        default_sample_size: 0,
        default_sample_flags: 0,
    }
}

fn traf_for(track_id: u32, base: u64, samples: &[PendingSample]) -> Traf {
    Traf {
        tfhd: Tfhd {
            track_id,
            default_base_is_moof: true,
            ..Default::default()
        },
        tfdt: Some(Tfdt {
            base_media_decode_time: base,
        }),
        trun: vec![Trun {
            data_offset: Some(0),
            entries: samples
                .iter()
                .map(|s| TrunEntry {
                    duration: Some(s.duration),
                    size: Some(s.size),
                    flags: Some(if s.sync { FLAGS_SYNC } else { FLAGS_NON_SYNC }),
                    cts: None,
                })
                .collect(),
        }],
        ..Default::default()
    }
}

fn mvhd(duration_ms: u64, next_track_id: u32) -> Mvhd {
    Mvhd {
        timescale: MOVIE_TIMESCALE,
        duration: duration_ms,
        next_track_id,
        ..Default::default()
    }
}

/// The sample tables of one track — empty in the fragmented header, full in
/// the progressive file.
#[derive(Default)]
struct StblTables {
    stts: Stts,
    stss: Option<Stss>,
    stsc: Stsc,
    stsz: Stsz,
    stco: Option<Stco>,
    co64: Option<Co64>,
}

fn empty_stbl_tables() -> StblTables {
    StblTables {
        stsz: Stsz {
            samples: StszSamples::Identical { count: 0, size: 0 },
        },
        stco: Some(Stco::default()),
        ..Default::default()
    }
}

fn stbl(stsd: Stsd, t: StblTables) -> Stbl {
    Stbl {
        stsd,
        stts: t.stts,
        stss: t.stss,
        stsc: t.stsc,
        stsz: t.stsz,
        stco: t.stco,
        co64: t.co64,
        ..Default::default()
    }
}

fn dinf() -> Dinf {
    Dinf {
        dref: Dref {
            urls: vec![Url {
                location: String::new(),
            }],
        },
    }
}

fn video_trak(
    v: &VideoTrack,
    sps: &[Vec<u8>],
    pps: &[Vec<u8>],
    media_duration: u64,
    tables: StblTables,
) -> Result<Trak> {
    let first_sps = sps.first().ok_or_else(|| anyhow!("recording: no SPS"))?;
    let first_pps = pps.first().ok_or_else(|| anyhow!("recording: no PPS"))?;
    let mut avcc = Avcc::new(first_sps, first_pps).map_err(mp4_err)?;
    avcc.sequence_parameter_sets = sps.to_vec();
    avcc.picture_parameter_sets = pps.to_vec();
    let width = u16::try_from(v.width).map_err(|_| anyhow!("recording: width too large"))?;
    let height = u16::try_from(v.height).map_err(|_| anyhow!("recording: height too large"))?;
    let avc1 = Avc1 {
        visual: Visual {
            data_reference_index: 1,
            width,
            height,
            compressor: "Roomler".into(),
            ..Default::default()
        },
        avcc,
        colr: Some(Colr::Nclx {
            colour_primaries: v.color.primaries,
            transfer_characteristics: v.color.transfer,
            matrix_coefficients: v.color.matrix,
            full_range_flag: v.color.full_range,
        }),
        pasp: Some(Pasp {
            h_spacing: 1,
            v_spacing: 1,
        }),
        ..Default::default()
    };
    Ok(Trak {
        tkhd: Tkhd {
            track_id: VIDEO_TRACK_ID,
            duration: ticks_to_ms(media_duration, VIDEO_TIMESCALE),
            enabled: true,
            in_movie: true,
            matrix: Matrix::default(),
            width: FixedPoint::new(width, 0),
            height: FixedPoint::new(height, 0),
            ..Default::default()
        },
        mdia: Mdia {
            mdhd: Mdhd {
                timescale: VIDEO_TIMESCALE,
                duration: media_duration,
                language: "und".into(),
                ..Default::default()
            },
            hdlr: Hdlr {
                handler: b"vide".into(),
                name: "Roomler video".into(),
            },
            minf: Minf {
                vmhd: Some(Vmhd::default()),
                dinf: dinf(),
                stbl: stbl(
                    Stsd {
                        codecs: vec![Codec::Avc1(avc1)],
                    },
                    tables,
                ),
                ..Default::default()
            },
        },
        ..Default::default()
    })
}

fn audio_trak(a: &AudioTrack, media_duration: u64, tables: StblTables) -> Trak {
    let entry = Audio {
        data_reference_index: 1,
        channel_count: u16::from(a.channels),
        sample_size: 16,
        sample_rate: FixedPoint::new(a.sample_rate.min(u32::from(u16::MAX)) as u16, 0),
    };
    let codec = match &a.codec {
        AudioCodec::Opus { pre_skip } => Codec::Opus(Opus {
            audio: entry,
            dops: Dops {
                output_channel_count: a.channels,
                pre_skip: *pre_skip,
                input_sample_rate: a.sample_rate,
                output_gain: 0,
            },
            btrt: None,
        }),
        AudioCodec::Aac { asc, bitrate } => {
            let (profile, freq_index, chan_conf) = asc_fields(asc);
            Codec::Mp4a(Mp4a {
                audio: entry,
                esds: Esds {
                    es_desc: esds::EsDescriptor {
                        // ISO/IEC 14496-14 §3.1.2: 0 in a stored file.
                        es_id: 0,
                        dec_config: esds::DecoderConfig {
                            object_type_indication: OTI_MPEG4_AUDIO,
                            stream_type: STREAM_TYPE_AUDIO,
                            up_stream: 0,
                            buffer_size_db: Default::default(),
                            max_bitrate: *bitrate,
                            avg_bitrate: *bitrate,
                            dec_specific: Some(esds::DecoderSpecific {
                                profile,
                                freq_index,
                                chan_conf,
                                raw: asc.clone(),
                            }),
                        },
                        sl_config: esds::SLConfig::default(),
                    },
                },
                btrt: None,
                taic: None,
            })
        }
    };
    Trak {
        tkhd: Tkhd {
            track_id: AUDIO_TRACK_ID,
            duration: ticks_to_ms(media_duration, a.sample_rate),
            enabled: true,
            in_movie: true,
            alternate_group: 1,
            volume: FixedPoint::new(1, 0),
            matrix: Matrix::default(),
            ..Default::default()
        },
        mdia: Mdia {
            mdhd: Mdhd {
                timescale: a.sample_rate,
                duration: media_duration,
                language: "und".into(),
                ..Default::default()
            },
            hdlr: Hdlr {
                handler: b"soun".into(),
                name: "Roomler audio".into(),
            },
            minf: Minf {
                smhd: Some(Smhd::default()),
                dinf: dinf(),
                stbl: stbl(
                    Stsd {
                        codecs: vec![codec],
                    },
                    tables,
                ),
                ..Default::default()
            },
        },
        ..Default::default()
    }
}

/// The sampling-frequency index of an AudioSpecificConfig (ISO/IEC 14496-3
/// §1.6.3.4), or `None` for a rate that needs the explicit 24-bit escape.
fn aac_freq_index(rate: u32) -> Option<u8> {
    const RATES: [u32; 13] = [
        96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025,
        8_000, 7_350,
    ];
    RATES.iter().position(|&r| r == rate).map(|i| i as u8)
}

/// FR-85 P4 — the two-byte AudioSpecificConfig of AAC-LC at `rate` with
/// `channels` (1–7): what an encoder that hands none over would have said.
pub fn aac_lc_asc(rate: u32, channels: u8) -> Option<Vec<u8>> {
    const AOT_AAC_LC: u8 = 2;
    let fi = aac_freq_index(rate)?;
    if !(1..=7).contains(&channels) {
        return None;
    }
    Some(vec![
        (AOT_AAC_LC << 3) | (fi >> 1),
        ((fi & 1) << 7) | (channels << 3),
    ])
}

/// An AudioSpecificConfig's leading fields (object type, frequency index,
/// channel configuration); zeros where it is too short to say.
fn asc_fields(asc: &[u8]) -> (u8, u8, u8) {
    match asc {
        [a, b, ..] => (a >> 3, ((a & 0x07) << 1) | (b >> 7), (b >> 3) & 0x0F),
        _ => (0, 0, 0),
    }
}

fn ticks_to_ms(ticks: u64, timescale: u32) -> u64 {
    if timescale == 0 {
        return 0;
    }
    ((u128::from(ticks) * 1000 + u128::from(timescale) / 2) / u128::from(timescale)) as u64
}

// ── reading our own fragmented files ────────────────────────────────────────

/// One sample of a fragmented file, as its `trun` describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleRecord {
    pub duration: u32,
    pub size: u32,
    pub sync: bool,
}

/// One track's run inside one fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackRun {
    track_id: u32,
    /// Offset of the run's first byte from the start of the fragment's
    /// `mdat` payload.
    offset_in_payload: u64,
    samples: Vec<SampleRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fragment {
    /// Absolute file offset of the `mdat` payload.
    payload_offset: u64,
    payload_len: u64,
    runs: Vec<TrackRun>,
}

/// What [`read_fragmented`] found.
#[derive(Debug, Clone)]
pub struct FragmentedIndex {
    moov: Moov,
    fragments: Vec<Fragment>,
    /// `true` when the file ended inside a fragment (a recorder that died).
    pub truncated: bool,
}

impl FragmentedIndex {
    /// Number of complete fragments.
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }

    /// All samples of `track_id`, in decode order.
    pub fn samples(&self, track_id: u32) -> Vec<SampleRecord> {
        self.fragments
            .iter()
            .flat_map(|f| f.runs.iter())
            .filter(|r| r.track_id == track_id)
            .flat_map(|r| r.samples.iter().copied())
            .collect()
    }
}

/// A top-level box: kind, absolute offset of its header, header length and
/// payload length. `None` payload length = "to end of file".
struct TopBox {
    kind: [u8; 4],
    offset: u64,
    header_len: u64,
    payload_len: Option<u64>,
}

/// Read the next top-level box header at the reader's position. `Ok(None)` at
/// a clean end of file, or when fewer bytes than a header remain (a truncated
/// tail).
fn read_top_box<R: Read + Seek>(r: &mut R, file_len: u64) -> Result<Option<TopBox>> {
    let offset = r.stream_position()?;
    if file_len.saturating_sub(offset) < 8 {
        return Ok(None);
    }
    let mut h = [0u8; 8];
    r.read_exact(&mut h)?;
    let size32 = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    let kind = [h[4], h[5], h[6], h[7]];
    let (header_len, payload_len) = match size32 {
        0 => (8, None),
        1 => {
            if file_len.saturating_sub(offset) < 16 {
                return Ok(None);
            }
            let mut l = [0u8; 8];
            r.read_exact(&mut l)?;
            let total = u64::from_be_bytes(l);
            (
                16,
                Some(
                    total
                        .checked_sub(16)
                        .ok_or_else(|| anyhow!("mp4: bad large size"))?,
                ),
            )
        }
        n => (
            8,
            Some(
                u64::from(n)
                    .checked_sub(8)
                    .ok_or_else(|| anyhow!("mp4: bad size"))?,
            ),
        ),
    };
    Ok(Some(TopBox {
        kind,
        offset,
        header_len,
        payload_len,
    }))
}

fn read_box_bytes<R: Read + Seek>(r: &mut R, b: &TopBox) -> Result<Vec<u8>> {
    let len = b.payload_len.ok_or_else(|| anyhow!("mp4: unbounded box"))?;
    if len > 256 * 1024 * 1024 {
        bail!("mp4: box too large to read into memory ({len} bytes)");
    }
    r.seek(SeekFrom::Start(b.offset))?;
    let mut buf = vec![0u8; (b.header_len + len) as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Index a fragmented file written by [`FragmentedWriter`], stopping cleanly
/// at the first incomplete fragment.
pub fn read_fragmented(path: &Path) -> Result<FragmentedIndex> {
    let mut f = File::open(path).with_context(|| format!("mp4: open {}", path.display()))?;
    let file_len = f.metadata()?.len();
    let mut moov: Option<Moov> = None;
    let mut fragments = Vec::new();
    let mut truncated = false;
    let mut pending_moof: Option<(u64, Moof)> = None;
    loop {
        let Some(b) = read_top_box(&mut f, file_len)? else {
            if pending_moof.is_some() || f.stream_position()? < file_len {
                truncated = true;
            }
            break;
        };
        let end = b
            .payload_len
            .map(|l| b.offset + b.header_len + l)
            .unwrap_or(file_len);
        if end > file_len {
            // The box claims more bytes than the file has: a recorder died
            // while writing it. Everything before it is intact.
            truncated = true;
            break;
        }
        match &b.kind {
            b"moov" => {
                let bytes = read_box_bytes(&mut f, &b)?;
                moov = Some(Moov::decode(&mut Cursor::new(bytes.as_slice())).map_err(mp4_err)?);
            }
            b"moof" => {
                let bytes = read_box_bytes(&mut f, &b)?;
                match Moof::decode(&mut Cursor::new(bytes.as_slice())) {
                    Ok(m) => pending_moof = Some((b.offset, m)),
                    Err(_) => {
                        truncated = true;
                        break;
                    }
                }
            }
            b"mdat" => {
                let Some((moof_offset, moof)) = pending_moof.take() else {
                    bail!("mp4: mdat without a preceding moof");
                };
                let payload_offset = b.offset + b.header_len;
                let payload_len = end - payload_offset;
                let mut runs = Vec::new();
                for traf in &moof.traf {
                    for trun in &traf.trun {
                        let data_offset = trun
                            .data_offset
                            .ok_or_else(|| anyhow!("mp4: trun without data offset"))?;
                        let start = moof_offset
                            .checked_add_signed(i64::from(data_offset))
                            .ok_or_else(|| anyhow!("mp4: bad data offset"))?;
                        let offset_in_payload = start
                            .checked_sub(payload_offset)
                            .ok_or_else(|| anyhow!("mp4: data offset before mdat"))?;
                        let samples: Vec<SampleRecord> = trun
                            .entries
                            .iter()
                            .map(|e| SampleRecord {
                                duration: e.duration.unwrap_or(0),
                                size: e.size.unwrap_or(0),
                                sync: e.flags.map(|f| f & 0x0001_0000 == 0).unwrap_or(true),
                            })
                            .collect();
                        let run_len: u64 = samples.iter().map(|s| u64::from(s.size)).sum();
                        if offset_in_payload + run_len > payload_len {
                            bail!("mp4: a run overruns its mdat");
                        }
                        runs.push(TrackRun {
                            track_id: traf.tfhd.track_id,
                            offset_in_payload,
                            samples,
                        });
                    }
                }
                fragments.push(Fragment {
                    payload_offset,
                    payload_len,
                    runs,
                });
            }
            _ => {}
        }
        f.seek(SeekFrom::Start(end))?;
    }
    let moov = moov.ok_or_else(|| {
        anyhow!("mp4: no moov — not a recording, or it died before its first keyframe")
    })?;
    Ok(FragmentedIndex {
        moov,
        fragments,
        truncated,
    })
}

// ── the progressive remux ───────────────────────────────────────────────────

/// What [`finalize`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizeSummary {
    pub video_samples: u64,
    pub audio_samples: u64,
    pub duration_ms: u64,
    pub bytes: u64,
    /// The source ended inside a fragment; what was complete was kept.
    pub truncated: bool,
}

/// Remux the fragmented file at `partial` into a progressive, moov-first MP4
/// at `dest` (written to a temp name beside it, synced, then renamed —
/// never a half-written `dest`). The source is left in place; the caller
/// removes it once it has what it needs.
pub fn finalize(partial: &Path, dest: &Path) -> Result<FinalizeSummary> {
    let index = read_fragmented(partial)?;
    if index.fragments.is_empty() {
        bail!("mp4: {} holds no complete fragment", partial.display());
    }

    // Per-track sample tables, chunked one chunk per fragment run.
    let mut tracks: Vec<ProgressiveTrack> = index
        .moov
        .trak
        .iter()
        .map(|t| ProgressiveTrack::new(t.tkhd.track_id))
        .collect();
    let mut payload_cursor = 0u64; // offset within the new mdat payload
    for frag in &index.fragments {
        for run in &frag.runs {
            let Some(t) = tracks.iter_mut().find(|t| t.track_id == run.track_id) else {
                bail!("mp4: fragment names unknown track {}", run.track_id);
            };
            t.add_chunk(payload_cursor + run.offset_in_payload, &run.samples);
        }
        payload_cursor += frag.payload_len;
    }
    let payload_total = payload_cursor;
    let use_co64 = payload_total + (16 << 20) > u64::from(u32::MAX);

    // Pass 1: the moov with the right table shapes and zero offsets, to learn
    // its size; offsets are fixed-width, so pass 2 cannot change it.
    let ftyp = Ftyp {
        major_brand: b"isom".into(),
        minor_version: 0x200,
        compatible_brands: vec![
            b"isom".into(),
            b"iso2".into(),
            b"avc1".into(),
            b"mp41".into(),
        ],
    };
    let mut ftyp_buf = Vec::new();
    ftyp.encode(&mut ftyp_buf).map_err(mp4_err)?;
    let moov0 = progressive_moov(&index.moov, &tracks, 0, use_co64)?;
    let moov_len = encoded_len(&moov0)?;
    let mdat_header_len: u64 = if payload_total + 8 > u64::from(u32::MAX) {
        16
    } else {
        8
    };
    let payload_start = ftyp_buf.len() as u64 + moov_len + mdat_header_len;
    let moov = progressive_moov(&index.moov, &tracks, payload_start, use_co64)?;
    let mut moov_buf = Vec::new();
    moov.encode(&mut moov_buf).map_err(mp4_err)?;
    if moov_buf.len() as u64 != moov_len {
        bail!("mp4: moov size changed between passes");
    }

    let tmp = temp_beside(dest);
    let result = (|| -> Result<u64> {
        let out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("mp4: cannot create {}", tmp.display()))?;
        let mut w = BufWriter::with_capacity(1 << 20, out);
        w.write_all(&ftyp_buf)?;
        w.write_all(&moov_buf)?;
        let mut hdr = Vec::with_capacity(16);
        write_box_header(&mut hdr, b"mdat", payload_total);
        w.write_all(&hdr)?;
        let mut src = File::open(partial)?;
        let mut buf = vec![0u8; 1 << 20];
        for frag in &index.fragments {
            src.seek(SeekFrom::Start(frag.payload_offset))?;
            let mut left = frag.payload_len;
            while left > 0 {
                let n = (left.min(buf.len() as u64)) as usize;
                src.read_exact(&mut buf[..n])?;
                w.write_all(&buf[..n])?;
                left -= n as u64;
            }
        }
        w.flush()?;
        let total = w.get_ref().metadata()?.len();
        w.get_ref().sync_all()?;
        Ok(total)
    })();
    let bytes = match result {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.context("mp4: remux failed"));
        }
    };
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("mp4: rename {} → {}", tmp.display(), dest.display()))?;

    let video_ticks: u64 = tracks
        .iter()
        .find(|t| t.track_id == VIDEO_TRACK_ID)
        .map(|t| t.duration)
        .unwrap_or(0);
    Ok(FinalizeSummary {
        video_samples: tracks
            .iter()
            .find(|t| t.track_id == VIDEO_TRACK_ID)
            .map(|t| t.sizes.len() as u64)
            .unwrap_or(0),
        audio_samples: tracks
            .iter()
            .find(|t| t.track_id == AUDIO_TRACK_ID)
            .map(|t| t.sizes.len() as u64)
            .unwrap_or(0),
        duration_ms: ticks_to_ms(video_ticks, VIDEO_TIMESCALE),
        bytes,
        truncated: index.truncated,
    })
}

fn temp_beside(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".remux-tmp");
    dest.with_file_name(name)
}

#[derive(Debug, Default)]
struct ProgressiveTrack {
    track_id: u32,
    durations: Vec<u32>,
    sizes: Vec<u32>,
    sync: Vec<bool>,
    /// (offset within the new mdat payload, samples in the chunk)
    chunks: Vec<(u64, u32)>,
    duration: u64,
}

impl ProgressiveTrack {
    fn new(track_id: u32) -> Self {
        Self {
            track_id,
            ..Default::default()
        }
    }

    fn add_chunk(&mut self, offset_in_payload: u64, samples: &[SampleRecord]) {
        if samples.is_empty() {
            return;
        }
        self.chunks.push((offset_in_payload, samples.len() as u32));
        for s in samples {
            self.durations.push(s.duration);
            self.sizes.push(s.size);
            self.sync.push(s.sync);
            self.duration += u64::from(s.duration);
        }
    }

    fn tables(&self, payload_start: u64, use_co64: bool) -> StblTables {
        let mut stts: Vec<SttsEntry> = Vec::new();
        for &d in &self.durations {
            match stts.last_mut() {
                Some(e) if e.sample_delta == d => e.sample_count += 1,
                _ => stts.push(SttsEntry {
                    sample_count: 1,
                    sample_delta: d,
                }),
            }
        }
        let mut stsc: Vec<StscEntry> = Vec::new();
        for (i, &(_, n)) in self.chunks.iter().enumerate() {
            if stsc.last().map(|e| e.samples_per_chunk) != Some(n) {
                stsc.push(StscEntry {
                    first_chunk: i as u32 + 1,
                    samples_per_chunk: n,
                    sample_description_index: 1,
                });
            }
        }
        let all_sync = self.sync.iter().all(|&s| s);
        let stss = (!all_sync).then(|| Stss {
            entries: self
                .sync
                .iter()
                .enumerate()
                .filter(|(_, s)| **s)
                .map(|(i, _)| i as u32 + 1)
                .collect(),
        });
        let offsets = self.chunks.iter().map(|&(o, _)| payload_start + o);
        let (stco, co64) = if use_co64 {
            (
                None,
                Some(Co64 {
                    entries: offsets.collect(),
                }),
            )
        } else {
            (
                Some(Stco {
                    entries: offsets.map(|o| o as u32).collect(),
                }),
                None,
            )
        };
        let stsz = match self.sizes.first() {
            Some(&first) if self.sizes.iter().all(|&s| s == first) => Stsz {
                samples: StszSamples::Identical {
                    count: self.sizes.len() as u32,
                    size: first,
                },
            },
            _ => Stsz {
                samples: StszSamples::Different {
                    sizes: self.sizes.clone(),
                },
            },
        };
        StblTables {
            stts: Stts { entries: stts },
            stss,
            stsc: Stsc { entries: stsc },
            stsz,
            stco,
            co64,
        }
    }
}

/// Rebuild the fragmented file's `moov` as a progressive one: same tracks and
/// sample descriptions, full sample tables, no `mvex`.
fn progressive_moov(
    frag_moov: &Moov,
    tracks: &[ProgressiveTrack],
    payload_start: u64,
    use_co64: bool,
) -> Result<Moov> {
    let mut moov = frag_moov.clone();
    moov.mvex = None;
    let mut movie_ms = 0u64;
    for trak in &mut moov.trak {
        let id = trak.tkhd.track_id;
        let t = tracks
            .iter()
            .find(|t| t.track_id == id)
            .ok_or_else(|| anyhow!("mp4: no samples indexed for track {id}"))?;
        let tables = t.tables(payload_start, use_co64);
        let timescale = trak.mdia.mdhd.timescale;
        trak.mdia.mdhd.duration = t.duration;
        let ms = ticks_to_ms(t.duration, timescale);
        trak.tkhd.duration = ms;
        movie_ms = movie_ms.max(ms);
        let stbl = &mut trak.mdia.minf.stbl;
        stbl.stts = tables.stts;
        stbl.stss = tables.stss;
        stbl.stsc = tables.stsc;
        stbl.stsz = tables.stsz;
        stbl.stco = tables.stco;
        stbl.co64 = tables.co64;
    }
    moov.mvhd.duration = movie_ms;
    Ok(moov)
}

// ── reading progressive files (tests; the P5 export engine) ─────────────────

/// FR-85 P5 — a recording's video, as an export sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoFormat {
    pub width: u32,
    pub height: u32,
    /// `avcC`'s profile: 66 Baseline (what openh264 writes), 77 Main, 100
    /// High (what the hardware encoders write).
    pub profile: u8,
    /// The track's media timescale ([`VIDEO_TIMESCALE`] for a recording).
    pub timescale: u32,
}

/// FR-85 P5b — a recording's audio, as an export sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFormat {
    pub channels: u16,
    pub timescale: u32,
    /// Opus with the `pre_skip` (48 kHz samples) a decoder drops from the
    /// start, or AAC with its AudioSpecificConfig (P4).
    pub codec: AudioCodec,
}

/// One sample of a progressive file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressiveSample {
    pub offset: u64,
    pub size: u32,
    /// Decode time in the track's timescale.
    pub dts: u64,
    pub duration: u32,
    pub sync: bool,
}

/// A progressive MP4, indexed.
#[derive(Debug, Clone)]
pub struct ProgressiveFile {
    pub moov: Moov,
    /// Absolute offset of the `moov` box and of the `mdat` box.
    pub moov_offset: u64,
    pub mdat_offset: u64,
}

impl ProgressiveFile {
    pub fn open(path: &Path) -> Result<Self> {
        let mut f = File::open(path).with_context(|| format!("mp4: open {}", path.display()))?;
        let file_len = f.metadata()?.len();
        let (mut moov, mut moov_offset, mut mdat_offset) = (None, None, None);
        while let Some(b) = read_top_box(&mut f, file_len)? {
            let end = b
                .payload_len
                .map(|l| b.offset + b.header_len + l)
                .unwrap_or(file_len);
            match &b.kind {
                b"moov" => {
                    let bytes = read_box_bytes(&mut f, &b)?;
                    moov = Some(Moov::decode(&mut Cursor::new(bytes.as_slice())).map_err(mp4_err)?);
                    moov_offset = Some(b.offset);
                }
                b"mdat" => mdat_offset = mdat_offset.or(Some(b.offset)),
                _ => {}
            }
            if end > file_len {
                bail!("mp4: truncated box");
            }
            f.seek(SeekFrom::Start(end))?;
        }
        Ok(Self {
            moov: moov.ok_or_else(|| anyhow!("mp4: no moov"))?,
            moov_offset: moov_offset.unwrap_or(0),
            mdat_offset: mdat_offset.ok_or_else(|| anyhow!("mp4: no mdat"))?,
        })
    }

    /// Every sample of `track_id`, in decode order.
    pub fn samples(&self, track_id: u32) -> Result<Vec<ProgressiveSample>> {
        let trak = self
            .moov
            .trak
            .iter()
            .find(|t| t.tkhd.track_id == track_id)
            .ok_or_else(|| anyhow!("mp4: no track {track_id}"))?;
        let stbl = &trak.mdia.minf.stbl;
        let sizes: Vec<u32> = match &stbl.stsz.samples {
            StszSamples::Identical { count, size } => vec![*size; *count as usize],
            StszSamples::Different { sizes } => sizes.clone(),
        };
        let mut durations = Vec::with_capacity(sizes.len());
        for e in &stbl.stts.entries {
            durations.extend(std::iter::repeat_n(e.sample_delta, e.sample_count as usize));
        }
        let chunk_offsets: Vec<u64> = match (&stbl.stco, &stbl.co64) {
            (Some(s), _) => s.entries.iter().map(|&o| u64::from(o)).collect(),
            (None, Some(c)) => c.entries.clone(),
            (None, None) => bail!("mp4: no chunk offsets"),
        };
        let sync_set: Option<std::collections::HashSet<u32>> = stbl
            .stss
            .as_ref()
            .map(|s| s.entries.iter().copied().collect());
        let mut out = Vec::with_capacity(sizes.len());
        let mut sample = 0usize;
        let mut dts = 0u64;
        for (ci, &chunk_offset) in chunk_offsets.iter().enumerate() {
            let chunk_no = ci as u32 + 1;
            let per = stbl
                .stsc
                .entries
                .iter()
                .rev()
                .find(|e| e.first_chunk <= chunk_no)
                .map(|e| e.samples_per_chunk)
                .ok_or_else(|| anyhow!("mp4: stsc does not cover chunk {chunk_no}"))?;
            let mut offset = chunk_offset;
            for _ in 0..per {
                let size = *sizes
                    .get(sample)
                    .ok_or_else(|| anyhow!("mp4: stsz too short"))?;
                let duration = durations.get(sample).copied().unwrap_or(0);
                out.push(ProgressiveSample {
                    offset,
                    size,
                    dts,
                    duration,
                    sync: sync_set
                        .as_ref()
                        .map(|s| s.contains(&(sample as u32 + 1)))
                        .unwrap_or(true),
                });
                offset += u64::from(size);
                dts += u64::from(duration);
                sample += 1;
            }
        }
        if sample != sizes.len() {
            bail!("mp4: chunk map covers {sample} of {} samples", sizes.len());
        }
        Ok(out)
    }

    /// The video track's `avc1` sample entry and its media timescale.
    fn video_avc1(&self) -> Result<(&Avc1, u32)> {
        let trak = self
            .moov
            .trak
            .iter()
            .find(|t| t.tkhd.track_id == VIDEO_TRACK_ID)
            .ok_or_else(|| anyhow!("mp4: no video track"))?;
        let codec = trak
            .mdia
            .minf
            .stbl
            .stsd
            .codecs
            .first()
            .ok_or_else(|| anyhow!("mp4: empty stsd"))?;
        let Codec::Avc1(avc1) = codec else {
            bail!("mp4: video track is not avc1");
        };
        Ok((avc1, trak.mdia.mdhd.timescale))
    }

    /// FR-85 P5b — the audio track, when the recording has one: its channel
    /// count and codec (Opus with the `pre_skip` a decoder must drop from the
    /// start, or — P4 — AAC with its AudioSpecificConfig).
    /// `None` = no audio track (recordings are silent unless asked).
    pub fn audio_format(&self) -> Result<Option<AudioFormat>> {
        let Some(trak) = self
            .moov
            .trak
            .iter()
            .find(|t| t.tkhd.track_id == AUDIO_TRACK_ID)
        else {
            return Ok(None);
        };
        let timescale = trak.mdia.mdhd.timescale;
        match trak.mdia.minf.stbl.stsd.codecs.first() {
            Some(Codec::Opus(opus)) => Ok(Some(AudioFormat {
                channels: opus.audio.channel_count,
                timescale,
                codec: AudioCodec::Opus {
                    pre_skip: opus.dops.pre_skip,
                },
            })),
            Some(Codec::Mp4a(m)) => {
                let config = &m.esds.es_desc.dec_config;
                if config.object_type_indication != OTI_MPEG4_AUDIO {
                    bail!(
                        "mp4: the audio track is MPEG object type {:#04x}, not AAC",
                        config.object_type_indication
                    );
                }
                let Some(ds) = &config.dec_specific else {
                    bail!("mp4: the AAC track carries no AudioSpecificConfig");
                };
                let asc = if ds.raw.is_empty() {
                    // A hand-built config: the fields are all there is.
                    vec![
                        (ds.profile << 3) | (ds.freq_index >> 1),
                        ((ds.freq_index & 1) << 7) | (ds.chan_conf << 3),
                    ]
                } else {
                    ds.raw.clone()
                };
                Ok(Some(AudioFormat {
                    channels: m.audio.channel_count,
                    timescale,
                    codec: AudioCodec::Aac {
                        asc,
                        bitrate: config.avg_bitrate,
                    },
                }))
            }
            Some(_) => bail!("mp4: the audio track is neither Opus nor AAC"),
            None => bail!("mp4: the audio track has an empty stsd"),
        }
    }

    /// FR-85 P5 — what an export needs to know before it decodes a sample.
    pub fn video_format(&self) -> Result<VideoFormat> {
        let (avc1, timescale) = self.video_avc1()?;
        if timescale == 0 {
            bail!("mp4: the video track has no timescale");
        }
        Ok(VideoFormat {
            width: u32::from(avc1.visual.width),
            height: u32::from(avc1.visual.height),
            profile: avc1.avcc.avc_profile_indication,
            timescale,
        })
    }

    /// The `avcC` parameter sets of the video track, as Annex-B, ready to be
    /// prepended to the first keyframe for a start-code decoder.
    pub fn avc_parameter_sets_annexb(&self) -> Result<Vec<u8>> {
        let (avc1, _) = self.video_avc1()?;
        let mut out = Vec::new();
        for ps in avc1
            .avcc
            .sequence_parameter_sets
            .iter()
            .chain(avc1.avcc.picture_parameter_sets.iter())
        {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(ps);
        }
        Ok(out)
    }

    /// Read one sample's bytes.
    pub fn read_sample(&self, f: &mut File, s: &ProgressiveSample) -> Result<Vec<u8>> {
        f.seek(SeekFrom::Start(s.offset))?;
        let mut buf = vec![0u8; s.size as usize];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::annexb::length_prefixed_to_annexb;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("roomler-fr85-mp4-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SPS: [u8; 4] = [0x67, 0x42, 0xc0, 0x1f];
    const PPS: [u8; 2] = [0x68, 0xce];

    /// A fake access unit: an IDR carries SPS+PPS; the payload encodes `n`
    /// so a remux that reorders or drops samples is caught.
    ///
    /// ⚠️ Seven bits per byte with the top bit set, so the payload never
    /// holds a zero byte: real H.264 cannot contain `00 00 01` inside a NAL
    /// (emulation prevention) nor end one on `00`, and a fixture that does is
    /// testing the splitter against a stream no encoder produces. The first
    /// version of this fixture wrote `n` raw and "failed" on exactly that.
    fn au(n: u32, idr: bool) -> Vec<u8> {
        let mut v = Vec::new();
        if idr {
            v.extend_from_slice(&[0, 0, 0, 1]);
            v.extend_from_slice(&SPS);
            v.extend_from_slice(&[0, 0, 0, 1]);
            v.extend_from_slice(&PPS);
        }
        v.extend_from_slice(&[0, 0, 0, 1, if idr { 0x65 } else { 0x41 }]);
        v.extend_from_slice(&encode_n(n));
        v
    }

    fn encode_n(n: u32) -> [u8; 3] {
        [
            0x80 | ((n >> 14) & 0x7F) as u8,
            0x80 | ((n >> 7) & 0x7F) as u8,
            0x80 | (n & 0x7F) as u8,
        ]
    }

    fn decode_n(b: &[u8]) -> u32 {
        (u32::from(b[0] & 0x7F) << 14) | (u32::from(b[1] & 0x7F) << 7) | u32::from(b[2] & 0x7F)
    }

    fn video() -> VideoTrack {
        VideoTrack {
            width: 320,
            height: 240,
            fps: 30,
            color: ColorInfo::BT601_LIMITED,
        }
    }

    /// Write `n` frames at 30 fps with a keyframe every `gop`.
    fn write_frames(path: &Path, n: u32, gop: u32) -> WriterStats {
        let mut w = FragmentedWriter::create(path, video(), None).unwrap();
        for i in 0..n {
            let pts = u64::from(i) * 3000;
            let o = w.push_video(pts, &au(i, i % gop == 0), false).unwrap();
            assert_eq!(o, PushOutcome::Written);
        }
        w.finish().unwrap()
    }

    #[test]
    fn a_fragment_starts_on_every_keyframe() {
        let dir = scratch("frag");
        let p = dir.join("r.mp4.partial");
        let stats = write_frames(&p, 150, 60);
        assert_eq!(stats.video_samples, 150);
        assert_eq!(stats.fragments, 3, "keyframes at 0, 60 and 120");
        let idx = read_fragmented(&p).unwrap();
        assert!(!idx.truncated);
        let s = idx.samples(VIDEO_TRACK_ID);
        assert_eq!(s.len(), 150);
        assert!(s.iter().all(|x| x.duration == 3000));
        let syncs: Vec<usize> = s
            .iter()
            .enumerate()
            .filter(|(_, x)| x.sync)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(syncs, vec![0, 60, 120]);
    }

    #[test]
    fn nothing_before_the_first_keyframe_is_written() {
        let dir = scratch("pre-idr");
        let p = dir.join("r.mp4.partial");
        let mut w = FragmentedWriter::create(&p, video(), None).unwrap();
        assert_eq!(
            w.push_video(0, &au(0, false), false).unwrap(),
            PushOutcome::DroppedBeforeKeyframe
        );
        assert_eq!(
            w.push_video(3000, &au(1, true), false).unwrap(),
            PushOutcome::Written
        );
        w.push_video(6000, &au(2, false), false).unwrap();
        let st = w.finish().unwrap();
        assert_eq!(st.video_samples, 2);
    }

    #[test]
    fn non_increasing_pts_is_refused() {
        let dir = scratch("pts");
        let p = dir.join("r.mp4.partial");
        let mut w = FragmentedWriter::create(&p, video(), None).unwrap();
        w.push_video(3000, &au(0, true), false).unwrap();
        assert!(w.push_video(3000, &au(1, false), false).is_err());
    }

    #[test]
    fn changed_parameter_sets_mid_recording_are_refused() {
        let dir = scratch("sps");
        let p = dir.join("r.mp4.partial");
        let mut w = FragmentedWriter::create(&p, video(), None).unwrap();
        w.push_video(0, &au(0, true), false).unwrap();
        let mut other = vec![0, 0, 0, 1, 0x67, 0x64, 0x00, 0x28];
        other.extend_from_slice(&au(1, false));
        assert!(w.push_video(3000, &other, false).is_err());
    }

    #[test]
    fn the_file_is_never_overwritten() {
        let dir = scratch("excl");
        let p = dir.join("r.mp4.partial");
        std::fs::write(&p, b"precious").unwrap();
        assert!(FragmentedWriter::create(&p, video(), None).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"precious");
    }

    #[test]
    fn remux_keeps_every_sample_in_order_with_moov_first() {
        let dir = scratch("remux");
        let partial = dir.join("r.mp4.partial");
        write_frames(&partial, 150, 60);
        let dest = dir.join("r.mp4");
        let sum = finalize(&partial, &dest).unwrap();
        assert_eq!(sum.video_samples, 150);
        assert_eq!(sum.duration_ms, 5000);
        assert!(!sum.truncated);

        let pf = ProgressiveFile::open(&dest).unwrap();
        assert!(
            pf.moov_offset < pf.mdat_offset,
            "moov must precede mdat (faststart)"
        );
        let samples = pf.samples(VIDEO_TRACK_ID).unwrap();
        assert_eq!(samples.len(), 150);
        let mut f = File::open(&dest).unwrap();
        for (i, s) in samples.iter().enumerate() {
            assert_eq!(s.dts, i as u64 * 3000);
            assert_eq!(s.sync, i % 60 == 0);
            let bytes = pf.read_sample(&mut f, s).unwrap();
            let annexb = length_prefixed_to_annexb(&bytes).unwrap();
            // The payload's last three bytes are the frame number.
            let n = decode_n(&annexb[annexb.len() - 3..]);
            assert_eq!(n, i as u32, "sample {i} carries the wrong frame");
        }
        assert_eq!(
            pf.avc_parameter_sets_annexb().unwrap(),
            [&[0, 0, 0, 1][..], &SPS, &[0, 0, 0, 1], &PPS].concat()
        );
        // No temp file is left behind.
        assert!(!dir.join("r.mp4.remux-tmp").exists());
    }

    #[test]
    fn a_truncated_recording_keeps_every_complete_fragment() {
        let dir = scratch("trunc");
        let partial = dir.join("r.mp4.partial");
        write_frames(&partial, 150, 60);
        // Chop the file in the middle of its last fragment, as a recorder
        // killed mid-write would leave it.
        let len = std::fs::metadata(&partial).unwrap().len();
        let f = OpenOptions::new().write(true).open(&partial).unwrap();
        f.set_len(len - 40).unwrap();
        drop(f);
        let idx = read_fragmented(&partial).unwrap();
        assert!(idx.truncated);
        assert_eq!(idx.fragment_count(), 2);
        let dest = dir.join("r.mp4");
        let sum = finalize(&partial, &dest).unwrap();
        assert!(sum.truncated);
        assert_eq!(sum.video_samples, 120, "the two complete GOPs survive");
        let pf = ProgressiveFile::open(&dest).unwrap();
        assert_eq!(pf.samples(VIDEO_TRACK_ID).unwrap().len(), 120);
    }

    #[test]
    fn a_recording_with_no_complete_fragment_is_refused_not_faked() {
        let dir = scratch("empty");
        let partial = dir.join("r.mp4.partial");
        let mut w = FragmentedWriter::create(&partial, video(), None).unwrap();
        w.push_video(0, &au(0, true), false).unwrap();
        // Drop without finish: only ftyp+moov reached the file.
        drop(w);
        assert!(finalize(&partial, &dir.join("r.mp4")).is_err());
    }

    #[test]
    fn audio_rides_in_the_same_fragments_and_survives_the_remux() {
        let dir = scratch("audio");
        let partial = dir.join("r.mp4.partial");
        let audio = AudioTrack {
            sample_rate: 48_000,
            channels: 2,
            codec: AudioCodec::Opus { pre_skip: 312 },
        };
        let mut w = FragmentedWriter::create(&partial, video(), Some(audio)).unwrap();
        for i in 0..90u32 {
            w.push_video(u64::from(i) * 3000, &au(i, i % 30 == 0), false)
                .unwrap();
            // 20 ms Opus packets: 5 per 3 video frames at 30 fps.
            if i % 3 == 0 {
                for k in 0..5u8 {
                    w.push_audio(&[0xF8, k, i as u8], 960).unwrap();
                }
            }
        }
        let st = w.finish().unwrap();
        assert_eq!(st.audio_samples, 150);
        let dest = dir.join("r.mp4");
        let sum = finalize(&partial, &dest).unwrap();
        assert_eq!(sum.audio_samples, 150);
        let pf = ProgressiveFile::open(&dest).unwrap();
        let a = pf.samples(AUDIO_TRACK_ID).unwrap();
        assert_eq!(a.len(), 150);
        assert!(a.iter().all(|s| s.duration == 960 && s.sync));
        let mut f = File::open(&dest).unwrap();
        assert_eq!(pf.read_sample(&mut f, &a[149]).unwrap(), vec![0xF8, 4, 87]);
        assert_eq!(pf.samples(VIDEO_TRACK_ID).unwrap().len(), 90);
    }

    /// FR-85 P4 — an AAC track survives the crash-safe file AND the remux
    /// with its AudioSpecificConfig intact: the one field a decoder cannot
    /// start without.
    #[test]
    fn an_aac_track_keeps_its_config_through_the_remux() {
        let dir = scratch("aac");
        let partial = dir.join("r.mp4.partial");
        let asc = aac_lc_asc(48_000, 2).unwrap();
        let audio = AudioTrack {
            sample_rate: 48_000,
            channels: 2,
            codec: AudioCodec::Aac {
                asc: asc.clone(),
                bitrate: 192_000,
            },
        };
        let mut w = FragmentedWriter::create(&partial, video(), Some(audio)).unwrap();
        // 1024-sample AAC frames: 45 per second against 30 video frames.
        let mut pushed = 0u64;
        for i in 0..90u32 {
            w.push_video(u64::from(i) * 3000, &au(i, i % 30 == 0), false)
                .unwrap();
            while pushed * 1024 < u64::from(i + 1) * 1600 {
                w.push_audio(&[0x21, pushed as u8], 1024).unwrap();
                pushed += 1;
            }
        }
        w.finish().unwrap();
        let dest = dir.join("r.mp4");
        let sum = finalize(&partial, &dest).unwrap();
        assert_eq!(sum.audio_samples, pushed);
        let pf = ProgressiveFile::open(&dest).unwrap();
        let format = pf.audio_format().unwrap().expect("an audio track");
        assert_eq!(format.channels, 2);
        assert_eq!(format.timescale, 48_000);
        assert_eq!(
            format.codec,
            AudioCodec::Aac {
                asc,
                bitrate: 192_000
            }
        );
        let a = pf.samples(AUDIO_TRACK_ID).unwrap();
        assert!(a.iter().all(|s| s.duration == 1024 && s.sync));
        let mut f = File::open(&dest).unwrap();
        assert_eq!(
            pf.read_sample(&mut f, &a[a.len() - 1]).unwrap(),
            vec![0x21, (pushed - 1) as u8]
        );
    }

    /// The negative control of the round trip: an Opus track reads back as
    /// Opus, never as AAC (the reader dispatches on the sample entry).
    #[test]
    fn an_opus_track_reads_back_as_opus() {
        let dir = scratch("opus-read");
        let partial = dir.join("r.mp4.partial");
        let audio = AudioTrack {
            sample_rate: 48_000,
            channels: 2,
            codec: AudioCodec::Opus { pre_skip: 312 },
        };
        let mut w = FragmentedWriter::create(&partial, video(), Some(audio)).unwrap();
        for i in 0..31u32 {
            w.push_video(u64::from(i) * 3000, &au(i, i % 30 == 0), false)
                .unwrap();
            w.push_audio(&[0xF8, i as u8], 960).unwrap();
        }
        w.finish().unwrap();
        let dest = dir.join("r.mp4");
        finalize(&partial, &dest).unwrap();
        let format = ProgressiveFile::open(&dest)
            .unwrap()
            .audio_format()
            .unwrap()
            .unwrap();
        assert_eq!(format.codec, AudioCodec::Opus { pre_skip: 312 });
    }

    #[test]
    fn the_audio_specific_config_is_the_standard_two_bytes() {
        // ISO/IEC 14496-3: AAC-LC (2), 48 kHz (index 3), stereo (2) — the
        // bytes FFmpeg's encoder and every muxer write.
        assert_eq!(aac_lc_asc(48_000, 2), Some(vec![0x11, 0x90]));
        assert_eq!(aac_lc_asc(44_100, 1), Some(vec![0x12, 0x08]));
        assert_eq!(asc_fields(&[0x11, 0x90]), (2, 3, 2));
        assert_eq!(aac_lc_asc(47_999, 2), None, "not a table rate");
        assert_eq!(aac_lc_asc(48_000, 0), None);
        assert_eq!(aac_lc_asc(48_000, 8), None);
    }

    #[test]
    fn ticks_convert_to_milliseconds_with_rounding() {
        assert_eq!(ticks_to_ms(90_000, VIDEO_TIMESCALE), 1000);
        assert_eq!(ticks_to_ms(3000, VIDEO_TIMESCALE), 33);
        assert_eq!(ticks_to_ms(48_000, 48_000), 1000);
        assert_eq!(ticks_to_ms(5, 0), 0);
    }
}
