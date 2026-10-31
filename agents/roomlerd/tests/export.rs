// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P5a — the export engine, end to end: a recording whose every frame
//! paints its own index, an edit list, an export, and the frames that come
//! back out of a decoder are exactly the ones the edit list says. P5b, with
//! `audio` (`mod sound`): the same for the sound, second by second.
//!
//! ⚠️ This binary runs only when CI NAMES it (`--test export`), and `mod
//! sound` only in the run that also names `audio`.
//!
//! The oracle is the recorder tests' counter: 16 luma blocks of 16×16 px per
//! frame, black or white, big enough to survive H.264 at any sane QP. It is
//! proven to discriminate here too: the same comparison against the unedited
//! source fails.

#![cfg(all(feature = "recording", feature = "openh264-encoder"))]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use roomlerd::capture::{Damage, Frame, PixelFormat};
use roomlerd::encode::VideoEncoder;
use roomlerd::encode::openh264_backend::Openh264Encoder;
use roomlerd::recording::annexb::length_prefixed_to_annexb;
use roomlerd::recording::edit::{Action, EditList, Segment, VERSION};
use roomlerd::recording::export::{self, ExportError};
use roomlerd::recording::mp4::{
    self, ColorInfo, FragmentedWriter, ProgressiveFile, VIDEO_TRACK_ID, VideoTrack,
};

const W: u32 = 320;
const H: u32 = 240;
const BLOCK: u32 = 16;
const BITS: u32 = 16;
const FPS: u32 = 30;
const TICK: u64 = 3000; // one frame at 30 fps, 90 kHz

fn render(counter: u16) -> Vec<u8> {
    let mut data = vec![0x80u8; (W * H * 4) as usize];
    for bit in 0..BITS {
        let on = (counter >> (BITS - 1 - bit)) & 1 == 1;
        let v = if on { 0xFF } else { 0x00 };
        for y in 0..BLOCK {
            for x in bit * BLOCK..(bit + 1) * BLOCK {
                let i = ((y * W + x) * 4) as usize;
                data[i..i + 3].copy_from_slice(&[v, v, v]);
                data[i + 3] = 0xFF;
            }
        }
    }
    data
}

fn read_counter(y_plane: &[u8], stride: usize) -> u16 {
    let mut v = 0u16;
    for bit in 0..BITS as usize {
        let mut sum = 0u32;
        for dy in 4..12usize {
            for dx in 4..12usize {
                sum += u32::from(y_plane[dy * stride + bit * BLOCK as usize + dx]);
            }
        }
        v = (v << 1) | u16::from(sum / 64 > 128);
    }
    v
}

fn software() -> roomlerd::recording::recorder::EncoderFactory {
    Box::new(|w, h| {
        let e = Openh264Encoder::new_recording(w, h, FPS, FPS * 2)?;
        Ok(Box::new(e) as Box<dyn VideoEncoder>)
    })
}

/// A progressive recording of `frames` frames at 30 fps in which frame `i`
/// paints `i`, through the recording encoder and writer the recorder uses —
/// deterministic, so frame i of the file IS counter i.
async fn make_source(path: &Path, frames: u16) {
    let partial = path.with_extension("partial");
    let mut enc = Openh264Encoder::new_recording(W, H, FPS, FPS * 2).unwrap();
    let mut w = FragmentedWriter::create(
        &partial,
        VideoTrack {
            width: W,
            height: H,
            fps: FPS,
            color: ColorInfo::BT601_LIMITED,
        },
        None,
    )
    .unwrap();
    for i in 0..frames {
        let f = Arc::new(Frame {
            width: W,
            height: H,
            stride: W * 4,
            pixel_format: PixelFormat::Bgra,
            data: render(i),
            monotonic_us: 0,
            monitor: 0,
            damage: Damage::Unknown,
            source: None,
        });
        let packets = enc.encode(f).await.unwrap();
        let key = packets.iter().any(|p| p.is_keyframe);
        let au: Vec<u8> = packets.into_iter().flat_map(|p| p.data).collect();
        w.push_video(u64::from(i) * TICK, &au, key).unwrap();
    }
    w.finish().unwrap();
    mp4::finalize(&partial, path).unwrap();
    std::fs::remove_file(&partial).unwrap();
}

/// Every frame of a progressive file, decoded, as its counter.
fn counters(path: &Path) -> Vec<u16> {
    use openh264::formats::YUVSource;
    let pf = ProgressiveFile::open(path).expect("open");
    assert!(pf.moov_offset < pf.mdat_offset, "moov must precede mdat");
    let samples = pf.samples(VIDEO_TRACK_ID).expect("samples");
    let ps = pf.avc_parameter_sets_annexb().expect("avcC");
    let mut dec = openh264::decoder::Decoder::new().expect("decoder");
    let mut f = std::fs::File::open(path).unwrap();
    let mut out = Vec::new();
    for s in &samples {
        let raw = pf.read_sample(&mut f, s).unwrap();
        let mut au = Vec::new();
        if s.sync {
            au.extend_from_slice(&ps);
        }
        au.extend_from_slice(&length_prefixed_to_annexb(&raw).unwrap());
        let pic = dec.decode(&au).unwrap().expect("a picture per sample");
        let (y_stride, _, _) = pic.strides();
        out.push(read_counter(pic.y(), y_stride));
    }
    out
}

fn edit_list(segments: Vec<Segment>) -> EditList {
    EditList {
        version: VERSION,
        source: "source.mp4".into(),
        segments,
        original_volume: None,
        music: None,
    }
}

fn seg(start_ms: u64, end_ms: u64, action: Action) -> Segment {
    Segment {
        start_ms,
        end_ms,
        action,
    }
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// The plan's own oracle: keep 0–2 s, cut 2–4 s, 4× on 4–8 s, keep 8–10 s
/// of a 10 s recording is exactly frames 0..59, 120, 124 … 236, 240..299 —
/// five seconds, moov first, and the recording itself untouched.
#[tokio::test]
async fn an_export_shows_exactly_the_frames_its_edit_list_says() {
    let d = dir();
    let source = d.path().join("source.mp4");
    make_source(&source, 300).await;
    let before = std::fs::read(&source).unwrap();

    let edits = edit_list(vec![
        seg(0, 2000, Action::Keep),
        seg(2000, 4000, Action::Cut),
        seg(4000, 8000, Action::Speed { speed: 4.0 }),
        seg(8000, 10_000, Action::Keep),
    ]);
    let dest = export::edited_name(&source).unwrap();
    let mut seen = Vec::new();
    let s = export::export(
        &source,
        &edits,
        &dest,
        software(),
        &AtomicBool::new(false),
        |done, total| seen.push((done, total)),
    )
    .await
    .unwrap();

    let expected: Vec<u16> = (0..60)
        .chain((0..30).map(|k| 120 + 4 * k))
        .chain(240..300)
        .collect();
    let got = counters(&dest);
    assert_eq!(got, expected);
    assert_eq!(s.frames, 150);
    assert!(
        (4966..=5034).contains(&s.duration_ms),
        "five seconds ± a frame: {s:?}"
    );
    assert_eq!(seen.last(), Some(&(150, 150)), "progress reaches the end");
    assert_eq!(
        std::fs::read(&source).unwrap(),
        before,
        "the recording is never written"
    );
    assert!(
        !d.path()
            .join(".roomler-partial")
            .join(format!(
                "{}.partial",
                dest.file_name().unwrap().to_string_lossy()
            ))
            .exists(),
        "nothing staged is left behind"
    );

    // The oracle discriminates: the unedited source is NOT that sequence.
    let source_frames = counters(&source);
    assert_eq!(source_frames, (0..300).collect::<Vec<u16>>());
    assert_ne!(source_frames, expected);
}

/// The control for the engine itself: keeping everything reproduces the
/// source frame for frame — so the edit, not the engine, made the difference.
#[tokio::test]
async fn keeping_everything_reproduces_the_recording() {
    let d = dir();
    let source = d.path().join("source.mp4");
    make_source(&source, 90).await;
    let dest = export::edited_name(&source).unwrap();
    let s = export::export(
        &source,
        &edit_list(vec![seg(0, 3000, Action::Keep)]),
        &dest,
        software(),
        &AtomicBool::new(false),
        |_, _| {},
    )
    .await
    .unwrap();
    assert_eq!(s.frames, 90);
    assert_eq!(counters(&dest), (0..90).collect::<Vec<u16>>());
}

#[tokio::test]
async fn a_cancelled_or_impossible_export_leaves_nothing_behind() {
    let d = dir();
    let source = d.path().join("source.mp4");
    make_source(&source, 60).await;
    let dest = export::edited_name(&source).unwrap();

    let cancelled = export::export(
        &source,
        &edit_list(vec![seg(0, 2000, Action::Keep)]),
        &dest,
        software(),
        &AtomicBool::new(true),
        |_, _| {},
    )
    .await;
    assert!(
        matches!(cancelled, Err(ExportError::Cancelled)),
        "{cancelled:?}"
    );

    let nothing = export::export(
        &source,
        &edit_list(vec![seg(0, 2000, Action::Cut)]),
        &dest,
        software(),
        &AtomicBool::new(false),
        |_, _| {},
    )
    .await;
    let e = nothing.unwrap_err();
    assert_eq!(e.code(), "bad_edit_list");
    assert!(e.detail().contains("nothing to export"), "{}", e.detail());

    assert!(!dest.exists(), "no export file");
    let staged: Vec<PathBuf> = std::fs::read_dir(d.path().join(".roomler-partial"))
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(staged.is_empty(), "nothing staged left: {staged:?}");
}

/// The process roomler-desktop runs: `roomlerd media probe` says the
/// recording is editable, and `roomlerd media export` writes the file and
/// says so, with what its sound carries (nothing: the recording is silent).
#[tokio::test]
async fn the_media_process_probes_and_exports() {
    use roomlerd::recording::child::parse_event_line;
    let d = dir();
    let source = d.path().join("source.mp4");
    make_source(&source, 60).await;
    let edl = d.path().join("source.mp4.edit.json");
    std::fs::write(
        &edl,
        serde_json::to_string(&edit_list(vec![
            seg(0, 1000, Action::Cut),
            seg(1000, 2000, Action::Speed { speed: 2.0 }),
        ]))
        .unwrap(),
    )
    .unwrap();

    let exe = env!("CARGO_BIN_EXE_meshharbord");
    let run = |args: &[&str]| {
        let out = std::process::Command::new(exe)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(parse_event_line)
            .collect::<Vec<_>>()
    };

    let probe = run(&["media", "probe", source.to_str().unwrap()]);
    let p = probe
        .iter()
        .find(|e| e["ev"] == "probe")
        .expect("a probe event");
    assert_eq!(p["editable"], true, "{p}");
    assert_eq!(p["duration_ms"], 2000, "{p}");
    assert_eq!(p["width"], W, "{p}");

    let events = run(&[
        "media",
        "export",
        "--edl",
        edl.to_str().unwrap(),
        "--encoder",
        "software",
    ]);
    let done = events
        .iter()
        .find(|e| e["ev"] == "done")
        .unwrap_or_else(|| panic!("no done event: {events:?}"));
    assert_eq!(done["frames"], 15, "{done}");
    // The recording is silent and there is no music: no sound, said so.
    assert_eq!(done["audio"], "none", "{done}");
    let path = PathBuf::from(done["path"].as_str().unwrap());
    assert!(path.ends_with("source (edited).mp4"), "{}", path.display());
    // Cut the first second, then 2× over the second: frames 30, 32 … 58.
    assert_eq!(
        counters(&path),
        (0..15).map(|k| 30 + 2 * k).collect::<Vec<u16>>()
    );

    // A list naming a file outside its folder is refused before anything
    // is read.
    std::fs::write(
        &edl,
        r#"{"version":1,"source":"../elsewhere.mp4","segments":[{"start_ms":0,"end_ms":1000,"action":"keep"}]}"#,
    )
    .unwrap();
    let refused = run(&["media", "export", "--edl", edl.to_str().unwrap()]);
    let r = refused
        .iter()
        .find(|e| e["ev"] == "refused")
        .expect("refused");
    assert_eq!(r["code"], "bad_edit_list", "{r}");
}

// ── FR-85 P4 — a hardware encoder's recording ───────────────────────────────

/// Recordings a hardware encoder made, committed: 90 frames (3 s) of the
/// counter pattern each, encoded by `h264_nvenc` with no B-frames and a 2 s
/// GOP (the recording profile's shape), written by the recorder's own writer
/// — once in High profile (the default 4:2:0) and once in High 4:4:4 (the
/// opt-in chroma). `make_the_hardware_fixtures` regenerates them.
struct Fixture {
    name: &'static str,
    pix_fmt: &'static str,
    profile_arg: &'static str,
    profile: u8,
}

const FIXTURES: [Fixture; 2] = [
    Fixture {
        name: "export-high-profile.mp4",
        pix_fmt: "yuv420p",
        profile_arg: "high",
        profile: 100,
    },
    Fixture {
        name: "export-high444-profile.mp4",
        pix_fmt: "yuv444p",
        profile_arg: "high444p",
        profile: 244,
    },
];

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Regenerate the fixtures — by hand, on a machine whose `ffmpeg` CLI has a
/// working `h264_nvenc`:
/// `cargo test -p roomlerd --features recording,openh264-encoder --test export -- --ignored make_the_hardware_fixtures`
#[test]
#[ignore = "writes the committed fixtures; needs an ffmpeg CLI with a working h264_nvenc"]
fn make_the_hardware_fixtures() {
    for f in &FIXTURES {
        make_fixture(f);
    }
}

fn make_fixture(fixture: &Fixture) {
    use roomlerd::recording::annexb::{h264, split_nals};
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    const FRAMES: u16 = 90;
    let size = format!("{W}x{H}");
    let rate = FPS.to_string();
    let gop = (FPS * 2).to_string();
    let mut child = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "bgra",
        ])
        .args(["-s", &size, "-r", &rate, "-i", "-"])
        .args(["-c:v", "h264_nvenc", "-profile:v", fixture.profile_arg])
        .args(["-preset", "p6", "-tune", "hq"])
        .args([
            "-rc", "vbr", "-cq", "23", "-b:v", "0", "-bf", "0", "-g", &gop,
        ])
        .args([
            "-pix_fmt",
            fixture.pix_fmt,
            "-color_range",
            "tv",
            "-colorspace",
            "smpte170m",
        ])
        .args(["-color_primaries", "smpte170m", "-color_trc", "smpte170m"])
        .args(["-bsf:v", "h264_metadata=aud=insert", "-f", "h264", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("an ffmpeg CLI on PATH");
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        for i in 0..FRAMES {
            stdin.write_all(&render(i)).unwrap();
        }
    });
    let mut stream = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stream)
        .unwrap();
    feeder.join().unwrap();
    assert!(child.wait().unwrap().success(), "ffmpeg failed");

    // One access unit per delimiter; the delimiters themselves are dropped,
    // since the recorder's encoders write none.
    let mut units: Vec<Vec<u8>> = Vec::new();
    for nal in split_nals(&stream) {
        if h264::nal_type(nal) == Some(h264::AUD) {
            units.push(Vec::new());
            continue;
        }
        let au = units
            .last_mut()
            .expect("the stream starts with a delimiter");
        au.extend_from_slice(&[0, 0, 0, 1]);
        au.extend_from_slice(nal);
    }
    assert_eq!(
        units.len(),
        usize::from(FRAMES),
        "one access unit per frame"
    );

    let dest = fixture_path(fixture.name);
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let partial = std::env::temp_dir().join(format!(
        "fr85-{}-{}.partial",
        fixture.profile,
        std::process::id()
    ));
    let mut w = FragmentedWriter::create(
        &partial,
        VideoTrack {
            width: W,
            height: H,
            fps: FPS,
            color: ColorInfo::BT601_LIMITED,
        },
        None,
    )
    .unwrap();
    for (i, au) in units.iter().enumerate() {
        let key = split_nals(au)
            .iter()
            .any(|n| h264::nal_type(n) == Some(h264::SLICE_IDR));
        w.push_video(i as u64 * TICK, au, key).unwrap();
    }
    w.finish().unwrap();
    let _ = std::fs::remove_file(&dest);
    mp4::finalize(&partial, &dest).unwrap();
    std::fs::remove_file(&partial).unwrap();
    let format = ProgressiveFile::open(&dest)
        .unwrap()
        .video_format()
        .unwrap();
    assert_eq!(format.profile, fixture.profile, "{}", fixture.name);
}

/// The fixtures are what they claim: High and High 4:4:4, 90 frames of the
/// counter each — so the tests below are about a hardware encoder's
/// recordings, and a build without FFmpeg's decoder MUST refuse them.
#[test]
fn the_hardware_fixtures_are_what_they_claim() {
    for f in &FIXTURES {
        let pf = ProgressiveFile::open(&fixture_path(f.name)).expect("the committed fixture");
        let format = pf.video_format().unwrap();
        assert_eq!(format.profile, f.profile, "{}", f.name);
        assert_eq!((format.width, format.height), (W, H), "{}", f.name);
        assert_eq!(pf.samples(VIDEO_TRACK_ID).unwrap().len(), 90, "{}", f.name);
    }
}

/// FR-85 P4 — a hardware encoder's recording exports frame for frame where
/// the build's FFmpeg carries its H.264 decoder: keep 0–1 s · cut 1–2 s ·
/// keep 2–3 s is exactly counters `0..30 ++ 60..90`, in 4:2:0 and in 4:4:4.
/// Where the decoder is absent, the same export is refused
/// `decoder_unavailable` by name (the control: neither fixture is Baseline,
/// so openh264 alone cannot read them).
#[tokio::test]
async fn a_hardware_recording_exports_frame_for_frame_where_ffmpeg_decodes_it() {
    use roomlerd::recording::decode::{h264_decoder_available, h264_decoder_expected};
    let available = h264_decoder_available();
    assert!(
        available || !h264_decoder_expected(),
        "ROOMLER_EXPECT_FFMPEG_H264_DECODER=1 but the linked FFmpeg has no H.264 decoder"
    );
    for f in &FIXTURES {
        let d = dir();
        let source = d.path().join("source.mp4");
        std::fs::copy(fixture_path(f.name), &source).unwrap();
        let edits = edit_list(vec![
            seg(0, 1000, Action::Keep),
            seg(1000, 2000, Action::Cut),
            seg(2000, 3000, Action::Keep),
        ]);
        let dest = export::edited_name(&source).unwrap();
        let result = export::export(
            &source,
            &edits,
            &dest,
            software(),
            &AtomicBool::new(false),
            |_, _| {},
        )
        .await;
        if !available {
            match result {
                Err(ExportError::DecoderUnavailable { profile }) if profile == f.profile => {}
                other => panic!(
                    "{}: a build without the decoder refuses by name: {other:?}",
                    f.name
                ),
            }
            assert!(!dest.exists(), "{}: nothing written", f.name);
            continue;
        }
        let s = result.unwrap_or_else(|e| panic!("{}: {} — {}", f.name, e.code(), e.detail()));
        let expected: Vec<u16> = (0..30).chain(60..90).collect();
        assert_eq!(counters(&dest), expected, "{}", f.name);
        assert_eq!(s.frames, 60, "{}", f.name);
    }
}

/// And the probe says so, before any export is tried: a hardware recording
/// is `editable` exactly where the decoder is linked in.
#[tokio::test]
async fn the_probe_says_a_hardware_recording_is_editable_only_with_the_decoder() {
    use roomlerd::recording::child::parse_event_line;
    use roomlerd::recording::decode::h264_decoder_available;
    for f in &FIXTURES {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_meshharbord"))
            .args(["media", "probe"])
            .arg(fixture_path(f.name))
            .stdin(std::process::Stdio::null())
            .output()
            .expect("roomlerd media probe");
        let probe = String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(parse_event_line)
            .expect("a probe event");
        assert_eq!(probe["ev"], "probe", "{probe}");
        assert_eq!(probe["profile"], f.profile, "{probe}");
        assert_eq!(probe["editable"], h264_decoder_available(), "{probe}");
        if !h264_decoder_available() {
            let reason = probe["reason"].as_str().unwrap_or_default();
            assert!(reason.contains("no decoder"), "{reason}");
        }
    }
}

/// FR-85 P5b — an export's sound. The oracle is the audio counterpart of the
/// frame counter: a STEPPED tone, second k of the recording playing
/// (300 + 100·k) Hz, so every second of an export names the second of the
/// recording it came from.
#[cfg(feature = "audio")]
mod sound {
    use super::*;
    use roomlerd::recording::audio_codec::AudioEncoder;
    use roomlerd::recording::edit::Music;
    use roomlerd::recording::mp4::{AUDIO_TRACK_ID, AudioCodec};

    const RATE: usize = 48_000;
    const FRAME: usize = 960;
    const PER_VIDEO_FRAME: usize = RATE / FPS as usize; // 1600

    /// Source second `t` plays this.
    fn stepped_hz(t: f64) -> f64 {
        300.0 + 100.0 * t.floor()
    }

    /// Like `make_source`, with an Opus track of the stepped tone.
    async fn make_source_with_sound(path: &Path, frames: u16) {
        make_source_with_sound_as(path, frames, AudioEncoder::opus().unwrap()).await;
    }

    /// FR-85 P4 — the same recording with its sound in `enc`'s codec, fed
    /// the way the recorder feeds it: from the encoder's priming delay past
    /// time zero, so decoded sample k is time k.
    async fn make_source_with_sound_as(path: &Path, frames: u16, mut audio: AudioEncoder) {
        let partial = path.with_extension("partial");
        let mut enc = Openh264Encoder::new_recording(W, H, FPS, FPS * 2).unwrap();
        let mut w = FragmentedWriter::create(
            &partial,
            VideoTrack {
                width: W,
                height: H,
                fps: FPS,
                color: ColorInfo::BT601_LIMITED,
            },
            Some(audio.track()),
        )
        .unwrap();
        let total = frames as usize * PER_VIDEO_FRAME;
        let mut phase = 0.0f64;
        let mut pcm: Vec<i16> = Vec::with_capacity((total + FRAME) * 2);
        for s in 0..total + FRAME {
            let hz = stepped_hz(s as f64 / RATE as f64);
            let v = (phase.sin() * 8000.0) as i16;
            phase += 2.0 * std::f64::consts::PI * hz / RATE as f64;
            pcm.extend_from_slice(&[v, v]);
        }
        let mut sent = audio.unsignalled_delay() as usize;
        for i in 0..frames {
            let f = Arc::new(Frame {
                width: W,
                height: H,
                stride: W * 4,
                pixel_format: PixelFormat::Bgra,
                data: render(i),
                monotonic_us: 0,
                monitor: 0,
                damage: Damage::Unknown,
                source: None,
            });
            let packets = enc.encode(f).await.unwrap();
            let key = packets.iter().any(|p| p.is_keyframe);
            let au: Vec<u8> = packets.into_iter().flat_map(|p| p.data).collect();
            w.push_video(u64::from(i) * TICK, &au, key).unwrap();
            let until = (usize::from(i) + 1) * PER_VIDEO_FRAME;
            if until > sent {
                audio
                    .push(&pcm[sent * 2..until * 2], &mut |p, d| w.push_audio(&p, d))
                    .unwrap();
                sent = until;
            }
        }
        audio.finish(&mut |p, d| w.push_audio(&p, d)).unwrap();
        w.finish().unwrap();
        mp4::finalize(&partial, path).unwrap();
        std::fs::remove_file(&partial).unwrap();
    }

    /// The whole audio track, decoded, interleaved stereo, time zero first:
    /// Opus's `pre_skip` dropped; AAC's priming was paid by the writer (FR-85
    /// P4 — an export is AAC wherever the build's FFmpeg has the encoder).
    /// The test's own decoders, never the engine's reader. `None` = no audio
    /// track.
    fn decode_sound(path: &Path) -> Option<Vec<i16>> {
        let pf = ProgressiveFile::open(path).unwrap();
        let format = pf.audio_format().unwrap()?;
        let mut f = std::fs::File::open(path).unwrap();
        let mut out = Vec::new();
        match format.codec {
            AudioCodec::Opus { pre_skip } => {
                use audiopus::coder::Decoder;
                use audiopus::{Channels, SampleRate};
                let mut dec = Decoder::new(SampleRate::Hz48000, Channels::Stereo).unwrap();
                let mut buf = vec![0i16; 5760 * 2];
                for s in pf.samples(AUDIO_TRACK_ID).unwrap() {
                    let data = pf.read_sample(&mut f, &s).unwrap();
                    let packet: audiopus::packet::Packet<'_> = (&data[..]).try_into().unwrap();
                    let signals: audiopus::MutSignals<'_, i16> = (&mut buf[..]).try_into().unwrap();
                    let n = dec.decode(Some(packet), signals, false).unwrap();
                    out.extend_from_slice(&buf[..n * 2]);
                }
                Some(out.split_off(usize::from(pre_skip) * 2))
            }
            AudioCodec::Aac { asc, .. } => {
                use symphonia::core::audio::SampleBuffer;
                use symphonia::core::codecs::{CODEC_TYPE_AAC, CodecParameters, DecoderOptions};
                let mut params = CodecParameters::new();
                params
                    .for_codec(CODEC_TYPE_AAC)
                    .with_sample_rate(RATE as u32)
                    .with_extra_data(asc.into_boxed_slice());
                let mut dec = symphonia::default::get_codecs()
                    .make(&params, &DecoderOptions::default())
                    .unwrap();
                for s in pf.samples(AUDIO_TRACK_ID).unwrap() {
                    let data = pf.read_sample(&mut f, &s).unwrap();
                    let packet = symphonia::core::formats::Packet::new_from_slice(0, 0, 0, &data);
                    let decoded = dec.decode(&packet).unwrap();
                    let spec = *decoded.spec();
                    assert_eq!(spec.channels.count(), 2, "a stereo track");
                    let mut buf = SampleBuffer::<i16>::new(decoded.capacity() as u64, spec);
                    buf.copy_interleaved_ref(decoded);
                    out.extend_from_slice(buf.samples());
                }
                Some(out)
            }
        }
    }

    /// FR-85 P4 — whether this build writes AAC (its FFmpeg has the encoder).
    /// A lane that declares AAC (`ROOMLER_EXPECT_FFMPEG_AAC=1`) fails here if
    /// it fell back to Opus.
    fn aac_here() -> bool {
        #[cfg(feature = "ffmpeg-encoder")]
        {
            use roomlerd::recording::audio_codec::{AudioEncoder, aac_expected};
            match AudioEncoder::aac() {
                Ok(_) => return true,
                Err(e) => assert!(
                    !aac_expected(),
                    "ROOMLER_EXPECT_FFMPEG_AAC=1 but AAC did not open: {e:#}"
                ),
            }
        }
        false
    }

    /// The left channel between two times, in seconds.
    fn span(pcm: &[i16], from: f64, to: f64) -> Vec<f64> {
        let a = (from * RATE as f64) as usize;
        let b = ((to * RATE as f64) as usize).min(pcm.len() / 2);
        (a..b).map(|i| f64::from(pcm[i * 2])).collect()
    }

    fn rms(x: &[f64]) -> f64 {
        (x.iter().map(|v| v * v).sum::<f64>() / x.len().max(1) as f64).sqrt()
    }

    /// Frequency from zero crossings: two per cycle.
    fn hz(x: &[f64]) -> f64 {
        let crossings = x
            .windows(2)
            .filter(|w| (w[0] < 0.0) != (w[1] < 0.0))
            .count();
        crossings as f64 / 2.0 / (x.len() as f64 / RATE as f64)
    }

    /// A stereo 16-bit WAV at 44.1 kHz, so the music is resampled on its way
    /// in, as a real song usually is.
    fn write_wav(path: &Path, freq: f64, seconds: f64, amplitude: f64) {
        let rate = 44_100u32;
        let n = (seconds * f64::from(rate)) as u32;
        let samples: Vec<i16> = (0..n)
            .flat_map(|i| {
                let v = ((2.0 * std::f64::consts::PI * freq * f64::from(i) / f64::from(rate)).sin()
                    * amplitude) as i16;
                [v, v]
            })
            .collect();
        write_wav_raw(path, rate, &samples);
    }

    /// Interleaved stereo samples as a WAV declaring `rate`, whatever it is.
    fn write_wav_raw(path: &Path, rate: u32, samples: &[i16]) {
        let data: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
        wav.extend_from_slice(&2u16.to_le_bytes()); // stereo
        wav.extend_from_slice(&rate.to_le_bytes());
        wav.extend_from_slice(&rate.wrapping_mul(4).to_le_bytes());
        wav.extend_from_slice(&4u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&(data.len() as u32).to_le_bytes());
        wav.extend_from_slice(&data);
        std::fs::write(path, wav).unwrap();
    }

    fn music(path: &str) -> Music {
        Music {
            path: path.into(),
            volume: 0.5,
            start_ms: 0,
            fade_in_ms: 0,
            fade_out_ms: 0,
            looped: true,
        }
    }

    async fn run(source: &Path, edits: &EditList) -> Result<export::ExportSummary, ExportError> {
        let dest = export::edited_name(source).unwrap();
        export::export(
            source,
            edits,
            &dest,
            software(),
            &AtomicBool::new(false),
            |_, _| {},
        )
        .await
    }

    /// Keep 0–2 s · cut 2–4 s · 4× 4–8 s · keep 8–10 s: output second 0
    /// plays recording second 0 (300 Hz), second 1 plays second 1 (400 Hz),
    /// second 2 is the speed-up and is MUTED, seconds 3 and 4 play recording
    /// seconds 8 and 9 (1100, 1200 Hz). The cut and the offsets are proven,
    /// not just "some sound".
    #[tokio::test]
    async fn the_recordings_own_sound_follows_the_edit() {
        sound_follows_the_edit(AudioEncoder::opus().unwrap()).await;
    }

    /// FR-85 P4 — the same, for a recording whose own track is AAC: the
    /// engine reads it (symphonia), from time zero — the recorder paid the
    /// priming, so nothing may be skipped.
    #[cfg(feature = "ffmpeg-encoder")]
    #[tokio::test]
    async fn an_aac_recordings_sound_follows_the_edit_too() {
        if !aac_here() {
            eprintln!("skipped: this FFmpeg has no AAC encoder");
            return;
        }
        sound_follows_the_edit(AudioEncoder::aac().unwrap()).await;
    }

    async fn sound_follows_the_edit(source_audio: AudioEncoder) {
        let d = dir();
        let source = d.path().join("source.mp4");
        make_source_with_sound_as(&source, 300, source_audio).await;
        // The oracle discriminates: the recording itself, second 3, is 600 Hz.
        let original = decode_sound(&source).unwrap();
        assert!((hz(&span(&original, 3.2, 3.8)) - 600.0).abs() < 15.0);

        let s = run(
            &source,
            &edit_list(vec![
                seg(0, 2000, Action::Keep),
                seg(2000, 4000, Action::Cut),
                seg(4000, 8000, Action::Speed { speed: 4.0 }),
                seg(8000, 10_000, Action::Keep),
            ]),
        )
        .await
        .unwrap();
        assert_eq!(s.audio, "original");
        // FR-85 P4 — the export writes the build's best codec whatever the
        // recording carried (this one is Opus): AAC where FFmpeg has it.
        let format = ProgressiveFile::open(&s.path)
            .unwrap()
            .audio_format()
            .unwrap()
            .unwrap();
        assert_eq!(
            matches!(format.codec, AudioCodec::Aac { .. }),
            aac_here(),
            "the export's track is {:?}",
            format.codec
        );
        let pcm = decode_sound(&s.path).expect("an audio track");
        let secs = pcm.len() as f64 / 2.0 / RATE as f64;
        assert!(
            (4.95..=5.05).contains(&secs),
            "the sound lasts as long as the picture: {secs}"
        );
        for (second, want) in [(0.0, 300.0), (1.0, 400.0), (3.0, 1100.0), (4.0, 1200.0)] {
            let x = span(&pcm, second + 0.2, second + 0.8);
            assert!(rms(&x) > 3000.0, "second {second} is loud: {}", rms(&x));
            let got = hz(&x);
            assert!(
                (got - want).abs() < 15.0,
                "second {second}: {got} Hz, want {want}"
            );
        }
        let muted = rms(&span(&pcm, 2.2, 2.8));
        assert!(muted < 100.0, "the speed-up is muted: RMS {muted}");
    }

    /// Music plays under the whole export, the sped-up stretch included,
    /// loops when it is shorter, fades in, and sits at its volume.
    #[tokio::test]
    async fn music_plays_under_the_whole_export_loops_and_fades_in() {
        let d = dir();
        let source = d.path().join("source.mp4");
        make_source(&source, 300).await; // no sound of its own
        write_wav(&d.path().join("song.wav"), 880.0, 2.0, 16_000.0);
        let mut edits = edit_list(vec![
            seg(0, 2000, Action::Keep),
            seg(2000, 10_000, Action::Speed { speed: 4.0 }),
        ]);
        let mut m = music("song.wav");
        m.fade_in_ms = 1000;
        edits.music = Some(m);

        let s = run(&source, &edits).await.unwrap();
        assert_eq!(s.audio, "music");
        let pcm = decode_sound(&s.path).expect("an audio track");
        let secs = pcm.len() as f64 / 2.0 / RATE as f64;
        assert!((3.95..=4.05).contains(&secs), "{secs}");
        // Full volume: a 16000 sine at 0.5 has an RMS of 8000/√2 ≈ 5657.
        let full = rms(&span(&pcm, 1.2, 1.8));
        assert!((4500.0..=6800.0).contains(&full), "RMS {full}");
        assert!((hz(&span(&pcm, 1.2, 1.8)) - 880.0).abs() < 15.0);
        // Under the speed-up, and past the song's two seconds: it looped.
        let later = span(&pcm, 2.5, 3.5);
        assert!(rms(&later) > 4500.0, "the music loops: RMS {}", rms(&later));
        assert!((hz(&later) - 880.0).abs() < 15.0);
        // The fade-in: quieter at the start than at full volume.
        let early = rms(&span(&pcm, 0.05, 0.3));
        assert!(early < full * 0.4, "fading in: {early} vs {full}");
    }

    /// Both together: inside the speed-up only the music is heard.
    #[tokio::test]
    async fn a_speed_up_keeps_the_music_and_mutes_the_recording() {
        let d = dir();
        let source = d.path().join("source.mp4");
        make_source_with_sound(&source, 300).await;
        write_wav(&d.path().join("song.wav"), 2000.0, 1.0, 16_000.0);
        let mut edits = edit_list(vec![
            seg(0, 2000, Action::Keep),
            seg(2000, 10_000, Action::Speed { speed: 4.0 }),
        ]);
        edits.music = Some(music("song.wav"));
        let s = run(&source, &edits).await.unwrap();
        assert_eq!(s.audio, "original_and_music");
        let pcm = decode_sound(&s.path).unwrap();
        let sped = span(&pcm, 2.2, 3.8);
        assert!(
            (hz(&sped) - 2000.0).abs() < 30.0,
            "only the music: {} Hz",
            hz(&sped)
        );
    }

    #[tokio::test]
    async fn silence_is_no_track_and_bad_music_is_refused_by_name() {
        let d = dir();
        let source = d.path().join("source.mp4");
        make_source_with_sound(&source, 60).await;
        let mut edits = edit_list(vec![seg(0, 2000, Action::Keep)]);
        edits.original_volume = Some(0.0);
        let s = run(&source, &edits).await.unwrap();
        assert_eq!(s.audio, "none");
        assert!(decode_sound(&s.path).is_none(), "no audio track at all");

        std::fs::write(d.path().join("song.mp3"), b"not music").unwrap();
        let mut edits = edit_list(vec![seg(0, 2000, Action::Keep)]);
        edits.music = Some(music("song.mp3"));
        let e = run(&source, &edits).await.unwrap_err();
        assert_eq!(e.code(), "music_unreadable", "{}", e.detail());
    }

    /// The music is a file the person picked: untrusted input. A WAV
    /// declaring 0 Hz makes symphonia 0.5.5's probe PANIC, and one declaring
    /// 1 Hz would grow every packet 48 000-fold on its way to 48 kHz. Both
    /// are refused by name, and the export lives to say so.
    ///
    /// ⚠️ The 1 Hz cell is green with EITHER rate check deleted (the header
    /// at open, every buffer in `fill`): it is red only with the range
    /// itself widened. Keep both: `fill`'s is the gate (a container can
    /// declare one rate and its codec produce another), the open's says it
    /// before the export starts.
    #[tokio::test]
    async fn a_malformed_music_file_is_refused_by_name_not_a_crash() {
        let d = dir();
        let source = d.path().join("source.mp4");
        make_source(&source, 30).await;
        let tone: Vec<i16> = (0..4_000)
            .map(|i| ((i % 50) * 400 - 10_000) as i16)
            .collect();
        for (name, rate) in [("zero-hz.wav", 0u32), ("one-hz.wav", 1)] {
            write_wav_raw(&d.path().join(name), rate, &tone);
            let mut edits = edit_list(vec![seg(0, 1000, Action::Keep)]);
            edits.music = Some(music(name));
            let e = run(&source, &edits).await.unwrap_err();
            assert_eq!(e.code(), "music_unreadable", "{name}: {}", e.detail());
        }
        let staged: Vec<_> = std::fs::read_dir(d.path().join(".roomler-partial"))
            .map(|r| r.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(staged.is_empty(), "nothing staged left: {staged:?}");
    }

    /// A piece shorter than 100 ms plays once and is not looped: looping a
    /// few samples would reopen the file thousands of times per second of
    /// export.
    #[tokio::test]
    async fn a_piece_too_short_to_loop_plays_once() {
        let d = dir();
        let source = d.path().join("source.mp4");
        make_source(&source, 60).await;
        write_wav(&d.path().join("blip.wav"), 880.0, 0.05, 16_000.0);
        let mut edits = edit_list(vec![seg(0, 2000, Action::Keep)]);
        edits.music = Some(music("blip.wav"));
        let s = run(&source, &edits).await.unwrap();
        assert_eq!(s.audio, "music");
        let pcm = decode_sound(&s.path).unwrap();
        let blip = rms(&span(&pcm, 0.005, 0.035));
        assert!(blip > 3000.0, "it plays: RMS {blip}");
        let after = rms(&span(&pcm, 0.5, 1.5));
        assert!(after < 100.0, "once, not looped: RMS {after}");
    }
}
