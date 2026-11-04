// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P5 — the edit list: what an export keeps, cuts and speeds up.
//!
//! An edit list is saved beside its recording as `<name>.edit.json`, and it
//! never touches the recording: editing is non-destructive, and an export
//! writes a new file (`<name> (edited).mp4`).
//!
//! Segments partition the recording's timeline from 0, in order and without
//! gaps. Each is kept, cut, or sped up (1.25× to 16×, in quarter steps).
//! Anything after the last segment is kept, so "cut the first ten seconds"
//! is one segment.
//!
//! ⚠️ **The time map is exact integer arithmetic**, on purpose. Output frame
//! `n` of an export at `fps` presents source time [`Plan::source_time`], and a
//! k× speed-up shows every k-th frame of the source without drift. A float
//! map accumulates error over an hour and slips a frame here and there, which
//! the counter oracle in `tests/export.rs` reads as the wrong frame.

use serde::{Deserialize, Serialize};

use super::mp4::VIDEO_TIMESCALE;

/// The file an edit list is saved in, beside `<name>.mp4`.
pub const EDIT_SUFFIX: &str = ".edit.json";
/// The only version this build writes and reads.
pub const VERSION: u32 = 1;
/// Speeds are quarter steps: `quarters / 4` is the factor.
const QUARTERS_PER_X: u64 = 4;
/// 1.25× — the slowest speed-up.
pub const MIN_SPEED_QUARTERS: u64 = 5;
/// 16× — the fastest.
pub const MAX_SPEED_QUARTERS: u64 = 64;

/// A recording's edit list, as saved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditList {
    pub version: u32,
    /// The recording's file name, bare, in the same folder as this list.
    pub source: String,
    pub segments: Vec<Segment>,
    /// FR-85 P5b — the recording's own audio, 0.0 (muted) to 1.0 (as
    /// recorded, the default). Always muted inside a speed-up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_volume: Option<f32>,
    /// FR-85 P5b — background music under the export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub music: Option<Music>,
}

/// Background music for an export.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Music {
    /// The music file: absolute, or relative to the edit list's folder. The
    /// export runs as the person, so it reaches only what they can read.
    pub path: String,
    /// 0.0 to 1.0.
    #[serde(default = "Music::default_volume")]
    pub volume: f32,
    /// Where in the EXPORT the music begins.
    #[serde(default)]
    pub start_ms: u64,
    #[serde(default)]
    pub fade_in_ms: u64,
    /// Over the last stretch of the music's time in the export.
    #[serde(default)]
    pub fade_out_ms: u64,
    /// Start again from the top when it ends (a short piece under a long
    /// export); otherwise silence after it.
    #[serde(default = "Music::default_loop", rename = "loop")]
    pub looped: bool,
}

impl Music {
    fn default_volume() -> f32 {
        0.5
    }
    fn default_loop() -> bool {
        true
    }
}

/// A stretch of the recording and what happens to it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Segment {
    pub start_ms: u64,
    pub end_ms: u64,
    #[serde(flatten)]
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Keep,
    Cut,
    /// Faster by `speed` (1.25 to 16, in quarter steps).
    Speed {
        speed: f64,
    },
}

/// One stretch of the output, in [`VIDEO_TIMESCALE`] ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Piece {
    src_start: u64,
    src_end: u64,
    /// The speed as quarters: 4 = 1×, 16 = 4×.
    quarters: u64,
    out_start: u64,
    out_len: u64,
}

/// A validated edit list, ready to drive an export: which source time each
/// moment of the output shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pieces: Vec<Piece>,
    /// The output's length, in ticks.
    pub out_ticks: u64,
}

impl Plan {
    /// The source time (ticks) the output shows at `out` (ticks), or `None`
    /// past its end.
    pub fn source_time(&self, out: u64) -> Option<u64> {
        let p = self
            .pieces
            .iter()
            .find(|p| out >= p.out_start && out < p.out_start + p.out_len)?;
        Some(p.src_start + (out - p.out_start) * p.quarters / QUARTERS_PER_X)
    }

    /// How many frames an export at `fps` holds.
    pub fn frames(&self, fps: u32) -> u64 {
        let tick = u64::from(VIDEO_TIMESCALE / fps.clamp(1, 60));
        self.out_ticks.div_ceil(tick)
    }

    /// The output's length in milliseconds.
    pub fn out_ms(&self) -> u64 {
        self.out_ticks * 1000 / u64::from(VIDEO_TIMESCALE)
    }

    /// FR-85 P5b — the output's audio timeline in samples at `rate`: each
    /// stretch either plays the source from `src_start` (kept) or is muted
    /// (a speed-up: sped-up sound is noise, and a recording's audio is mostly
    /// speech). Cuts are gone, as in the video.
    pub fn audio_spans(&self, rate: u32) -> Vec<AudioSpan> {
        let at = |ticks: u64| ticks * u64::from(rate) / u64::from(VIDEO_TIMESCALE);
        self.pieces
            .iter()
            .map(|p| AudioSpan {
                out_start: at(p.out_start),
                out_end: at(p.out_start + p.out_len),
                src_start: (p.quarters == QUARTERS_PER_X).then(|| at(p.src_start)),
            })
            .collect()
    }

    /// The output's length in samples at `rate`.
    pub fn out_samples(&self, rate: u32) -> u64 {
        self.out_ticks * u64::from(rate) / u64::from(VIDEO_TIMESCALE)
    }
}

/// One stretch of an export's audio timeline, in samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioSpan {
    pub out_start: u64,
    pub out_end: u64,
    /// Where the source's audio for this stretch starts; `None` = muted.
    pub src_start: Option<u64>,
}

/// Why an edit list cannot be exported. Each is said to the person as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    Version(u32),
    NoSegments,
    DoesNotStartAtZero(u64),
    Gap {
        after_ms: u64,
        next_ms: u64,
    },
    Empty {
        start_ms: u64,
    },
    Speed {
        start_ms: u64,
        speed: String,
    },
    NothingKept,
    /// A volume outside 0.0–1.0 (or not a number).
    Volume {
        what: &'static str,
        value: String,
    },
    NoMusicFile,
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version(v) => write!(f, "edit list version {v} is not one this build reads"),
            Self::NoSegments => write!(f, "the edit list has no segments"),
            Self::DoesNotStartAtZero(ms) => {
                write!(f, "the first segment starts at {ms} ms, not at the start")
            }
            Self::Gap { after_ms, next_ms } => write!(
                f,
                "segments must follow each other: one ends at {after_ms} ms and the next starts at {next_ms} ms"
            ),
            Self::Empty { start_ms } => write!(f, "the segment at {start_ms} ms has no length"),
            Self::Speed { start_ms, speed } => write!(
                f,
                "the segment at {start_ms} ms has speed {speed}: speeds go from 1.25 to 16 in quarter steps"
            ),
            Self::NothingKept => write!(f, "every part of the recording is cut: nothing to export"),
            Self::Volume { what, value } => {
                write!(f, "the {what} volume is {value}: volumes go from 0 to 1")
            }
            Self::NoMusicFile => write!(f, "the music has no file"),
        }
    }
}

/// A volume is a number from 0 to 1.
fn volume_ok(v: f32) -> bool {
    v.is_finite() && (0.0..=1.0).contains(&v)
}

impl EditList {
    /// Where a recording's edit list is saved: `<name>.mp4.edit.json`, the
    /// sidecar's naming, so the two sit together.
    pub fn path_for(recording: &std::path::Path) -> std::path::PathBuf {
        let mut name = recording
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(EDIT_SUFFIX);
        recording.with_file_name(name)
    }

    /// Validate against a source `duration_ms` long, and plan the output.
    ///
    /// Segments past the source's end are clipped to it (a list written
    /// against a longer probe must not fail an export); anything after the
    /// last segment is kept.
    pub fn plan(&self, duration_ms: u64) -> Result<Plan, Invalid> {
        if self.version != VERSION {
            return Err(Invalid::Version(self.version));
        }
        if let Some(v) = self.original_volume
            && !volume_ok(v)
        {
            return Err(Invalid::Volume {
                what: "recording's",
                value: format!("{v}"),
            });
        }
        if let Some(m) = &self.music {
            if m.path.trim().is_empty() {
                return Err(Invalid::NoMusicFile);
            }
            if !volume_ok(m.volume) {
                return Err(Invalid::Volume {
                    what: "music",
                    value: format!("{}", m.volume),
                });
            }
        }
        let Some(first) = self.segments.first() else {
            return Err(Invalid::NoSegments);
        };
        if first.start_ms != 0 {
            return Err(Invalid::DoesNotStartAtZero(first.start_ms));
        }
        let mut pieces = Vec::new();
        let mut out_start = 0u64;
        let mut push = |src_start_ms: u64, src_end_ms: u64, quarters: u64| {
            let (s, e) = (ms_to_ticks(src_start_ms), ms_to_ticks(src_end_ms));
            let out_len = (e - s) * QUARTERS_PER_X / quarters;
            if out_len > 0 {
                pieces.push(Piece {
                    src_start: s,
                    src_end: e,
                    quarters,
                    out_start,
                    out_len,
                });
                out_start += out_len;
            }
        };
        let mut prev_end = 0u64;
        for seg in &self.segments {
            if seg.start_ms != prev_end {
                return Err(Invalid::Gap {
                    after_ms: prev_end,
                    next_ms: seg.start_ms,
                });
            }
            if seg.end_ms <= seg.start_ms {
                return Err(Invalid::Empty {
                    start_ms: seg.start_ms,
                });
            }
            prev_end = seg.end_ms;
            let quarters = match seg.action {
                Action::Cut => continue,
                Action::Keep => QUARTERS_PER_X,
                Action::Speed { speed } => speed_quarters(speed).ok_or(Invalid::Speed {
                    start_ms: seg.start_ms,
                    speed: format!("{speed}"),
                })?,
            };
            let (s, e) = (seg.start_ms.min(duration_ms), seg.end_ms.min(duration_ms));
            if e > s {
                push(s, e, quarters);
            }
        }
        if prev_end < duration_ms {
            push(prev_end, duration_ms, QUARTERS_PER_X);
        }
        if pieces.is_empty() {
            return Err(Invalid::NothingKept);
        }
        Ok(Plan {
            out_ticks: out_start,
            pieces,
        })
    }
}

/// `speed` as quarters, when it is 1.25 to 16 in quarter steps.
fn speed_quarters(speed: f64) -> Option<u64> {
    let q = speed * QUARTERS_PER_X as f64;
    let rounded = q.round();
    ((q - rounded).abs() < 1e-9
        && (MIN_SPEED_QUARTERS as f64..=MAX_SPEED_QUARTERS as f64).contains(&rounded))
    .then_some(rounded as u64)
}

fn ms_to_ticks(ms: u64) -> u64 {
    ms * u64::from(VIDEO_TIMESCALE) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(start_ms: u64, end_ms: u64, action: Action) -> Segment {
        Segment {
            start_ms,
            end_ms,
            action,
        }
    }

    fn list(segments: Vec<Segment>) -> EditList {
        EditList {
            version: VERSION,
            source: "MeshHarbor Recording.mp4".into(),
            segments,
            original_volume: None,
            music: None,
        }
    }

    const TICK_30: u64 = 3000; // one frame at 30 fps, in 90 kHz ticks

    /// The frame of a 30 fps source shown at output frame `n`.
    fn shown(plan: &Plan, n: u64) -> Option<u64> {
        plan.source_time(n * TICK_30).map(|t| t / TICK_30)
    }

    /// The plan's own example: keep, cut, speed ×4, keep over ten seconds —
    /// exactly the frames the export oracle expects.
    #[test]
    fn keep_cut_speed_keep_maps_every_output_frame_exactly() {
        let plan = list(vec![
            seg(0, 2000, Action::Keep),
            seg(2000, 4000, Action::Cut),
            seg(4000, 8000, Action::Speed { speed: 4.0 }),
            seg(8000, 10000, Action::Keep),
        ])
        .plan(10_000)
        .unwrap();
        assert_eq!(plan.out_ms(), 5000);
        assert_eq!(plan.frames(30), 150);
        let frames: Vec<u64> = (0..plan.frames(30))
            .map(|n| shown(&plan, n).unwrap())
            .collect();
        let expected: Vec<u64> = (0..60)
            .chain((0..30).map(|k| 120 + 4 * k))
            .chain(240..300)
            .collect();
        assert_eq!(frames, expected);
        assert_eq!(shown(&plan, 150), None, "past the end");
    }

    /// The control: an edit list of one kept segment maps the source to
    /// itself, so the assertion above can tell an edit from none.
    #[test]
    fn keeping_everything_is_the_identity() {
        let plan = list(vec![seg(0, 10_000, Action::Keep)])
            .plan(10_000)
            .unwrap();
        let frames: Vec<u64> = (0..plan.frames(30))
            .map(|n| shown(&plan, n).unwrap())
            .collect();
        assert_eq!(frames, (0..300).collect::<Vec<_>>());
    }

    /// A 1.5× over an hour lands on the frame integer arithmetic says, at
    /// the very end: no drift.
    #[test]
    fn an_hour_at_one_and_a_half_times_does_not_drift() {
        let hour = 3_600_000;
        let plan = list(vec![seg(0, hour, Action::Speed { speed: 1.5 })])
            .plan(hour)
            .unwrap();
        assert_eq!(plan.out_ms(), 2_400_000);
        let last = plan.frames(30) - 1;
        assert_eq!(last, 72_000 - 1);
        // Output frame n shows source frame floor(n * 1.5).
        assert_eq!(shown(&plan, last), Some(last * 3 / 2));
        assert_eq!(shown(&plan, 1), Some(1));
        assert_eq!(shown(&plan, 2), Some(3));
    }

    #[test]
    fn what_follows_the_last_segment_is_kept_and_a_long_list_is_clipped() {
        // "Cut the first two seconds": one segment.
        let plan = list(vec![seg(0, 2000, Action::Cut)]).plan(10_000).unwrap();
        assert_eq!(plan.out_ms(), 8000);
        assert_eq!(shown(&plan, 0), Some(60));
        // Written against a longer probe: clipped, never an error.
        let plan = list(vec![seg(0, 60_000, Action::Keep)])
            .plan(10_000)
            .unwrap();
        assert_eq!(plan.out_ms(), 10_000);
    }

    #[test]
    fn a_bad_list_is_refused_by_name() {
        let cases = [
            (list(vec![]), Invalid::NoSegments),
            (
                list(vec![seg(500, 1000, Action::Keep)]),
                Invalid::DoesNotStartAtZero(500),
            ),
            (
                list(vec![
                    seg(0, 1000, Action::Keep),
                    seg(1500, 2000, Action::Keep),
                ]),
                Invalid::Gap {
                    after_ms: 1000,
                    next_ms: 1500,
                },
            ),
            (
                list(vec![seg(0, 0, Action::Keep)]),
                Invalid::Empty { start_ms: 0 },
            ),
            (
                list(vec![seg(0, 10_000, Action::Cut)]),
                Invalid::NothingKept,
            ),
        ];
        for (l, want) in cases {
            assert_eq!(l.plan(10_000), Err(want.clone()), "{want}");
        }
        let mut old = list(vec![seg(0, 1000, Action::Keep)]);
        old.version = 2;
        assert_eq!(old.plan(10_000), Err(Invalid::Version(2)));
    }

    #[test]
    fn speeds_are_quarter_steps_from_one_and_a_quarter_to_sixteen() {
        for ok in [1.25, 1.5, 2.0, 4.0, 8.0, 16.0] {
            assert!(speed_quarters(ok).is_some(), "{ok}");
        }
        for bad in [1.0, 0.5, 1.3, 17.0, f64::NAN, f64::INFINITY, -2.0] {
            assert!(speed_quarters(bad).is_none(), "{bad}");
        }
        let err = list(vec![seg(0, 1000, Action::Speed { speed: 3.3 })])
            .plan(10_000)
            .unwrap_err();
        assert!(err.to_string().contains("quarter steps"), "{err}");
    }

    /// P5b — the audio timeline follows the video's: a kept stretch plays the
    /// source from the same moment (48 samples a millisecond), a speed-up is
    /// muted, a cut is gone.
    #[test]
    fn the_audio_timeline_keeps_mutes_and_cuts_as_the_picture_does() {
        let plan = list(vec![
            seg(0, 2000, Action::Keep),
            seg(2000, 4000, Action::Cut),
            seg(4000, 8000, Action::Speed { speed: 4.0 }),
            seg(8000, 10_000, Action::Keep),
        ])
        .plan(10_000)
        .unwrap();
        assert_eq!(plan.out_samples(48_000), 240_000);
        assert_eq!(
            plan.audio_spans(48_000),
            vec![
                AudioSpan {
                    out_start: 0,
                    out_end: 96_000,
                    src_start: Some(0)
                },
                AudioSpan {
                    out_start: 96_000,
                    out_end: 144_000,
                    src_start: None
                },
                AudioSpan {
                    out_start: 144_000,
                    out_end: 240_000,
                    src_start: Some(384_000)
                },
            ]
        );
    }

    #[test]
    fn a_volume_is_zero_to_one_and_music_needs_a_file() {
        let mut l = list(vec![seg(0, 1000, Action::Keep)]);
        l.original_volume = Some(1.5);
        assert!(matches!(l.plan(1000), Err(Invalid::Volume { .. })));
        l.original_volume = Some(f32::NAN);
        assert!(matches!(l.plan(1000), Err(Invalid::Volume { .. })));
        l.original_volume = Some(0.0);
        assert!(l.plan(1000).is_ok(), "0 is a volume: the recording muted");
        l.music = Some(Music {
            path: " ".into(),
            volume: 0.5,
            start_ms: 0,
            fade_in_ms: 0,
            fade_out_ms: 0,
            looped: true,
        });
        assert_eq!(l.plan(1000), Err(Invalid::NoMusicFile));
        l.music.as_mut().unwrap().path = "song.mp3".into();
        l.music.as_mut().unwrap().volume = -0.1;
        assert!(matches!(
            l.plan(1000),
            Err(Invalid::Volume { what: "music", .. })
        ));
    }

    /// Music fields default as the Edit view expects: half volume, looping.
    #[test]
    fn music_defaults_to_half_volume_and_looping() {
        let l: EditList = serde_json::from_str(
            r#"{"version":1,"source":"a.mp4","segments":[{"start_ms":0,"end_ms":1000,"action":"keep"}],
                "music":{"path":"song.mp3"}}"#,
        )
        .unwrap();
        let m = l.music.unwrap();
        assert_eq!((m.volume, m.looped, m.start_ms), (0.5, true, 0));
        assert_eq!(l.original_volume, None, "absent = as recorded");
    }

    /// FR-85 P5c — the list meshharbor-desktop's Edit view writes. Its own test
    /// (`ui/src/__tests__/companion/editor.spec.ts`) pins the page's output
    /// to this same file, so a change on either side fails one of the two.
    #[test]
    fn the_list_the_desktop_writes_is_one_this_reads() {
        let l: EditList = serde_json::from_str(include_str!(
            "../../../meshharbor-desktop/tests/fixtures/edit-list.json"
        ))
        .unwrap();
        let plan = l.plan(10_000).unwrap();
        assert_eq!(
            plan.out_ms(),
            5000,
            "keep 2 s, cut 2 s, 4 s at 4×, keep 2 s"
        );
        assert_eq!(l.original_volume, Some(0.8));
        let m = l.music.expect("music");
        assert_eq!(m.path, r"C:\Users\me\Music\song.mp3");
        assert_eq!(
            (m.volume, m.start_ms, m.fade_in_ms, m.fade_out_ms, m.looped),
            (0.35, 1000, 2000, 1500, false)
        );
    }

    /// The saved shape is the one meshharbor-desktop writes.
    #[test]
    fn the_file_reads_as_written() {
        let json = r#"{"version":1,"source":"a.mp4","segments":[
            {"start_ms":0,"end_ms":2000,"action":"keep"},
            {"start_ms":2000,"end_ms":4000,"action":"cut"},
            {"start_ms":4000,"end_ms":8000,"action":"speed","speed":4}]}"#;
        let l: EditList = serde_json::from_str(json).unwrap();
        assert_eq!(l.segments[2].action, Action::Speed { speed: 4.0 });
        let back: EditList = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back, l);
    }
}
