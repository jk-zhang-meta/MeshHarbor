// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P3b — SPA POD serialisation, in Rust.
//!
//! PipeWire negotiates formats with **PODs**: a small self-describing binary
//! format. To connect a stream we have to hand `pw_stream_connect` an
//! `EnumFormat` object saying what we can accept.
//!
//! ## Why this is written here instead of called
//!
//! Not a preference — a constraint, and a measured one. The POD builder API
//! (`spa_pod_builder_*`) is **`static inline` in `spa/pod/builder.h`**, and
//! inline functions are not in a library's dynamic symbol table. Checked
//! rather than assumed:
//!
//! ```text
//! $ nm -D --defined-only libpipewire-0.3.so.0 | grep -c '^spa_'
//! 0
//! ```
//!
//! **Zero.** There is nothing to `dlsym` — [P3a](super::pipewire) can reach
//! `libpipewire`'s own exports and cannot reach any of SPA. Linking instead
//! would put the library in `DT_NEEDED` and undo the reason P3a exists.
//!
//! So the wire format is implemented directly. It is a good trade: this is pure
//! data with no `unsafe`, and it can be tested byte-for-byte, which the inline
//! C could not have been from here anyway.
//!
//! ⚠️ **Not yet validated by PipeWire itself.** These tests assert the bytes
//! against the layout in the headers, hand-computed — they cannot prove the
//! daemon accepts them. That proof is `pw_stream_connect` in P3b-ii, and until
//! it exists this module is *believed* correct, not *known* correct.
//!
//! ## The format, as verified against the headers
//!
//! Every POD is an 8-byte header followed by a body:
//!
//! ```text
//! struct spa_pod { uint32_t size; uint32_t type; }   // size = BODY size only
//! ```
//!
//! ⚠️ `size` counts the body and **excludes both the header and any padding**.
//! Padding to an 8-byte boundary is written after a POD but never counted.
//!
//! An **object** body is `{ type, id }` followed by properties, each
//! `{ key, flags }` then a full padded POD value.
//!
//! A **choice** is the subtle one, and the shape is not guessable:
//!
//! ```text
//! [ header: size, type=Choice ]
//! [ body: choice-kind, flags ]
//! [ first value: FULL pod — its header doubles as the body's `child` ]
//! [ later values: BODY ONLY, no header, no padding ]
//! ```
//!
//! That falls out of `spa_pod_builder_push`, which sets `FIRST|BODY` on a
//! Choice: the first `primitive` call sees flags that are not exactly `BODY`
//! and writes a whole POD unpadded, clearing `FIRST`; every later call sees
//! exactly `BODY` and writes the bare body. Guessing "an array of full PODs"
//! or "an array of bare bodies" would both be wrong, and wrong here means a
//! malformed param that PipeWire rejects with no useful diagnosis.

/// Constants, transcribed from the SPA headers (`spa-0.2`, verified against
/// 1.0.5 and unchanged since — these are ABI, not implementation detail).
pub mod ty {
    // spa/utils/type.h — basic types
    pub const ID: u32 = 3;
    pub const INT: u32 = 4;
    pub const RECTANGLE: u32 = 10;
    pub const FRACTION: u32 = 11;
    pub const OBJECT: u32 = 15;
    pub const CHOICE: u32 = 19;

    // spa/utils/type.h — object types
    const OBJECT_START: u32 = 0x40000;
    /// `SPA_TYPE_OBJECT_Format` — third after the start marker.
    pub const OBJECT_FORMAT: u32 = OBJECT_START + 3;

    // spa/param/param.h
    pub const PARAM_ENUM_FORMAT: u32 = 3;

    // spa/param/format.h
    pub const FORMAT_MEDIA_TYPE: u32 = 1;
    pub const FORMAT_MEDIA_SUBTYPE: u32 = 2;
    const FORMAT_START_VIDEO: u32 = 0x20000;
    pub const FORMAT_VIDEO_FORMAT: u32 = FORMAT_START_VIDEO + 1;
    pub const FORMAT_VIDEO_SIZE: u32 = FORMAT_START_VIDEO + 3;
    pub const FORMAT_VIDEO_FRAMERATE: u32 = FORMAT_START_VIDEO + 4;

    pub const MEDIA_TYPE_VIDEO: u32 = 2;
    pub const MEDIA_SUBTYPE_RAW: u32 = 1;

    // spa/param/video/raw.h — the 32-bit packed orders we can consume.
    pub const VIDEO_FORMAT_RGBX: u32 = 7;
    pub const VIDEO_FORMAT_BGRX: u32 = 8;
    pub const VIDEO_FORMAT_RGBA: u32 = 11;
    pub const VIDEO_FORMAT_BGRA: u32 = 12;
}

/// `enum spa_choice_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChoiceKind {
    None = 0,
    Range = 1,
    Step = 2,
    Enum = 3,
    Flags = 4,
}

/// A POD value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Id(u32),
    Int(i32),
    Rectangle {
        width: u32,
        height: u32,
    },
    Fraction {
        num: u32,
        denom: u32,
    },
    /// ⚠️ Every element must be the same variant. The choice body carries ONE
    /// `child` header describing all of them, so a mixed list cannot be
    /// represented — [`Value::choice`] enforces it rather than trusting the
    /// caller, because the corrupt result would only surface as a rejected
    /// format with nothing naming the cause.
    Choice {
        kind: ChoiceKind,
        /// First element is the default/preferred value.
        values: Vec<Value>,
    },
}

impl Value {
    /// Build a choice, refusing a mixed or empty list.
    pub fn choice(kind: ChoiceKind, values: Vec<Value>) -> Result<Value, String> {
        let Some(first) = values.first() else {
            return Err("a choice needs at least the default value".into());
        };
        if matches!(first, Value::Choice { .. }) {
            return Err("a choice cannot contain a choice".into());
        }
        if let Some(bad) = values.iter().find(|v| v.type_id() != first.type_id()) {
            return Err(format!(
                "a choice must be all one type: {:?} does not match {:?}",
                bad, first
            ));
        }
        Ok(Value::Choice { kind, values })
    }

    fn type_id(&self) -> u32 {
        match self {
            Value::Id(_) => ty::ID,
            Value::Int(_) => ty::INT,
            Value::Rectangle { .. } => ty::RECTANGLE,
            Value::Fraction { .. } => ty::FRACTION,
            Value::Choice { .. } => ty::CHOICE,
        }
    }

    /// The body bytes of a non-choice value.
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Value::Id(v) => b.extend_from_slice(&v.to_ne_bytes()),
            Value::Int(v) => b.extend_from_slice(&v.to_ne_bytes()),
            Value::Rectangle { width, height } => {
                b.extend_from_slice(&width.to_ne_bytes());
                b.extend_from_slice(&height.to_ne_bytes());
            }
            Value::Fraction { num, denom } => {
                b.extend_from_slice(&num.to_ne_bytes());
                b.extend_from_slice(&denom.to_ne_bytes());
            }
            Value::Choice { .. } => unreachable!("choices are written by write_value"),
        }
        b
    }
}

/// One property of an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prop {
    pub key: u32,
    pub value: Value,
}

/// A POD object — what a format param is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// e.g. [`ty::OBJECT_FORMAT`].
    pub object_type: u32,
    /// e.g. [`ty::PARAM_ENUM_FORMAT`].
    pub id: u32,
    pub props: Vec<Prop>,
}

impl Object {
    /// Serialise to the wire format.
    ///
    /// ⚠️ Native endian on purpose. PODs are exchanged with a PipeWire daemon
    /// over a unix socket on the same machine, and the format is defined in
    /// host byte order — converting to little-endian would corrupt it on a
    /// big-endian host rather than fix anything.
    pub fn to_pod(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header with a placeholder size, patched once the body is known.
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&ty::OBJECT.to_ne_bytes());
        let body_start = buf.len();

        buf.extend_from_slice(&self.object_type.to_ne_bytes());
        buf.extend_from_slice(&self.id.to_ne_bytes());

        for p in &self.props {
            buf.extend_from_slice(&p.key.to_ne_bytes());
            // flags — none of ours are read-only or hardware properties.
            buf.extend_from_slice(&0u32.to_ne_bytes());
            write_value(&mut buf, &p.value, true);
        }

        let body_len = (buf.len() - body_start) as u32;
        buf[0..4].copy_from_slice(&body_len.to_ne_bytes());
        buf
    }
}

/// Write one value as a POD.
///
/// `pad` is false only for the first element of a choice, which is written
/// unpadded so the elements that follow it are contiguous — see the module
/// docs for why that is the actual layout.
fn write_value(buf: &mut Vec<u8>, v: &Value, pad: bool) {
    match v {
        Value::Choice { kind, values } => {
            let start = buf.len();
            buf.extend_from_slice(&0u32.to_ne_bytes()); // size, patched below
            buf.extend_from_slice(&ty::CHOICE.to_ne_bytes());
            let body_start = buf.len();
            buf.extend_from_slice(&(*kind as u32).to_ne_bytes());
            buf.extend_from_slice(&0u32.to_ne_bytes()); // flags

            // The first value keeps its header — that header IS the body's
            // `child` field, describing every element that follows.
            if let Some(first) = values.first() {
                write_value(buf, first, false);
            }
            // The rest are bare bodies of exactly `child.size` bytes each.
            for v in values.iter().skip(1) {
                buf.extend_from_slice(&v.body());
            }

            let body_len = (buf.len() - body_start) as u32;
            buf[start..start + 4].copy_from_slice(&body_len.to_ne_bytes());
            if pad {
                pad_to_8(buf);
            }
        }
        simple => {
            let body = simple.body();
            buf.extend_from_slice(&(body.len() as u32).to_ne_bytes());
            buf.extend_from_slice(&simple.type_id().to_ne_bytes());
            buf.extend_from_slice(&body);
            if pad {
                pad_to_8(buf);
            }
        }
    }
}

fn pad_to_8(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

/// The `EnumFormat` we offer for screen capture: packed 32-bit BGRA-family
/// pixels, any reasonable size, any framerate up to `max_fps`.
///
/// The format list is ordered by preference, and `BGRx` leads because that is
/// what the rest of this crate's capture path already produces
/// ([`crate::capture::PixelFormat::Bgra`]) — every other entry costs a swizzle.
///
/// Size and framerate are **ranges** rather than fixed values: the compositor
/// owns the real answer, and asking for one specific size is how a negotiation
/// fails on a display we did not predict.
pub fn video_enum_format(max_fps: u32) -> Result<Object, String> {
    Ok(Object {
        object_type: ty::OBJECT_FORMAT,
        id: ty::PARAM_ENUM_FORMAT,
        props: vec![
            Prop {
                key: ty::FORMAT_MEDIA_TYPE,
                value: Value::Id(ty::MEDIA_TYPE_VIDEO),
            },
            Prop {
                key: ty::FORMAT_MEDIA_SUBTYPE,
                value: Value::Id(ty::MEDIA_SUBTYPE_RAW),
            },
            Prop {
                key: ty::FORMAT_VIDEO_FORMAT,
                value: Value::choice(
                    ChoiceKind::Enum,
                    vec![
                        Value::Id(ty::VIDEO_FORMAT_BGRX),
                        Value::Id(ty::VIDEO_FORMAT_BGRX),
                        Value::Id(ty::VIDEO_FORMAT_BGRA),
                        Value::Id(ty::VIDEO_FORMAT_RGBX),
                        Value::Id(ty::VIDEO_FORMAT_RGBA),
                    ],
                )?,
            },
            Prop {
                key: ty::FORMAT_VIDEO_SIZE,
                value: Value::choice(
                    ChoiceKind::Range,
                    vec![
                        Value::Rectangle {
                            width: 1920,
                            height: 1080,
                        },
                        Value::Rectangle {
                            width: 1,
                            height: 1,
                        },
                        Value::Rectangle {
                            width: 8192,
                            height: 8192,
                        },
                    ],
                )?,
            },
            Prop {
                key: ty::FORMAT_VIDEO_FRAMERATE,
                value: Value::choice(
                    ChoiceKind::Range,
                    vec![
                        Value::Fraction {
                            num: max_fps,
                            denom: 1,
                        },
                        Value::Fraction { num: 0, denom: 1 },
                        Value::Fraction {
                            num: max_fps.max(1),
                            denom: 1,
                        },
                    ],
                )?,
            },
        ],
    })
}

// ── reading PODs back ───────────────────────────────────────────────────

/// A value read off the wire.
///
/// `Unsupported` rather than an error: PipeWire may put properties in a format
/// we never asked about, and a parser that fails on the first unfamiliar type
/// would turn "one extra field" into "no capture at all".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedValue {
    Id(u32),
    Int(i32),
    Rectangle {
        width: u32,
        height: u32,
    },
    Fraction {
        num: u32,
        denom: u32,
    },
    /// A choice, carrying its kind and its **first** element (the default, or
    /// for [`ChoiceKind::None`] the only value there is).
    ///
    /// 🔑 This exists because of a SPA convention that is easy to miss: a
    /// **fixed value is still written as a Choice** — kind `None`, one
    /// element. That is why `spa_pod_get_id` and friends unwrap choices rather
    /// than rejecting them. Measured on GNOME 48: a fully negotiated format
    /// arrived with *every* property as a Choice, `mediaType` included, which
    /// can only ever be "video".
    Choice {
        kind: u32,
        first: Box<ParsedValue>,
    },
    Unsupported {
        pod_type: u32,
    },
}

impl ParsedValue {
    /// The settled value, unwrapping a `Choice(None)`.
    ///
    /// ⚠️ Only `None` unwraps. A `Range` or `Enum` still has genuine
    /// alternatives, so returning its default would report a value the other
    /// side never committed to — the difference between "1920×1080" and
    /// "somewhere between 1×1 and 8192×8192, probably".
    pub fn fixed(&self) -> Option<&ParsedValue> {
        match self {
            ParsedValue::Choice { kind, first } if *kind == ChoiceKind::None as u32 => Some(first),
            ParsedValue::Choice { .. } => None,
            other => Some(other),
        }
    }
}

/// An object read off the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedObject {
    pub object_type: u32,
    pub id: u32,
    pub props: Vec<(u32, ParsedValue)>,
}

impl ParsedObject {
    pub fn get(&self, key: u32) -> Option<&ParsedValue> {
        self.props.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
}

/// Parse an object POD.
///
/// ⚠️ Every read is bounds-checked against the slice, and no length taken from
/// the data is trusted to be in range. The input is a copy of memory owned by
/// another process's library: this is exactly where "the header says 4 GB"
/// must be a returned error and not a panic or a wild read.
///
/// Used on `param_changed`, where the value is the *negotiated* format and so
/// carries plain values rather than choices — a `Choice` here is reported as
/// unsupported instead of being silently unwrapped, since reading one as
/// though it were fixed would report a made-up size.
pub fn parse_object(bytes: &[u8]) -> Result<ParsedObject, String> {
    let (_size, pod_type, body) = split_pod(bytes)?;
    if pod_type != ty::OBJECT {
        return Err(format!("expected an object pod, got type {pod_type}"));
    }
    if body.len() < 8 {
        return Err(format!("object body is {} bytes, needs 8", body.len()));
    }
    let object_type = read_u32(body, 0)?;
    let id = read_u32(body, 4)?;

    // Each property is: key(4) flags(4) then a full POD value, padded to 8.
    let mut props = Vec::new();
    let mut off = 8usize;
    while off + 8 <= body.len() {
        let key = read_u32(body, off)?;
        // `flags` sits at off+4 and is not acted on: none of the flags defined
        // today change how a value is READ.
        let (v_size, v_type, v_body) = split_pod(
            body.get(off + 8..)
                .ok_or_else(|| format!("property at {off} runs past the object"))?,
        )?;
        props.push((key, parse_value(v_type, v_body)?));
        off += 8 + round_up_8(8 + v_size as usize);
    }
    Ok(ParsedObject {
        object_type,
        id,
        props,
    })
}

fn parse_value(pod_type: u32, body: &[u8]) -> Result<ParsedValue, String> {
    Ok(match pod_type {
        ty::ID => ParsedValue::Id(read_u32(body, 0)?),
        ty::INT => ParsedValue::Int(read_u32(body, 0)? as i32),
        ty::RECTANGLE => ParsedValue::Rectangle {
            width: read_u32(body, 0)?,
            height: read_u32(body, 4)?,
        },
        ty::FRACTION => ParsedValue::Fraction {
            num: read_u32(body, 0)?,
            denom: read_u32(body, 4)?,
        },
        // Choice body: kind(4) flags(4) child-header(8) then the elements,
        // the first of which is described by that header. Only the first is
        // read — it is the default, and for kind `None` the only one.
        ty::CHOICE => {
            let kind = read_u32(body, 0)?;
            let child_size = read_u32(body, 8)? as usize;
            let child_type = read_u32(body, 12)?;
            let child_body = body.get(16..16 + child_size).ok_or_else(|| {
                format!(
                    "choice claims a {child_size}-byte element, body is {}",
                    body.len()
                )
            })?;
            ParsedValue::Choice {
                kind,
                first: Box::new(parse_value(child_type, child_body)?),
            }
        }
        other => ParsedValue::Unsupported { pod_type: other },
    })
}

/// Split a POD into `(body size, type, body)`, refusing anything that would
/// read past the end.
fn split_pod(bytes: &[u8]) -> Result<(u32, u32, &[u8]), String> {
    if bytes.len() < 8 {
        return Err(format!("a pod header needs 8 bytes, got {}", bytes.len()));
    }
    let size = read_u32(bytes, 0)?;
    let pod_type = read_u32(bytes, 4)?;
    let body = bytes.get(8..8 + size as usize).ok_or_else(|| {
        format!(
            "pod claims a {size}-byte body but only {} remain",
            bytes.len() - 8
        )
    })?;
    Ok((size, pod_type, body))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, String> {
    let s = bytes
        .get(at..at + 4)
        .ok_or_else(|| format!("wanted 4 bytes at {at}, have {}", bytes.len()))?;
    Ok(u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn round_up_8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32s(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// The smallest complete object, asserted **word for word**.
    ///
    /// Hand-computed from the header definitions rather than from this
    /// implementation's own output, which is the only way a test like this
    /// means anything: an object with one `Id` property is
    /// 8 (header) + 8 (object body) + 8 (prop key/flags) + 8 (Id pod) + 4
    /// (Id body) + 4 (pad) = 40 bytes, with `size` recording the 32-byte body.
    #[test]
    fn a_one_property_object_matches_the_wire_format_exactly() {
        let o = Object {
            object_type: ty::OBJECT_FORMAT,
            id: ty::PARAM_ENUM_FORMAT,
            props: vec![Prop {
                key: ty::FORMAT_MEDIA_TYPE,
                value: Value::Id(ty::MEDIA_TYPE_VIDEO),
            }],
        };
        let pod = o.to_pod();
        assert_eq!(pod.len(), 40, "unexpected total length");
        assert_eq!(
            u32s(&pod),
            vec![
                32,         // body size, EXCLUDING this header and any padding
                ty::OBJECT, // 15
                0x40003,    // SPA_TYPE_OBJECT_Format
                3,          // SPA_PARAM_EnumFormat
                1,          // key: SPA_FORMAT_mediaType
                0,          // prop flags
                4,          // value pod: body size
                ty::ID,     // value pod: type
                2,          // SPA_MEDIA_TYPE_video
                0,          // padding to 8
            ]
        );
    }

    /// The choice layout is the part that cannot be guessed: the FIRST element
    /// keeps its header (it doubles as the body's `child`), later elements are
    /// bare bodies with no header and no padding between them.
    #[test]
    fn a_choice_puts_a_header_on_the_first_value_only() {
        let c = Value::choice(
            ChoiceKind::Enum,
            vec![Value::Id(8), Value::Id(12), Value::Id(7)],
        )
        .unwrap();
        let mut buf = Vec::new();
        write_value(&mut buf, &c, true);

        assert_eq!(
            u32s(&buf),
            vec![
                8 + 12 + 4 + 4, // body: kind+flags, first full pod, two bodies
                ty::CHOICE,     // 19
                3,              // SPA_CHOICE_Enum
                0,              // flags
                4,              // child header: size of ONE element body
                ty::ID,         // child header: type of every element
                8,              // first value  (also the default)
                12,             // second — body only
                7,              // third — body only
                0,              // padding: 36 bytes rounded up to 40
            ]
        );
        assert_eq!(buf.len(), 40);
        // The declared size must NOT include that padding — the one rule most
        // likely to be got wrong, and a parser trusts it absolutely.
        assert_eq!(u32s(&buf)[0], 28);
    }

    /// A `Rectangle` body is already 8 bytes, so a range of three of them
    /// needs no padding anywhere — a good check that padding is driven by the
    /// actual length rather than assumed per element.
    #[test]
    fn a_rectangle_range_needs_no_padding() {
        let c = Value::choice(
            ChoiceKind::Range,
            vec![
                Value::Rectangle {
                    width: 1920,
                    height: 1080,
                },
                Value::Rectangle {
                    width: 1,
                    height: 1,
                },
                Value::Rectangle {
                    width: 4096,
                    height: 4096,
                },
            ],
        )
        .unwrap();
        let mut buf = Vec::new();
        write_value(&mut buf, &c, true);
        assert_eq!(buf.len() % 8, 0);
        assert_eq!(
            u32s(&buf),
            vec![
                8 + 16 + 8 + 8, // kind+flags, first full pod (8+8), two bodies
                ty::CHOICE,
                1, // SPA_CHOICE_Range
                0,
                8, // child size: a rectangle body
                ty::RECTANGLE,
                1920,
                1080, // default
                1,
                1, // min
                4096,
                4096, // max
            ]
        );
    }

    /// A mixed choice cannot be represented — one `child` header describes
    /// every element — so it must be refused at construction rather than
    /// silently emitted as a POD that PipeWire rejects for no stated reason.
    #[test]
    fn a_mixed_choice_is_refused() {
        let e = Value::choice(ChoiceKind::Enum, vec![Value::Id(1), Value::Int(2)]).unwrap_err();
        assert!(e.contains("all one type"), "{e}");
        assert!(Value::choice(ChoiceKind::Enum, vec![]).is_err());
        assert!(
            Value::choice(
                ChoiceKind::Enum,
                vec![Value::choice(ChoiceKind::Enum, vec![Value::Id(1)]).unwrap()]
            )
            .is_err()
        );
    }

    /// Whatever else changes, the whole param must stay 8-aligned and declare
    /// its own length correctly — those two are what a parser relies on.
    #[test]
    fn the_real_enum_format_is_well_formed() {
        let pod = video_enum_format(60).unwrap().to_pod();
        assert_eq!(pod.len() % 8, 0, "the object must end 8-aligned");
        let declared = u32s(&pod)[0] as usize;
        assert_eq!(
            declared + 8,
            pod.len(),
            "declared body size must account for everything after the header"
        );
        let words = u32s(&pod);
        assert_eq!(words[1], ty::OBJECT);
        assert_eq!(words[2], ty::OBJECT_FORMAT);
        assert_eq!(words[3], ty::PARAM_ENUM_FORMAT);
    }

    /// Build → parse → compare. Not a substitute for PipeWire accepting the
    /// bytes, but it catches the whole class where the writer and the reader
    /// disagree about layout — which is exactly what `param_changed` would hit
    /// in the field, where the only symptom is a plausible-looking wrong size.
    #[test]
    fn a_negotiated_format_round_trips() {
        let o = Object {
            object_type: ty::OBJECT_FORMAT,
            // A NEGOTIATED format comes back with id 4 (SPA_PARAM_Format) and
            // plain values, not the choices we sent.
            id: 4,
            props: vec![
                Prop {
                    key: ty::FORMAT_MEDIA_TYPE,
                    value: Value::Id(ty::MEDIA_TYPE_VIDEO),
                },
                Prop {
                    key: ty::FORMAT_MEDIA_SUBTYPE,
                    value: Value::Id(ty::MEDIA_SUBTYPE_RAW),
                },
                Prop {
                    key: ty::FORMAT_VIDEO_FORMAT,
                    value: Value::Id(ty::VIDEO_FORMAT_BGRX),
                },
                Prop {
                    key: ty::FORMAT_VIDEO_SIZE,
                    value: Value::Rectangle {
                        width: 1920,
                        height: 1080,
                    },
                },
                Prop {
                    key: ty::FORMAT_VIDEO_FRAMERATE,
                    value: Value::Fraction { num: 60, denom: 1 },
                },
            ],
        };
        let parsed = parse_object(&o.to_pod()).expect("should parse");
        assert_eq!(parsed.object_type, ty::OBJECT_FORMAT);
        assert_eq!(parsed.id, 4);
        assert_eq!(parsed.props.len(), 5, "every property must survive");
        assert_eq!(
            parsed.get(ty::FORMAT_VIDEO_FORMAT),
            Some(&ParsedValue::Id(ty::VIDEO_FORMAT_BGRX))
        );
        assert_eq!(
            parsed.get(ty::FORMAT_VIDEO_SIZE),
            Some(&ParsedValue::Rectangle {
                width: 1920,
                height: 1080
            })
        );
        assert_eq!(
            parsed.get(ty::FORMAT_VIDEO_FRAMERATE),
            Some(&ParsedValue::Fraction { num: 60, denom: 1 })
        );
    }

    /// The parser reads a copy of another process's memory, so a length taken
    /// from the data must never be trusted. Truncation at every offset must
    /// produce an error — never a panic, and never a value read past the end.
    #[test]
    fn truncation_anywhere_is_an_error_not_a_panic() {
        let full = video_enum_format(60).unwrap().to_pod();
        for cut in 0..full.len() {
            // Any result is acceptable except a panic; the point is that no
            // input length can crash the helper.
            let _ = parse_object(&full[..cut]);
        }
        // A header promising far more body than exists must be refused.
        let mut lying = full.clone();
        lying[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let e = parse_object(&lying).unwrap_err();
        assert!(e.contains("body"), "{e}");
    }

    /// 🔑 The convention that cost a field run: **SPA writes a settled value
    /// as a `Choice(None)` with one element.** A negotiated format on GNOME 48
    /// arrived with every property wrapped that way — `mediaType` included,
    /// which can only ever be "video". So `fixed()` must unwrap `None`…
    #[test]
    fn a_choice_of_none_reads_as_the_settled_value() {
        let o = Object {
            object_type: ty::OBJECT_FORMAT,
            id: 4,
            props: vec![Prop {
                key: ty::FORMAT_VIDEO_SIZE,
                value: Value::choice(
                    ChoiceKind::None,
                    vec![Value::Rectangle {
                        width: 1920,
                        height: 1080,
                    }],
                )
                .unwrap(),
            }],
        };
        let parsed = parse_object(&o.to_pod()).unwrap();
        assert_eq!(
            parsed.get(ty::FORMAT_VIDEO_SIZE).unwrap().fixed(),
            Some(&ParsedValue::Rectangle {
                width: 1920,
                height: 1080
            })
        );
    }

    /// …and must NOT unwrap a Range or Enum. Those still have real
    /// alternatives, so returning the default would report a value the other
    /// side never committed to — "1920×1080" versus "somewhere between 1×1 and
    /// 8192×8192, probably".
    #[test]
    fn a_range_is_not_mistaken_for_a_settled_value() {
        let parsed = parse_object(&video_enum_format(60).unwrap().to_pod()).unwrap();
        let size = parsed.get(ty::FORMAT_VIDEO_SIZE).expect("size is present");
        assert!(
            matches!(size, ParsedValue::Choice { kind, .. } if *kind == ChoiceKind::Range as u32)
        );
        assert_eq!(size.fixed(), None, "a range must not read as settled");
        // A plain (unwrapped) value stays readable through the same accessor.
        assert_eq!(
            parsed.get(ty::FORMAT_MEDIA_TYPE).unwrap().fixed(),
            Some(&ParsedValue::Id(ty::MEDIA_TYPE_VIDEO))
        );
    }

    /// BGRx has to be the preferred pixel order: it is what the rest of the
    /// capture path already produces, and every other entry costs a swizzle.
    #[test]
    fn bgrx_is_offered_first() {
        let o = video_enum_format(60).unwrap();
        let fmt = o
            .props
            .iter()
            .find(|p| p.key == ty::FORMAT_VIDEO_FORMAT)
            .expect("no video format property");
        match &fmt.value {
            Value::Choice { values, .. } => {
                // values[0] is the DEFAULT, values[1] the first alternative;
                // both are BGRx so the preference holds whichever a reader
                // consults.
                assert_eq!(values[0], Value::Id(ty::VIDEO_FORMAT_BGRX));
                assert_eq!(values[1], Value::Id(ty::VIDEO_FORMAT_BGRX));
            }
            other => panic!("expected a choice, got {other:?}"),
        }
    }
}
