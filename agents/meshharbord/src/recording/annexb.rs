// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 — Annex-B ⇄ MP4 sample conversion for the recorder.
//!
//! Every encoder the agent owns emits **Annex-B** access units (start-code
//! delimited NAL units): openh264, Media Foundation and the FFmpeg backends
//! alike. MP4 (`avc1`) wants the opposite framing — each NAL prefixed by its
//! big-endian length — and wants the parameter sets **out** of the samples and
//! in the sample entry's `avcC`. This module does exactly that conversion and
//! nothing else; it never interprets slice data.
//!
//! ⚠️ `avc1` (not `avc3`) is chosen on purpose: it is the one every player and
//! editor accepts, and the recorder's encoder config never changes mid-file,
//! so the parameter sets are genuinely constant. A parameter set that DOES
//! change mid-recording is reported by [`AccessUnit::param_sets_differ`] and the
//! recorder stops rather than writing an `avc1` file that lies about itself.

/// H.264 NAL unit types the conversion cares about (ITU-T H.264 Table 7-1).
pub mod h264 {
    pub const SLICE_IDR: u8 = 5;
    pub const SEI: u8 = 6;
    pub const SPS: u8 = 7;
    pub const PPS: u8 = 8;
    pub const AUD: u8 = 9;

    /// `nal_unit_type` of an H.264 NAL (the low five bits of its first byte).
    pub fn nal_type(nal: &[u8]) -> Option<u8> {
        nal.first().map(|b| b & 0x1F)
    }
}

/// Split an Annex-B buffer into its NAL units, start codes removed.
///
/// Accepts both 3-byte (`00 00 01`) and 4-byte (`00 00 00 01`) start codes,
/// in any mix, and tolerates leading garbage before the first start code (it
/// is dropped — an encoder never emits any, and a partial NAL is not worth
/// guessing at). Trailing zero bytes of a NAL (`trailing_zero_8bits`) are
/// stripped, so a 4-byte start code never leaves a stray `00` on the NAL
/// before it.
pub fn split_nals(data: &[u8]) -> Vec<&[u8]> {
    let mut starts: Vec<(usize, usize)> = Vec::new(); // (start-code offset, payload offset)
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                starts.push((i, i + 3));
                i += 3;
                continue;
            }
            if data[i + 2] == 0 && i + 4 <= data.len() && data[i + 3] == 1 {
                starts.push((i, i + 4));
                i += 4;
                continue;
            }
        }
        i += 1;
    }
    let mut out = Vec::with_capacity(starts.len());
    for (k, &(_, payload)) in starts.iter().enumerate() {
        let end = starts.get(k + 1).map(|&(sc, _)| sc).unwrap_or(data.len());
        let mut nal = &data[payload..end];
        while let [rest @ .., 0] = nal {
            nal = rest;
        }
        if !nal.is_empty() {
            out.push(nal);
        }
    }
    out
}

/// One encoded H.264 access unit, split into what the MP4 writer needs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AccessUnit {
    /// The sample payload: every NAL except SPS/PPS/AUD, each prefixed by a
    /// 4-byte big-endian length (`avcC.length_size = 4`).
    pub sample: Vec<u8>,
    /// SPS NALs seen in this access unit (usually only on keyframes).
    pub sps: Vec<Vec<u8>>,
    /// PPS NALs seen in this access unit.
    pub pps: Vec<Vec<u8>>,
    /// Whether an IDR slice is present.
    pub has_idr: bool,
}

impl AccessUnit {
    /// Parse one H.264 Annex-B access unit.
    pub fn from_annexb_h264(data: &[u8]) -> Self {
        let mut au = AccessUnit::default();
        for nal in split_nals(data) {
            match h264::nal_type(nal) {
                Some(h264::SPS) => au.sps.push(nal.to_vec()),
                Some(h264::PPS) => au.pps.push(nal.to_vec()),
                // Access-unit delimiters carry nothing an MP4 sample needs,
                // and ISO/IEC 14496-15 recommends against keeping them.
                Some(h264::AUD) => {}
                Some(t) => {
                    if t == h264::SLICE_IDR {
                        au.has_idr = true;
                    }
                    push_length_prefixed(&mut au.sample, nal);
                }
                None => {}
            }
        }
        au
    }

    /// `true` when this access unit carries parameter sets that differ from
    /// the ones already written into the file's `avcC`.
    pub fn param_sets_differ(&self, sps: &[Vec<u8>], pps: &[Vec<u8>]) -> bool {
        (!self.sps.is_empty() && self.sps != sps) || (!self.pps.is_empty() && self.pps != pps)
    }
}

/// Append `nal` to `out` with a 4-byte big-endian length prefix.
pub fn push_length_prefixed(out: &mut Vec<u8>, nal: &[u8]) {
    out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
    out.extend_from_slice(nal);
}

/// The inverse of [`AccessUnit::sample`]: turn a 4-byte length-prefixed MP4
/// sample back into Annex-B, for a decoder that wants start codes (openh264,
/// the test oracle). Returns `None` on a truncated or inconsistent sample.
pub fn length_prefixed_to_annexb(sample: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(sample.len() + 16);
    let mut i = 0usize;
    while i < sample.len() {
        let len = u32::from_be_bytes(sample.get(i..i + 4)?.try_into().ok()?) as usize;
        i += 4;
        let nal = sample.get(i..i + len)?;
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(nal);
        i += len;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_three_and_four_byte_start_codes() {
        let data = [
            0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 3, 0, 0, 0, 1, 0x65, 9, 9,
        ];
        let nals = split_nals(&data);
        assert_eq!(
            nals,
            vec![&[0x67u8, 1, 2][..], &[0x68, 3][..], &[0x65, 9, 9][..]]
        );
    }

    #[test]
    fn a_four_byte_start_code_leaves_no_trailing_zero_on_the_previous_nal() {
        // The `00` of `00 00 00 01` belongs to the start code, not to the NAL.
        let data = [0, 0, 1, 0x41, 7, 0, 0, 0, 1, 0x41, 8];
        let nals = split_nals(&data);
        assert_eq!(nals, vec![&[0x41u8, 7][..], &[0x41, 8][..]]);
    }

    #[test]
    fn leading_garbage_is_dropped() {
        let data = [9, 9, 0, 0, 1, 0x41, 1];
        assert_eq!(split_nals(&data), vec![&[0x41u8, 1][..]]);
    }

    #[test]
    fn an_idr_access_unit_moves_parameter_sets_out_and_drops_the_aud() {
        let data = [
            0, 0, 0, 1, 0x09, 0x10, // AUD
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, // SPS
            0, 0, 0, 1, 0x68, 0xce, // PPS
            0, 0, 0, 1, 0x65, 0x88, 0x80, // IDR slice
        ];
        let au = AccessUnit::from_annexb_h264(&data);
        assert!(au.has_idr);
        assert_eq!(au.sps, vec![vec![0x67, 0x42, 0x00, 0x1f]]);
        assert_eq!(au.pps, vec![vec![0x68, 0xce]]);
        assert_eq!(au.sample, vec![0, 0, 0, 3, 0x65, 0x88, 0x80]);
    }

    #[test]
    fn a_non_idr_access_unit_has_no_parameter_sets() {
        let data = [0, 0, 0, 1, 0x41, 0x9a, 0x01];
        let au = AccessUnit::from_annexb_h264(&data);
        assert!(!au.has_idr);
        assert!(au.sps.is_empty() && au.pps.is_empty());
        assert_eq!(au.sample, vec![0, 0, 0, 3, 0x41, 0x9a, 0x01]);
    }

    #[test]
    fn length_prefixed_round_trips_to_annexb() {
        let mut sample = Vec::new();
        push_length_prefixed(&mut sample, &[0x65, 1, 2]);
        push_length_prefixed(&mut sample, &[0x06, 5]);
        let annexb = length_prefixed_to_annexb(&sample).unwrap();
        assert_eq!(annexb, vec![0, 0, 0, 1, 0x65, 1, 2, 0, 0, 0, 1, 0x06, 5]);
        assert_eq!(
            split_nals(&annexb),
            vec![&[0x65u8, 1, 2][..], &[0x06, 5][..]]
        );
    }

    #[test]
    fn a_truncated_length_prefixed_sample_is_refused() {
        assert!(length_prefixed_to_annexb(&[0, 0, 0, 9, 1, 2]).is_none());
        assert!(length_prefixed_to_annexb(&[0, 0, 1]).is_none());
    }

    #[test]
    fn changed_parameter_sets_are_detected() {
        let au = AccessUnit {
            sps: vec![vec![0x67, 1]],
            ..Default::default()
        };
        assert!(!au.param_sets_differ(&[vec![0x67, 1]], &[]));
        assert!(au.param_sets_differ(&[vec![0x67, 2]], &[]));
        // An access unit with no parameter sets never "differs".
        assert!(!AccessUnit::default().param_sets_differ(&[vec![0x67, 2]], &[vec![0x68]]));
    }
}
