// SPDX-License-Identifier: MPL-2.0
//! v039 — the loss test an ORG loss window is judged by. Ungated (unlike
//! `overlay`): the member that closes a window and the server that judges
//! its report (built without the data plane) share it.

/// v039 — is a window of `packets` with `lost` of them missing CLEARLY losing
/// at least `pct` percent? The Wilson score lower bound at z = 3 (one-sided,
/// ~99.9%), from [`EARLY_LOSS_MIN_PACKETS`] up. A relay losing 10% is judged
/// at ~200 packets, where a fixed 1000-packet window takes ~7 min at a light
/// stream's ~2.4 packets/s and reaches back to before the loss began (field
/// 2026-10-27, rf-a728a26325a1: read 4.6%). Shared by the member that closes
/// an ORG loss window and the server that judges its report.
pub fn loss_clearly_at_least(packets: u64, lost: u64, pct: f64) -> bool {
    const Z: f64 = 3.0;
    if packets < EARLY_LOSS_MIN_PACKETS {
        return false;
    }
    let n = packets as f64;
    let p = lost.min(packets) as f64 / n;
    let z2 = Z * Z;
    let lower =
        (p + z2 / (2.0 * n) - Z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt()) / (1.0 + z2 / n);
    lower * 100.0 >= pct
}

/// Fewer packets than this are never judged early, whatever they lost.
pub const EARLY_LOSS_MIN_PACKETS: u64 = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_is_clear_only_with_enough_packets_well_over_the_line() {
        assert!(loss_clearly_at_least(200, 20, 5.0), "10% of 200");
        assert!(!loss_clearly_at_least(150, 15, 5.0), "10% of 150: not yet");
        assert!(!loss_clearly_at_least(999, 60, 5.0), "6% of 999: not clear");
        assert!(loss_clearly_at_least(31_000, 2_294, 5.0), "7.4% of 31000");
        assert!(!loss_clearly_at_least(99, 99, 5.0), "under the floor");
        assert!(
            loss_clearly_at_least(100, u64::MAX, 5.0),
            "capped at the span"
        );
        assert!(!loss_clearly_at_least(u64::MAX, 0, 5.0));
        assert!(!loss_clearly_at_least(0, 0, 5.0));
    }
}
