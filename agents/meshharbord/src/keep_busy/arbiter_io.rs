// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — the pointer reads and moves every OS host asks the input arbiter
//! for. The arbiter owns the ONE injector, on its own thread (rebound to the
//! input desktop under a Windows SystemContext worker), so keep busy is
//! another input source and never a second injector.

use super::engine::{HostError, Reason};
use crate::input::arbiter::{self, KbOp, KbReply};

/// An arbiter answer that is not the one asked for.
pub fn map_err(r: KbReply) -> HostError {
    match r {
        KbReply::RemoteButtonHeld => HostError::RemoteButtonHeld,
        KbReply::Unsupported => HostError::Unsupported(Reason::Unsupported),
        KbReply::NoPermission => HostError::Unsupported(Reason::NoPermission),
        KbReply::Failed(e) => HostError::Failed(e),
        other => HostError::Failed(format!("unexpected arbiter reply {other:?}")),
    }
}

/// Where the pointer is, in the injector's pixel space.
pub fn cursor() -> Result<(i32, i32), HostError> {
    match arbiter::global().keep_busy(KbOp::Locate) {
        KbReply::Located(x, y) => Ok((x, y)),
        other => Err(map_err(other)),
    }
}

/// Move the pointer — refused while a controller holds a mouse button.
pub fn move_to(p: (i32, i32)) -> Result<(), HostError> {
    match arbiter::global().keep_busy(KbOp::Move { x: p.0, y: p.1 }) {
        KbReply::Moved => {
            // FR-108 — this move is the machine's, not a person's.
            super::note_own_move();
            Ok(())
        }
        other => Err(map_err(other)),
    }
}

/// FR-92 P9 — move to a fraction of the whole desktop, for an injector with no
/// pixel space (uinput, below the compositor). Refused, like a pixel move,
/// while a controller holds a mouse button.
#[cfg_attr(
    not(all(
        target_os = "linux",
        feature = "uinput-input",
        feature = "portal-capture"
    )),
    allow(dead_code)
)]
pub fn move_norm(fx: f64, fy: f64) -> Result<(), HostError> {
    let q = |f: f64| (f.clamp(0.0, 1.0) * f64::from(arbiter::NORM_ONE)).round() as u32;
    match arbiter::global().keep_busy(KbOp::MoveNorm { x: q(fx), y: q(fy) }) {
        KbReply::Moved => {
            super::note_own_move();
            Ok(())
        }
        other => Err(map_err(other)),
    }
}

/// Is a physical mouse button held, as the injector's platform reads it?
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn buttons() -> Result<bool, HostError> {
    match arbiter::global().keep_busy(KbOp::Buttons) {
        KbReply::Buttons(b) => Ok(b),
        other => Err(map_err(other)),
    }
}
