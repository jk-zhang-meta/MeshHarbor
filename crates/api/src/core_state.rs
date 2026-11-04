// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-69 P1b — `Core` lives in `meshharbor-core` now (`meshharbor_core::Core`);
//! this module keeps the api-side glue under the path P1a introduced.
//!
//! The one thing that cannot move with it is the `FromRef` impl below: the
//! orphan rules let this crate write it because `AppState` is local, and
//! `meshharbor-core` must not know `AppState` exists. It is what makes
//! `State<Core>` work in a handler while the router's state is still
//! `AppState`.

use axum::extract::FromRef;

pub use meshharbor_core::Core;

use crate::state::AppState;

impl FromRef<AppState> for Core {
    fn from_ref(state: &AppState) -> Self {
        state.core.clone()
    }
}
