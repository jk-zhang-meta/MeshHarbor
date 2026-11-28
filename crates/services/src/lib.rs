// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
pub mod auth;
pub mod background;
pub mod cloud_storage;
pub mod dao;
pub mod email;
pub mod oauth;
pub mod push;
pub mod quota;
pub mod relay_allowance;

pub use auth::AuthService;
pub use background::TaskService;
pub use dao::*;
pub use email::EmailService;
pub use oauth::OAuthService;
pub use push::PushService;
