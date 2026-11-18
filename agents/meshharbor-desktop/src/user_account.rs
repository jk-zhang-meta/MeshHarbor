// SPDX-License-Identifier: MPL-2.0
//! GUI-only user session. Daemon IPC never enters this module; public callers
//! receive only a loopback launch URL or status — with ONE exception,
//! [`mint_promotion_token`]: a single-use enrollment token, minted under this
//! session, handed straight to this device's own system promotion.
use meshharbor_node_core::user_session::{
    self, NativeSession, UserProfile, WebTarget,
    vault::{self, SavedSession},
};
use std::sync::{LazyLock, Mutex};

#[derive(Clone, Debug, Default)]
struct Badge {
    server: String,
    email: Option<String>,
    verified_now: bool,
    checked_at: Option<std::time::Instant>,
}
static BADGE: LazyLock<Mutex<Badge>> = LazyLock::new(|| Mutex::new(Badge::default()));
static SESSION_OP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn badge(server: &str, user: Option<&UserProfile>, fresh: bool) {
    if let Ok(mut value) = BADGE.lock() {
        *value = Badge {
            server: server.into(),
            email: user.map(|u| u.email.clone()),
            verified_now: fresh,
            checked_at: Some(std::time::Instant::now()),
        };
    }
}
pub fn has_identity(server: &str) -> bool {
    BADGE
        .lock()
        .ok()
        .is_some_and(|v| v.server == server && v.email.is_some())
}
pub fn label(server: &str, connected: bool) -> (String, bool) {
    let value = BADGE.lock().ok();
    label_for(value.as_deref(), server, connected)
}
fn label_for(value: Option<&Badge>, server: &str, connected: bool) -> (String, bool) {
    match value
        .filter(|v| v.server == server)
        .and_then(|v| v.email.as_ref().map(|email| (v, email)))
    {
        Some((value, email))
            if value.verified_now
                && connected
                && value.checked_at.is_some_and(|t| t.elapsed().as_secs() < 90) =>
        {
            (format!("Signed in as {email}"), false)
        }
        Some((_, email)) => (format!("{email} · offline / session unconfirmed"), true),
        None => ("Sign in…".into(), true),
    }
}
pub async fn load_cached_identity(server: String) {
    if BADGE.lock().is_ok_and(|v| v.server == server) {
        let due = BADGE.lock().is_ok_and(|v| {
            v.email.is_some() && v.checked_at.is_none_or(|t| t.elapsed().as_secs() >= 60)
        });
        if due {
            if let Ok(_operation) = SESSION_OP.try_lock() {
                let _ = refreshed(&server).await;
            }
        }
        return;
    }
    let scope = server.clone();
    match tokio::task::spawn_blocking(move || vault::load(&scope)).await {
        Ok(Ok(Some(saved))) => {
            badge(&server, Some(&saved.user), false);
            if let Ok(_operation) = SESSION_OP.try_lock() {
                let _ = refreshed(&server).await;
            }
        }
        _ => badge(&server, None, false),
    }
}
pub async fn save_login(server: String, session: NativeSession) -> Result<(), String> {
    let _operation = SESSION_OP.lock().await;
    session.validate().map_err(|e| e.to_string())?;
    // Replacing this GUI's authorization also revokes its previous derived
    // browser sessions; do not leave an inaccessible old sid behind on switch.
    let old_scope = server.clone();
    let old = tokio::task::spawn_blocking(move || vault::load(&old_scope))
        .await
        .map_err(|_| "OS credential read task failed")?
        .map_err(|_| "Cannot read the previous account authorization")?;
    if let Some(old) = old {
        if old.refresh_token != session.refresh_token {
            match user_session::refresh(&server, &old.refresh_token).await {
                Ok(prior) => match user_session::revoke(&server, &prior.access_token).await {
                    Ok(()) => {}
                    Err(error) if error.downcast_ref::<user_session::SessionDenied>().is_some() => {}
                    Err(error) => return Err(error.to_string()),
                },
                Err(error) if error.downcast_ref::<user_session::SessionDenied>().is_some() => {}
                Err(_) => return Err("Cannot confirm revocation of the previous account session; authorization was not replaced".into()),
            }
        }
    }
    let profile = session.user.clone();
    let scope = server.clone();
    tokio::task::spawn_blocking(move||vault::save(&SavedSession{server:scope,refresh_token:session.refresh_token,user:session.user})).await.map_err(|_|"OS credential save task failed")?.map_err(|_|"User approval succeeded, but the OS credential store could not save it. Unlock the OS vault and sign in again.")?;
    badge(&server, Some(&profile), true);
    Ok(())
}

async fn refreshed(server: &str) -> Result<NativeSession, String> {
    let scope = server.to_owned();
    let saved=tokio::task::spawn_blocking(move||vault::load(&scope)).await.map_err(|_|"OS credential read task failed")?.map_err(|_|"Cannot read the OS credential store; unlock it and sign in again")?.ok_or("Sign in to your account once from the tray before opening a web session. Device enrollment is not a user login.")?;
    match user_session::refresh(server, &saved.refresh_token).await {
        Ok(session) => {
            if session.user.id != saved.user.id {
                badge(server, None, false);
                return Err("Refreshed account identity did not match the stored authorization; sign in again".into());
            }
            let stored = SavedSession {
                server: server.into(),
                refresh_token: session.refresh_token.clone(),
                user: session.user.clone(),
            };
            tokio::task::spawn_blocking(move || vault::save(&stored))
                .await
                .map_err(|_| "OS credential update task failed")?
                .map_err(|_| "Cannot persist the refreshed user session in the OS vault")?;
            badge(server, Some(&session.user), true);
            Ok(session)
        }
        Err(error) => {
            if error
                .downcast_ref::<user_session::SessionDenied>()
                .is_some()
            {
                badge(server, None, false);
                let scope = server.to_owned();
                let _ = tokio::task::spawn_blocking(move || vault::delete(&scope)).await;
            } else {
                badge(server, Some(&saved.user), false);
            }
            Err(error.to_string())
        }
    }
}

pub async fn prepare(server: &str, target: WebTarget) -> Result<String, String> {
    let _operation = SESSION_OP.lock().await;
    let session = refreshed(server).await?;
    let listener = user_session::BrowserHandoff::bind()
        .await
        .map_err(|_| "Cannot bind the private account handoff listener")?;
    let handoff = user_session::handoff(
        server,
        &session.access_token,
        &target,
        listener
            .port()
            .map_err(|_| "Account listener unavailable")?,
    )
    .await
    .map_err(|e| e.to_string())?;
    let url = listener.launch_url();
    let handle = listener.serve(handoff);
    tauri::async_runtime::spawn(async move {
        // Never log ticket, HTTP body, refresh token, or launch route.
        if !matches!(handle.await, Ok(Ok(()))) {
            tracing::warn!("account handoff did not reach its browser before expiry");
        }
    });
    Ok(url)
}

/// The error text [`mint_promotion_token`] returns when no account is signed
/// in here; the UI matches on it to point at the tray's "Sign in…", which
/// grants the same rights as part of signing in.
pub const NO_ACCOUNT_SESSION: &str = "no_account_session";

/// Whether a user session for `server` is saved in the OS vault (not whether
/// the server still honours it).
pub async fn has_saved_session(server: &str) -> bool {
    let scope = server.to_owned();
    matches!(
        tokio::task::spawn_blocking(move || vault::load(&scope)).await,
        Ok(Ok(Some(_)))
    )
}

/// A single-use enrollment token for `tenant_id`, minted with the saved
/// session (`MANAGE_AGENTS`, the same right a device-login approval needs).
/// Its only caller promotes this device to its system service.
pub async fn mint_promotion_token(server: &str, tenant_id: &str) -> Result<String, String> {
    let _operation = SESSION_OP.lock().await;
    if !has_saved_session(server).await {
        return Err(NO_ACCOUNT_SESSION.into());
    }
    let session = refreshed(server).await?;
    user_session::mint_promotion_enrollment(server, &session.access_token, tenant_id)
        .await
        .map_err(|e| e.to_string())
}

pub async fn sign_out(server: &str) -> Result<(), String> {
    let _operation = SESSION_OP.lock().await;
    let load_scope = server.to_owned();
    let saved = tokio::task::spawn_blocking(move || vault::load(&load_scope))
        .await
        .map_err(|_| "OS credential read task failed")?
        .map_err(|_| "Cannot read the OS credential store; unlock it and try signing out again")?;
    if let Some(saved) = saved {
        match user_session::refresh(server, &saved.refresh_token).await {
            Ok(session) => match user_session::revoke(server, &session.access_token).await {
                Ok(()) => {}
                Err(error) if error.downcast_ref::<user_session::SessionDenied>().is_some() => {}
                Err(error) => return Err(error.to_string()),
            },
            Err(error) if error.downcast_ref::<user_session::SessionDenied>().is_some() => {}
            Err(error) => return Err(error.to_string()),
        }
        let del_scope = server.to_owned();
        tokio::task::spawn_blocking(move || vault::delete(&del_scope))
            .await
            .map_err(|_| "OS credential removal task failed")?
            .map_err(|_| "Server session revoked, but OS credential cleanup failed")?;
    }
    badge(server, None, false);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn enrollment_alone_has_no_signed_in_identity() {
        assert_eq!(
            super::label("https://fresh-test.invalid", true),
            ("Sign in…".into(), true)
        );
    }
    #[test]
    fn verified_email_label_has_offline_expiry_and_origin_fences() {
        let mut badge = super::Badge {
            server: "https://example.com/base".into(),
            email: Some("person@example.com".into()),
            verified_now: true,
            checked_at: Some(std::time::Instant::now()),
        };
        assert_eq!(
            super::label_for(Some(&badge), &badge.server, true),
            ("Signed in as person@example.com".into(), false)
        );
        assert!(
            super::label_for(Some(&badge), &badge.server, false)
                .0
                .contains("session unconfirmed")
        );
        assert_eq!(
            super::label_for(Some(&badge), "https://example.com/other", true),
            ("Sign in…".into(), true)
        );
        badge.checked_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(91));
        assert!(
            super::label_for(Some(&badge), &badge.server, true)
                .0
                .contains("session unconfirmed")
        );
    }
}
