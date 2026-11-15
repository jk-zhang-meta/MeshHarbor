//! Explicit password step-up followed by a one-use mailbox proof.
use crate::{core_state::Core, error::ApiError, extractors::auth::AuthUser};
use axum::{Json, extract::State, http::HeaderMap};
use bson::{DateTime, oid::ObjectId};
use meshharbor_services::dao::email_change::{self, PendingEmailChange};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use validator::ValidateEmail;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    email: String,
    current_password: String,
    new_password: Option<String>,
}
#[derive(Serialize)]
pub struct Requested {
    request_id: String,
    email: String,
    expires_in: u64,
    message: &'static str,
}
fn digest(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

pub async fn request(
    State(core): State<Core>,
    auth: AuthUser,
    Json(input): Json<Request>,
) -> Result<Json<Requested>, ApiError> {
    let user = core.users.base.find_by_id(auth.user_id).await?;
    let valid = user
        .password_hash
        .as_deref()
        .map(|h| core.auth.verify_password(&input.current_password, h))
        .transpose()?
        .unwrap_or(false);
    if !valid {
        return Err(ApiError::Unauthorized("Current password required".into()));
    }
    let email = input.email.trim().to_lowercase();
    if !email.validate_email() || email == user.email.to_lowercase() {
        return Err(ApiError::BadRequest(
            "A different valid email is required".into(),
        ));
    }
    let mailer = core
        .email
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("Email verification unavailable".into()))?;
    let security_revision = user
        .security_revision()
        .ok_or_else(|| ApiError::Forbidden("Account security revision unavailable".into()))?;
    let request_id = ObjectId::new();
    let token = nanoid::nanoid!(48);
    let pending = PendingEmailChange {
        request_id,
        email: email.clone(),
        token_hash: digest(&token),
        expires_at: DateTime::from_millis(DateTime::now().timestamp_millis() + 900_000),
        security_revision,
        approval_revision: user.account_approval.revision,
        new_password_hash: input
            .new_password
            .as_deref()
            .map(|p| core.auth.hash_password(p))
            .transpose()?,
    };
    if !email_change::begin(&core.db, &user, pending).await? {
        return Err(ApiError::Conflict(
            "Account changed; authenticate again".into(),
        ));
    }
    let link = format!(
        "{}/verify-email-change?request_id={}#token={}",
        core.settings.app.frontend_url.trim_end_matches('/'),
        request_id.to_hex(),
        token
    );
    let html = format!(
        "<p>Confirm your requested account email change.</p><p><a href=\"{link}\">Review and confirm email change</a></p><p>This link expires in 15 minutes. Your account does not change until you confirm.</p>"
    );
    mailer
        .send(&email, "Confirm your MeshHarbor email change", &html)
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Verification email could not be sent".into()))?;
    Ok(Json(Requested {
        request_id: request_id.to_hex(),
        email,
        expires_in: 900,
        message: "verification_sent",
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    request_id: String,
    token: String,
}
#[derive(Serialize)]
pub struct Confirmed {
    email: String,
    email_verified: bool,
    message: &'static str,
}
pub async fn confirm(
    State(core): State<Core>,
    Json(input): Json<Confirm>,
) -> Result<(HeaderMap, Json<Confirmed>), ApiError> {
    let request_id = ObjectId::parse_str(&input.request_id)
        .map_err(|_| ApiError::BadRequest("Invalid verification request".into()))?;
    if input.token.len() != 48 {
        return Err(ApiError::Unauthorized(
            "Invalid or expired verification".into(),
        ));
    }
    let user = email_change::confirm(&core.db, request_id, &digest(&input.token))
        .await?
        .ok_or_else(|| {
            ApiError::Unauthorized("Invalid, superseded or expired verification".into())
        })?;
    Ok((
        super::auth::logout(State(core)).await?,
        Json(Confirmed {
            email: user.email,
            email_verified: true,
            message: "Account updated; sign in again",
        }),
    ))
}
