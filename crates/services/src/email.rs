// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use std::{collections::BTreeMap, sync::Arc};

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
    message::{
        Mailbox,
        header::{ContentType, HeaderName, HeaderValue},
    },
};
use meshharbor_config::EmailSettings;
use serde::Serialize;
use tracing::{info, warn};

/// Outbound email service. Two backends are supported and selected
/// at construction time based on `EmailSettings`:
///   - `SendGrid` (HTTP POST to api.sendgrid.com) — prod default,
///     active when `email.api_key` is non-empty.
///   - `Smtp` (plaintext SMTP via lettre) — used by the e2e overlay
///     to capture mail in Mailpit; active when `email.api_key` is
///     empty AND `email.smtp_host` + `email.smtp_port` are both set.
///
/// `from_settings` returns `None` when neither backend is configured;
/// `AppState` then leaves `state.email = None` and the register
/// handler silently skips email sends.
#[derive(Clone)]
pub struct EmailService {
    backend: EmailBackend,
    from_email: String,
    from_name: String,
}

#[derive(Clone)]
enum EmailBackend {
    SendGrid {
        client: reqwest::Client,
        api_key: String,
    },
    Smtp {
        transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
        endpoint: String,
    },
}

/// Per-message options for [`EmailService::send_ext`]. `Default` is inert —
/// [`EmailService::send`] delegates with it, so the transactional helpers are
/// byte-for-byte unchanged by its existence.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Extra top-level headers as (name, value) — e.g. `List-Unsubscribe` +
    /// `List-Unsubscribe-Post` on newsletter mail (FR-58). A name that is not
    /// a valid ASCII header name fails the send rather than being silently
    /// dropped: a newsletter without its unsubscribe header must not go out.
    pub headers: Vec<(String, String)>,
    /// Override the From mailbox (email, display name) for this message, so
    /// campaign mail carries the newsletter identity without touching the
    /// transactional From that activation/invite mail depends on.
    pub from: Option<(String, String)>,
    /// FR-102 P5 — SendGrid `custom_args`: carried into the Event Webhook's
    /// events for this message, and NOT into the message a recipient
    /// receives. The newsletter passes one, the issue's slug — the same for
    /// every recipient. Ignored by the SMTP backend.
    pub custom_args: Vec<(String, String)>,
    /// FR-102 P5 (D6) — switch SendGrid's open, click, subscription and
    /// Google Analytics tracking OFF for this message, whatever the account
    /// settings say: open tracking is a per-recipient pixel, click tracking
    /// rewrites every link into a per-recipient one, and Google Analytics
    /// tracking rewrites the issue's own UTM tags. Ignored by SMTP (which
    /// tracks nothing).
    pub no_tracking: bool,
}

#[derive(Debug, Serialize)]
struct SendGridRequest {
    personalizations: Vec<Personalization>,
    from: EmailAddress,
    subject: String,
    content: Vec<Content>,
    /// Top-level custom headers, applied by SendGrid to the message verbatim.
    /// Omitted entirely when empty — the v3 API rejects an empty object here.
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
    /// FR-102 P5 — omitted when empty, like `headers`.
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_args: Option<BTreeMap<String, String>>,
    /// FR-102 P5 — every tracking switch, explicitly off; omitted unless
    /// asked, so transactional mail is byte-for-byte what it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    tracking_settings: Option<TrackingOff>,
}

/// SendGrid v3 `tracking_settings`, every one of them `enable: false`.
#[derive(Debug, Serialize)]
struct TrackingOff {
    click_tracking: ClickTrackingOff,
    open_tracking: Switch,
    subscription_tracking: Switch,
    ganalytics: Switch,
}

#[derive(Debug, Serialize)]
struct ClickTrackingOff {
    enable: bool,
    enable_text: bool,
}

#[derive(Debug, Serialize)]
struct Switch {
    enable: bool,
}

impl TrackingOff {
    fn new() -> Self {
        Self {
            click_tracking: ClickTrackingOff {
                enable: false,
                enable_text: false,
            },
            open_tracking: Switch { enable: false },
            subscription_tracking: Switch { enable: false },
            ganalytics: Switch { enable: false },
        }
    }
}

/// FR-102 P5 — SendGrid's ACCOUNT-level open and click tracking, as read
/// back at startup. The newsletter turns both off per message anyway; this
/// is the check that the account does not track the rest of the mail (and
/// that nobody turned it on expecting newsletter numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TrackingReport {
    pub open: bool,
    pub click: bool,
}

/// `GET /v3/tracking_settings/open` answers `{"enabled": bool}`;
/// `GET /v3/tracking_settings/click` answers `{"enabled": bool,
/// "enable_text": bool}`. A missing field reads as ON — the check exists to
/// warn, and an answer it cannot read must not read as reassurance.
pub fn tracking_report(open: &serde_json::Value, click: &serde_json::Value) -> TrackingReport {
    let on = |v: &serde_json::Value, k: &str| v.get(k).and_then(|b| b.as_bool()).unwrap_or(true);
    TrackingReport {
        open: on(open, "enabled"),
        click: on(click, "enabled")
            || click
                .get("enable_text")
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
    }
}

#[derive(Debug, Serialize)]
struct Personalization {
    to: Vec<EmailAddress>,
}

#[derive(Debug, Serialize)]
struct EmailAddress {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Content {
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

impl EmailService {
    /// Build an `EmailService` from `EmailSettings`. Picks SendGrid
    /// when `api_key` is non-empty (prod), otherwise picks SMTP when
    /// `smtp_host` + `smtp_port` are both set (e2e Mailpit). Returns
    /// `None` when neither path is configured.
    pub fn from_settings(settings: &EmailSettings) -> Option<Self> {
        if !settings.api_key.is_empty() {
            return Some(Self {
                backend: EmailBackend::SendGrid {
                    client: reqwest::Client::new(),
                    api_key: settings.api_key.clone(),
                },
                from_email: settings.from_email.clone(),
                from_name: settings.from_name.clone(),
            });
        }
        if let (Some(host), Some(port)) = (settings.smtp_host.as_ref(), settings.smtp_port) {
            // `builder_dangerous` skips TLS — appropriate for the
            // in-cluster Mailpit target which doesn't terminate TLS.
            // For prod-grade SMTP delivery (future enhancement),
            // switch to `starttls_relay` + credentials.
            let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host.as_str())
                .port(port)
                .build();
            let endpoint = format!("{}:{}", host, port);
            return Some(Self {
                backend: EmailBackend::Smtp {
                    transport: Arc::new(transport),
                    endpoint,
                },
                from_email: settings.from_email.clone(),
                from_name: settings.from_name.clone(),
            });
        }
        None
    }

    /// Low-level send — used by every `send_*` helper below. Routes
    /// through whichever backend was selected at construction.
    pub async fn send(&self, to_email: &str, subject: &str, html_body: &str) -> anyhow::Result<()> {
        self.send_ext(to_email, subject, html_body, &SendOptions::default())
            .await
    }

    /// [`send`](Self::send) with per-message headers and an optional From
    /// override — the newsletter path (FR-58). Kept separate so the
    /// transactional callers never grow an options argument they would always
    /// default.
    pub async fn send_ext(
        &self,
        to_email: &str,
        subject: &str,
        html_body: &str,
        opts: &SendOptions,
    ) -> anyhow::Result<()> {
        match &self.backend {
            EmailBackend::SendGrid { client, api_key } => {
                let request = self.sendgrid_request(to_email, subject, html_body, opts);

                let resp = client
                    .post("https://api.sendgrid.com/v3/mail/send")
                    .bearer_auth(api_key)
                    .json(&request)
                    .send()
                    .await?;

                if resp.status().is_success() {
                    info!(to = to_email, subject, "Email sent via SendGrid");
                    Ok(())
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    warn!(to = to_email, %status, body, "SendGrid email failed");
                    anyhow::bail!("SendGrid error {}: {}", status, body)
                }
            }
            EmailBackend::Smtp {
                transport,
                endpoint,
            } => {
                let email = self.smtp_message(to_email, subject, html_body, opts)?;

                transport
                    .send(email)
                    .await
                    .map_err(|e| anyhow::anyhow!("SMTP send to {} failed: {}", endpoint, e))?;
                info!(to = to_email, subject, endpoint, "Email sent via SMTP");
                Ok(())
            }
        }
    }

    /// The exact JSON body a SendGrid send POSTs — split out so tests can pin
    /// the header/From plumbing without a network.
    fn sendgrid_request(
        &self,
        to_email: &str,
        subject: &str,
        html_body: &str,
        opts: &SendOptions,
    ) -> SendGridRequest {
        let (from_email, from_name) = match &opts.from {
            Some((email, name)) => (email.clone(), name.clone()),
            None => (self.from_email.clone(), self.from_name.clone()),
        };
        SendGridRequest {
            personalizations: vec![Personalization {
                to: vec![EmailAddress {
                    email: to_email.to_string(),
                    name: None,
                }],
            }],
            from: EmailAddress {
                email: from_email,
                name: Some(from_name),
            },
            subject: subject.to_string(),
            content: vec![Content {
                content_type: "text/html".to_string(),
                value: html_body.to_string(),
            }],
            headers: if opts.headers.is_empty() {
                None
            } else {
                Some(opts.headers.iter().cloned().collect())
            },
            custom_args: if opts.custom_args.is_empty() {
                None
            } else {
                Some(opts.custom_args.iter().cloned().collect())
            },
            tracking_settings: opts.no_tracking.then(TrackingOff::new),
        }
    }

    /// Whether this service sends through SendGrid (the only backend with
    /// account tracking settings and an Event Webhook).
    pub fn is_sendgrid(&self) -> bool {
        matches!(self.backend, EmailBackend::SendGrid { .. })
    }

    /// FR-102 P5 — read SendGrid's account-level open and click tracking
    /// (`GET /v3/tracking_settings/{open,click}`). `None` on the SMTP
    /// backend. Each request is bounded at 10 s; an error is the HTTP
    /// status (a key without the `tracking_settings.read` scope answers
    /// 403), never the key.
    pub async fn tracking_settings(&self) -> Option<Result<TrackingReport, String>> {
        let EmailBackend::SendGrid { client, api_key } = &self.backend else {
            return None;
        };
        let get = |path: &'static str| {
            let client = client.clone();
            let api_key = api_key.clone();
            async move {
                let resp = client
                    .get(format!(
                        "https://api.sendgrid.com/v3/tracking_settings/{path}"
                    ))
                    .bearer_auth(api_key)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                    .map_err(|e| format!("{path}: {}", e.without_url()))?;
                let status = resp.status();
                if !status.is_success() {
                    return Err(format!("{path}: HTTP {}", status.as_u16()));
                }
                resp.json::<serde_json::Value>()
                    .await
                    .map_err(|e| format!("{path}: unreadable answer ({})", e.without_url()))
            }
        };
        Some(match (get("open").await, get("click").await) {
            (Ok(open), Ok(click)) => Ok(tracking_report(&open, &click)),
            (Err(e), _) | (_, Err(e)) => Err(e),
        })
    }

    /// The exact RFC 5322 message an SMTP send submits — split out for the
    /// same reason as `sendgrid_request`.
    fn smtp_message(
        &self,
        to_email: &str,
        subject: &str,
        html_body: &str,
        opts: &SendOptions,
    ) -> anyhow::Result<lettre::Message> {
        let (from_email, from_name) = match &opts.from {
            Some((email, name)) => (email.as_str(), name.as_str()),
            None => (self.from_email.as_str(), self.from_name.as_str()),
        };
        let from_addr: lettre::Address = from_email
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid from_email '{}': {}", from_email, e))?;
        let from_mb = Mailbox::new(
            if from_name.is_empty() {
                None
            } else {
                Some(from_name.to_string())
            },
            from_addr,
        );

        let to_addr: lettre::Address = to_email
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid to_email '{}': {}", to_email, e))?;
        let to_mb = Mailbox::new(None, to_addr);

        let mut email = lettre::Message::builder()
            .from(from_mb)
            .to(to_mb)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| anyhow::anyhow!("Failed to build SMTP message: {}", e))?;

        for (name, value) in &opts.headers {
            let header_name = HeaderName::new_from_ascii(name.clone())
                .map_err(|e| anyhow::anyhow!("Invalid header name '{name}': {e:?}"))?;
            email
                .headers_mut()
                .insert_raw(HeaderValue::new(header_name, value.clone()));
        }
        Ok(email)
    }

    /// Send an invite email with a link to accept the invitation.
    pub async fn send_invite(
        &self,
        to_email: &str,
        inviter_name: &str,
        tenant_name: &str,
        invite_url: &str,
    ) -> anyhow::Result<()> {
        let subject = format!("You're invited to join {} on MeshHarbor", tenant_name);
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
<h2>You're invited!</h2>
<p><strong>{inviter}</strong> has invited you to join <strong>{tenant}</strong> on MeshHarbor.</p>
<p style="margin: 24px 0;">
  <a href="{url}" style="background: #1976d2; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">
    Accept Invitation
  </a>
</p>
<p style="color: #666; font-size: 13px;">
  Or copy this link: <a href="{url}">{url}</a>
</p>
<p style="color: #999; font-size: 12px; margin-top: 32px;">— The MeshHarbor Team</p>
</div>"#,
            inviter = inviter_name,
            tenant = tenant_name,
            url = invite_url,
        );
        self.send(to_email, &subject, &html).await
    }

    /// Notify a device owner that a remote-control session is awaiting their
    /// approval. Links to the in-app consent page (Approve/Deny live there, as
    /// authenticated POSTs) rather than an approve endpoint directly, so an
    /// email prefetcher can't auto-approve via a GET.
    pub async fn send_consent_request(
        &self,
        to_email: &str,
        controller_name: &str,
        device_name: &str,
        consent_url: &str,
    ) -> anyhow::Result<()> {
        let subject = format!("Approve remote control of {device_name}?");
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
<h2>Remote control request</h2>
<p><strong>{controller}</strong> is requesting to remotely control your device <strong>{device}</strong>.</p>
<p style="margin: 24px 0;">
  <a href="{url}" style="background: #1976d2; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">
    Review request
  </a>
</p>
<p style="color: #666; font-size: 13px;">
  Or copy this link: <a href="{url}">{url}</a>
</p>
<p style="color: #b45309; font-size: 12px;">
  If you didn't expect this, open the link and deny — the session cannot start
  without your approval, and the link expires shortly.
</p>
<p style="color: #999; font-size: 12px; margin-top: 32px;">— The MeshHarbor Team</p>
</div>"#,
            controller = controller_name,
            device = device_name,
            url = consent_url,
        );
        self.send(to_email, &subject, &html).await
    }

    /// Notify a device owner that their device was accessed via an ADMINISTRATOR
    /// break-glass (Phase 5) — informational, no action needed. `reason` is the
    /// operator-supplied justification, recorded in the audit log too.
    pub async fn send_override_notice(
        &self,
        to_email: &str,
        admin_name: &str,
        device_name: &str,
        reason: &str,
    ) -> anyhow::Result<()> {
        let subject = format!("Your device {device_name} was accessed by an administrator");
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
<h2>Device accessed via administrator override</h2>
<p><strong>{admin}</strong> started a remote-control session on your device
<strong>{device}</strong> using an administrator break-glass — <em>without</em> the usual
consent prompt.</p>
<p style="background: #fff7ed; border-left: 4px solid #b45309; padding: 8px 12px;">
  Reason given: {reason}
</p>
<p style="color: #666; font-size: 13px;">
  If this was unexpected, contact your tenant administrator. This access is recorded in
  the remote-control audit log.
</p>
<p style="color: #999; font-size: 12px; margin-top: 32px;">— The MeshHarbor Team</p>
</div>"#,
            admin = admin_name,
            device = device_name,
            reason = reason,
        );
        self.send(to_email, &subject, &html).await
    }

    /// Send a mention notification email.
    pub async fn send_mention_notification(
        &self,
        to_email: &str,
        mentioner_name: &str,
        room_name: &str,
        message_preview: &str,
        link_url: &str,
    ) -> anyhow::Result<()> {
        let subject = format!("{} mentioned you in #{}", mentioner_name, room_name);
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
<h2>You were mentioned</h2>
<p><strong>{mentioner}</strong> mentioned you in <strong>#{room}</strong>:</p>
<blockquote style="border-left: 3px solid #1976d2; padding: 8px 12px; margin: 16px 0; color: #333; background: #f5f5f5; border-radius: 4px;">
  {preview}
</blockquote>
<p style="margin: 24px 0;">
  <a href="{url}" style="background: #1976d2; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">
    View Message
  </a>
</p>
<p style="color: #999; font-size: 12px; margin-top: 32px;">— The MeshHarbor Team</p>
</div>"#,
            mentioner = mentioner_name,
            room = room_name,
            preview = message_preview,
            url = link_url,
        );
        self.send(to_email, &subject, &html).await
    }

    /// Send an account activation email with a verification link.
    pub async fn send_activation(
        &self,
        to_email: &str,
        display_name: &str,
        activation_url: &str,
        ttl_minutes: u64,
    ) -> anyhow::Result<()> {
        let subject = "Activate your MeshHarbor account".to_string();
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
<h2>Welcome, {name}!</h2>
<p>Please activate your account by clicking the button below. This link expires in {ttl} minutes.</p>
<p style="margin: 32px 0;">
  <a href="{url}" style="background: #1976d2; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">
    Activate Account
  </a>
</p>
<p style="color: #666; font-size: 13px;">Or copy this link: <a href="{url}">{url}</a></p>
<p style="color: #999; font-size: 12px; margin-top: 32px;">If you did not create an account, please ignore this email.</p>
</div>"#,
            name = display_name,
            url = activation_url,
            ttl = ttl_minutes,
        );
        self.send(to_email, &subject, &html).await
    }

    /// Send account activation success email.
    pub async fn send_activation_success(
        &self,
        to_email: &str,
        display_name: &str,
        login_url: &str,
    ) -> anyhow::Result<()> {
        let subject = "Your MeshHarbor account is active".to_string();
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
<h2>Account activated, {name}!</h2>
<p>Your MeshHarbor account is now active. You can <a href="{url}">sign in here</a>.</p>
<p style="color: #999; font-size: 12px; margin-top: 32px;">— The MeshHarbor Team</p>
</div>"#,
            name = display_name,
            url = login_url,
        );
        self.send(to_email, &subject, &html).await
    }

    /// Send a welcome email after registration.
    pub async fn send_welcome(
        &self,
        to_email: &str,
        display_name: &str,
        app_url: &str,
    ) -> anyhow::Result<()> {
        let subject = "Welcome to MeshHarbor!".to_string();
        let html = format!(
            r#"<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
<h2>Welcome, {name}!</h2>
<p>Your MeshHarbor account is ready. Start collaborating with your team.</p>
<p style="margin: 24px 0;">
  <a href="{url}" style="background: #1976d2; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold;">
    Get Started
  </a>
</p>
<p style="color: #999; font-size: 12px; margin-top: 32px;">— The MeshHarbor Team</p>
</div>"#,
            name = display_name,
            url = app_url,
        );
        self.send(to_email, &subject, &html).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(api_key: &str, smtp_host: Option<&str>, smtp_port: Option<u16>) -> EmailSettings {
        EmailSettings {
            api_key: api_key.to_string(),
            from_email: "noreply@test.local".to_string(),
            from_name: "Test".to_string(),
            activation_token_ttl_minutes: 5,
            smtp_host: smtp_host.map(|s| s.to_string()),
            smtp_port,
        }
    }

    #[test]
    fn from_settings_returns_none_when_unconfigured() {
        let s = settings("", None, None);
        assert!(EmailService::from_settings(&s).is_none());
    }

    #[test]
    fn from_settings_returns_sendgrid_when_api_key_set() {
        let s = settings("sg.key", None, None);
        let svc = EmailService::from_settings(&s).expect("expected Some");
        assert!(matches!(svc.backend, EmailBackend::SendGrid { .. }));
    }

    #[test]
    fn from_settings_returns_smtp_when_host_and_port_set() {
        let s = settings("", Some("mailpit.local"), Some(1025));
        let svc = EmailService::from_settings(&s).expect("expected Some");
        match svc.backend {
            EmailBackend::Smtp { endpoint, .. } => {
                assert_eq!(endpoint, "mailpit.local:1025");
            }
            _ => panic!("expected SMTP backend"),
        }
    }

    #[test]
    fn from_settings_prefers_sendgrid_over_smtp() {
        let s = settings("sg.key", Some("mailpit.local"), Some(1025));
        let svc = EmailService::from_settings(&s).expect("expected Some");
        assert!(matches!(svc.backend, EmailBackend::SendGrid { .. }));
    }

    #[test]
    fn from_settings_returns_none_when_smtp_partially_configured() {
        let host_only = settings("", Some("mailpit.local"), None);
        assert!(EmailService::from_settings(&host_only).is_none());

        let port_only = settings("", None, Some(1025));
        assert!(EmailService::from_settings(&port_only).is_none());
    }

    // ── send_ext plumbing (FR-58) ────────────────────────────────────────────
    // These pin the constructed request/message, not the network: the JSON a
    // SendGrid send would POST and the RFC 5322 bytes an SMTP send would
    // submit. Default options must be inert — `send` delegates through them,
    // so any drift here silently rewrites every transactional mail.

    fn unsub_headers() -> Vec<(String, String)> {
        vec![
            (
                "List-Unsubscribe".to_string(),
                "<https://meshharbor.test/api/subscribe/unsubscribe/tok>".to_string(),
            ),
            (
                "List-Unsubscribe-Post".to_string(),
                "List-Unsubscribe=One-Click".to_string(),
            ),
        ]
    }

    #[test]
    fn sendgrid_request_with_default_options_is_unchanged() {
        let svc = EmailService::from_settings(&settings("sg.key", None, None)).unwrap();
        let req = svc.sendgrid_request(
            "to@example.com",
            "Subj",
            "<p>hi</p>",
            &SendOptions::default(),
        );
        let json = serde_json::to_value(&req).unwrap();
        assert!(
            json.get("headers").is_none(),
            "no options ⇒ no `headers` key at all (the v3 API rejects an empty object)"
        );
        // FR-102 P5 — transactional mail carries neither key: its request
        // body is what it was before the newsletter grew options.
        assert!(json.get("custom_args").is_none());
        assert!(json.get("tracking_settings").is_none());
        assert_eq!(json["from"]["email"], "noreply@test.local");
        assert_eq!(json["from"]["name"], "Test");
    }

    /// FR-102 P5 — the newsletter's two additions: the issue as a custom
    /// arg (the Event Webhook's correlation key, the same for every
    /// recipient) and every tracking switch explicitly off (D6).
    #[test]
    fn sendgrid_request_carries_custom_args_and_turns_every_tracking_switch_off() {
        let svc = EmailService::from_settings(&settings("sg.key", None, None)).unwrap();
        let opts = SendOptions {
            custom_args: vec![("nl_issue".to_string(), "october-notes".to_string())],
            no_tracking: true,
            ..Default::default()
        };
        let req = svc.sendgrid_request("to@example.com", "Subj", "<p>hi</p>", &opts);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["custom_args"]["nl_issue"], "october-notes");
        let t = &json["tracking_settings"];
        assert_eq!(t["open_tracking"]["enable"], false);
        assert_eq!(t["click_tracking"]["enable"], false);
        assert_eq!(t["click_tracking"]["enable_text"], false);
        assert_eq!(t["subscription_tracking"]["enable"], false);
        assert_eq!(t["ganalytics"]["enable"], false);
        assert!(
            json["personalizations"][0].get("custom_args").is_none(),
            "the arg is the send's, not a per-recipient one"
        );
    }

    /// FR-102 P5 — the startup check's reading of SendGrid's answers. An
    /// answer it cannot read is ON: the check warns, and a malformed body
    /// must not read as reassurance.
    #[test]
    fn the_tracking_report_reads_off_only_when_sendgrid_says_off() {
        use serde_json::json;
        assert_eq!(
            tracking_report(
                &json!({ "enabled": false }),
                &json!({ "enabled": false, "enable_text": false })
            ),
            TrackingReport {
                open: false,
                click: false
            }
        );
        assert!(tracking_report(&json!({ "enabled": true }), &json!({ "enabled": false })).open);
        assert!(
            tracking_report(
                &json!({ "enabled": false }),
                &json!({ "enabled": false, "enable_text": true })
            )
            .click,
            "click tracking of plain-text links is click tracking"
        );
        let unreadable = tracking_report(&json!({}), &json!([]));
        assert!(unreadable.open && unreadable.click);
    }

    #[test]
    fn sendgrid_request_carries_headers_and_from_override() {
        let svc = EmailService::from_settings(&settings("sg.key", None, None)).unwrap();
        let opts = SendOptions {
            headers: unsub_headers(),
            from: Some(("news@test.local".to_string(), "Field Notes".to_string())),
            ..Default::default()
        };
        let req = svc.sendgrid_request("to@example.com", "Subj", "<p>hi</p>", &opts);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json["headers"]["List-Unsubscribe-Post"],
            "List-Unsubscribe=One-Click"
        );
        assert_eq!(
            json["headers"]["List-Unsubscribe"],
            "<https://meshharbor.test/api/subscribe/unsubscribe/tok>"
        );
        assert_eq!(json["from"]["email"], "news@test.local");
        assert_eq!(json["from"]["name"], "Field Notes");
    }

    #[test]
    fn smtp_message_carries_headers_and_from_override() {
        let svc =
            EmailService::from_settings(&settings("", Some("mailpit.local"), Some(1025))).unwrap();
        let opts = SendOptions {
            headers: unsub_headers(),
            from: Some(("news@test.local".to_string(), "Field Notes".to_string())),
            ..Default::default()
        };
        let msg = svc
            .smtp_message("to@example.com", "Subj", "<p>hi</p>", &opts)
            .expect("message should build");
        let wire = String::from_utf8_lossy(&msg.formatted()).to_string();
        assert!(
            wire.contains("List-Unsubscribe: <https://meshharbor.test/api/subscribe/unsubscribe/tok>"),
            "unsubscribe header missing from the wire form:\n{wire}"
        );
        assert!(wire.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
        assert!(
            wire.contains("news@test.local"),
            "the From override must reach the wire form"
        );
    }

    #[test]
    fn smtp_message_refuses_an_invalid_header_name() {
        // Fail closed: a newsletter whose unsubscribe header cannot be built
        // must not be sent without it.
        let svc =
            EmailService::from_settings(&settings("", Some("mailpit.local"), Some(1025))).unwrap();
        let opts = SendOptions {
            headers: vec![("Bad Name:".to_string(), "v".to_string())],
            ..Default::default()
        };
        assert!(svc.smtp_message("to@example.com", "S", "b", &opts).is_err());
    }
}
