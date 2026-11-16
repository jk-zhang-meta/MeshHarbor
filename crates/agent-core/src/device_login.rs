// SPDX-License-Identifier: MPL-2.0
//! Device login client — `mh login` and the desktop app's Sign in.
//!
//! RFC 8628 device authorization with a PKCE binding, against the server's
//! `/api/native/device-login` surface:
//!
//! 1. [`start`] asks the server for a request; the person gets a link and a
//!    short code to compare in the browser.
//! 2. [`Pending::wait`] polls until a signed-in person approves (or denies,
//!    or it expires), then receives a STANDARD single-use enrollment token.
//! 3. The caller enrolls with that token exactly as with a pasted one.
//!
//! The device code and the PKCE verifier never leave this process except to
//! the exchange endpoint, and neither is ever logged or printed.
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Where devices sign in when nobody says otherwise.
pub const DEFAULT_SERVER: &str = "https://www.itachi.fans/meshharbor";

/// Canonical error message returned when a pending sign-in is cancelled locally
/// or when the user closes the browser tab before deciding.
pub const CANCELLED_ERROR: &str = "sign-in cancelled";

#[derive(Debug, Deserialize)]
struct StartResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct ExchangeOk {
    #[serde(default)]
    enrollment_token: String,
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    native_session: Option<crate::user_session::NativeSession>,
}
impl ExchangeOk {
    fn validate(&self, purpose: Purpose) -> Result<()> {
        if purpose.needs_enrollment() && self.enrollment_token.is_empty() {
            bail!("the server approved the sign-in but sent no enrollment token");
        }
        if purpose.needs_session() {
            self.native_session
                .as_ref()
                .context("server does not support user sign-in; upgrade the server")?
                .validate()?;
        } else if self.native_session.is_some() {
            bail!("server returned an unrequested user session");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Enrollment,
    UserSession,
    EnrollmentAndUserSession,
}
impl Purpose {
    fn wire(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::UserSession => "user_session",
            Self::EnrollmentAndUserSession => "enrollment_and_user_session",
        }
    }
    fn needs_enrollment(self) -> bool {
        self != Self::UserSession
    }
    fn needs_session(self) -> bool {
        self != Self::Enrollment
    }
}

#[derive(Debug, Deserialize)]
struct ExchangeErr {
    error: String,
}

/// A started request: show [`Self::user_code`] and open
/// [`Self::verification_uri_complete`], then [`Self::wait`].
pub struct Pending {
    pub purpose: Purpose,
    pub server_url: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: Duration,
    interval: Duration,
    device_code: String,
    verifier: String,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The device code and verifier are credentials: never in Debug.
        f.debug_struct("Pending")
            .field("server_url", &self.server_url)
            .field("user_code", &self.user_code)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .finish_non_exhaustive()
    }
}

/// The approved outcome: a single-use enrollment token for `tenant_id`.
pub struct Approved {
    pub enrollment_token: String,
    pub tenant_id: String,
    pub native_session: Option<crate::user_session::NativeSession>,
}

/// The OS name the server shows the approver.
pub fn os_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// PKCE S256 challenge for `verifier`.
pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn new_verifier() -> String {
    // 32 random bytes → 43 base64url characters (RFC 7636 §4.1).
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the HTTP client")
}

/// Normalize `server` the way enrollment does (TLS only, no trailing slash).
pub fn server_base(server: &str) -> String {
    meshharbor_remote_control::server_url::secure(server, false)
        .url
        .trim_end_matches('/')
        .to_string()
}

/// Start a device login for `device_name` on `server`.
pub async fn start(server: &str, device_name: &str) -> Result<Pending> {
    start_with_purpose(server, device_name, Purpose::Enrollment).await
}

/// GUI-only explicit authorization. Existing CLI enrollment never requests
/// or stores a user session, including headless invitation enrollments.
pub async fn start_with_purpose(
    server: &str,
    device_name: &str,
    purpose: Purpose,
) -> Result<Pending> {
    let server_url = server_base(server);
    let name = device_name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        bail!("the device name must be 1-64 printable characters");
    }
    let verifier = new_verifier();
    let mut body = serde_json::json!({
        "device_name": name,
        "device_os": os_name(),
        "code_challenge": challenge_for(&verifier),
        "code_challenge_method": "S256",
    });
    // Old servers reject unknown fields. Enrollment-only remains byte-shape
    // compatible; user-session authorization is never silently downgraded.
    if purpose != Purpose::Enrollment {
        body["purpose"] = purpose.wire().into();
    }
    let res = client()?
        .post(format!("{server_url}/api/native/device-login"))
        .json(&body)
        .send()
        .await
        .with_context(|| format!("contacting {server_url}"))?;
    match res.status().as_u16() {
        201 => {}
        503 => bail!("this server does not offer sign-in yet (device login is turned off there)"),
        429 => bail!("too many sign-in requests from this network; wait a few minutes"),
        400 | 404 | 422 if purpose.needs_session() => bail!(
            "this server does not support GUI user-session authorization; upgrade the server before signing in"
        ),
        s => bail!("the server refused the sign-in request (HTTP {s})"),
    }
    let body: StartResponse = res.json().await.context("reading the server's answer")?;
    if body.device_code.len() != 43 || body.user_code.len() != 11 || body.expires_in == 0 {
        bail!("the server's sign-in answer is malformed");
    }
    Ok(Pending {
        purpose,
        server_url,
        user_code: body.user_code,
        verification_uri: body.verification_uri,
        verification_uri_complete: body.verification_uri_complete,
        expires_in: Duration::from_secs(body.expires_in.min(900)),
        interval: Duration::from_secs(body.interval.clamp(1, 10)),
        device_code: body.device_code,
        verifier,
    })
}

/// One exchange attempt.
enum Poll {
    Approved(Approved),
    Pending,
    SlowDown,
}

impl Pending {
    async fn poll_once(&self, http: &reqwest::Client) -> Result<Poll> {
        let res = http
            .post(format!(
                "{}/api/native/device-login/exchange",
                self.server_url
            ))
            .json(&serde_json::json!({
                "device_code": self.device_code,
                "code_verifier": self.verifier,
            }))
            .send()
            .await;
        // A network blip mid-wait is not a refusal: keep waiting.
        let Ok(res) = res else {
            return Ok(Poll::Pending);
        };
        let status = res.status().as_u16();
        if status == 200 {
            let ok: ExchangeOk = res.json().await.context("reading the enrollment token")?;
            ok.validate(self.purpose)?;
            return Ok(Poll::Approved(Approved {
                enrollment_token: ok.enrollment_token,
                tenant_id: ok.tenant_id,
                native_session: ok.native_session,
            }));
        }
        if status >= 500 {
            return Ok(Poll::Pending);
        }
        let err = res
            .json::<ExchangeErr>()
            .await
            .map(|e| e.error)
            .unwrap_or_default();
        match err.as_str() {
            "authorization_pending" => Ok(Poll::Pending),
            "slow_down" => Ok(Poll::SlowDown),
            "cancelled" => bail!("{CANCELLED_ERROR}"),
            "access_denied" => bail!("the sign-in was denied in the browser"),
            "expired_token" => bail!("the sign-in request expired; run it again"),
            other => bail!("the server refused the sign-in ({other}, HTTP {status})"),
        }
    }

    /// Wait for the browser decision. Returns the enrollment token on approval.
    pub async fn wait(&self) -> Result<Approved> {
        let http = client()?;
        let deadline = Instant::now() + self.expires_in;
        let mut interval = self.interval;
        loop {
            if Instant::now() >= deadline {
                bail!("the sign-in request expired before it was approved; run it again");
            }
            tokio::time::sleep(interval).await;
            match self.poll_once(&http).await? {
                Poll::Approved(a) => return Ok(a),
                Poll::Pending => {}
                Poll::SlowDown => {
                    interval = (interval + Duration::from_secs(5)).min(Duration::from_secs(30))
                }
            }
        }
    }
}

/// Best-effort: open `url` in the person's browser. `false` when there is no
/// desktop to open it on (a headless server, an SSH session) or it failed —
/// the caller prints the link either way.
pub fn open_browser(url: &str) -> bool {
    if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") {
        return false;
    }
    #[cfg(target_os = "windows")]
    let r = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(url).spawn();
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let r = {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
    };
    r.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_the_rfc_7636_vector() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let v = new_verifier();
        assert_eq!(v.len(), 43);
        assert_ne!(v, new_verifier());
    }

    #[test]
    fn the_server_url_is_tls_and_unslashed() {
        assert_eq!(
            server_base("https://www.itachi.fans/meshharbor/"),
            DEFAULT_SERVER
        );
        assert!(server_base("http://example.org").starts_with("https://"));
    }

    #[test]
    fn credentials_never_reach_debug_output() {
        let p = Pending {
            purpose: Purpose::Enrollment,
            server_url: DEFAULT_SERVER.into(),
            user_code: "BCDFG-HJKLM".into(),
            verification_uri: String::new(),
            verification_uri_complete: String::new(),
            expires_in: Duration::from_secs(1),
            interval: Duration::from_secs(1),
            device_code: "DEVICE-CODE-SECRET".into(),
            verifier: "VERIFIER-SECRET".into(),
        };
        let s = format!("{p:?}");
        assert!(!s.contains("SECRET"), "{s}");
    }

    #[test]
    fn user_session_requires_explicit_scope_and_legacy_server_cannot_fake_login() {
        let legacy: ExchangeOk = serde_json::from_value(
            serde_json::json!({"enrollment_token":"enroll-only","tenant_id":"tenant"}),
        )
        .unwrap();
        assert!(legacy.validate(Purpose::Enrollment).is_ok());
        assert!(legacy.validate(Purpose::UserSession).is_err());
        let user:ExchangeOk=serde_json::from_value(serde_json::json!({"native_session":{"access_token":"access-fixture","refresh_token":"refresh-fixture","expires_in":60,"user":{"id":"user","email":"person@example.com","email_verified":true}}})).unwrap();
        assert!(user.validate(Purpose::UserSession).is_ok());
        assert!(user.validate(Purpose::Enrollment).is_err());
        assert!(user.validate(Purpose::EnrollmentAndUserSession).is_err());
    }
}
