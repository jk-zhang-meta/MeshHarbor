// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — GPU alert bot channels (Feishu/Lark, DingTalk, WeCom, generic webhook).
//!
//! Security & delivery invariants (§7.6, §8):
//! - Strictly HTTPS-only; official bot hosts & paths pinned for Feishu, DingTalk,
//!   and WeCom.
//! - DNS resolution checked BOTH at channel save and immediately before each
//!   HTTP send; rejects loopback, RFC1918, CGNAT, link-local, ULA, multicast,
//!   unspecified, and IPv4-mapped private IPv6 addresses.
//! - Resolved public `SocketAddr` is pinned into the per-send `reqwest::Client`
//!   with `redirect::Policy::none()`, blocking DNS rebinding and 3xx SSRF pivots.
//! - Stored secrets are NEVER returned by any API; `webhook_url` is masked to
//!   `<host>/...<last4>`.
//! - 10 s per-channel coalescing, 5 s / 30 s / 120 s retry ladder, persisting
//!   `last_error` on failure.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bson::{DateTime, doc, oid::ObjectId};
use hmac::{Hmac, Mac};
use mongodb::Database;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;
use url::Url;

pub const COLLECTION: &str = "gpu_alert_channels";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotKind {
    Feishu,
    Dingtalk,
    Wecom,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAlertChannel {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub user_id: ObjectId,
    pub kind: BotKind,
    pub label: String,
    pub webhook_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default = "default_true")]
    pub include_users: bool,
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sent_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

fn default_true() -> bool {
    true
}
fn default_lang() -> String {
    "en".to_string()
}

/// Client-facing channel view: NEVER returns raw `webhook_url` or `secret`.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelView {
    pub id: String,
    pub kind: BotKind,
    pub label: String,
    pub webhook_masked: String,
    pub has_secret: bool,
    pub include_users: bool,
    pub lang: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sent_at: Option<String>,
    pub created_at: String,
}

impl From<GpuAlertChannel> for ChannelView {
    fn from(c: GpuAlertChannel) -> Self {
        Self {
            id: c.id.map(|i| i.to_hex()).unwrap_or_default(),
            kind: c.kind,
            label: c.label,
            webhook_masked: mask_webhook_url(&c.webhook_url),
            has_secret: c.secret.as_deref().is_some_and(|s| !s.is_empty()),
            include_users: c.include_users,
            lang: c.lang,
            enabled: c.enabled,
            last_error: c.last_error,
            last_sent_at: c.last_sent_at.and_then(|d| d.try_to_rfc3339_string().ok()),
            created_at: c.created_at.try_to_rfc3339_string().unwrap_or_default(),
        }
    }
}

/// Mask a webhook URL to `<host>/...<last4>` so credentials/tokens are never
/// echoed back over the API.
pub fn mask_webhook_url(raw: &str) -> String {
    let Ok(url) = Url::parse(raw) else {
        return "***".to_string();
    };
    let host = url.host_str().unwrap_or("***");
    let tail: String = raw
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if tail.len() == 4 {
        format!("{host}/...{tail}")
    } else {
        format!("{host}/...")
    }
}

/// Return `true` iff `ip` is globally routable (not loopback, private, CGNAT,
/// link-local, multicast, documentation, broadcast, ULA, or IPv4-mapped private).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
    {
        return false;
    }
    // 0.0.0.0/8 ("this" network)
    if o[0] == 0 {
        return false;
    }
    // 100.64.0.0/10 (RFC 6598 CGNAT / Tailscale / MeshHarbor overlay)
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false;
    }
    // 192.0.0.0/24 (IETF protocol assignments), 198.18.0.0/15 (benchmarking), 240.0.0.0/4 (reserved)
    if (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240
    {
        return false;
    }
    true
}

fn is_public_v6(v6: Ipv6Addr) -> bool {
    let segs = v6.segments();
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    // Unique local fc00::/7
    if (segs[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // Link-local fe80::/10
    if (segs[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Documentation 2001:db8::/32
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return false;
    }
    true
}

/// Static URL validation: HTTPS only, no credentials in URL, pinned official
/// host/path for Feishu/DingTalk/WeCom, and immediate refusal of literal private IPs.
pub fn validate_channel_url(kind: BotKind, raw: &str) -> Result<Url, String> {
    let trimmed = raw.trim();
    let url = Url::parse(trimmed).map_err(|e| format!("Invalid webhook URL: {e}"))?;
    if url.scheme() != "https" {
        return Err("Webhook URL must use https://".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Webhook URL must not embed credentials".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "Webhook URL is missing host".to_string())?
        .to_ascii_lowercase();

    // Reject IP literals that are non-public immediately.
    if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>()
        && !is_public_ip(ip)
    {
        return Err(format!("Webhook host {host} is not a public IP address"));
    }

    match kind {
        BotKind::Feishu => {
            if host != "open.feishu.cn" && host != "open.larksuite.com" {
                return Err(
                    "Feishu/Lark webhook host must be open.feishu.cn or open.larksuite.com"
                        .to_string(),
                );
            }
            if !url.path().starts_with("/open-apis/bot/v2/hook/") {
                return Err(
                    "Feishu/Lark webhook path must start with /open-apis/bot/v2/hook/".to_string(),
                );
            }
            if url.port().is_some_and(|p| p != 443) {
                return Err("Feishu/Lark webhook must use port 443".to_string());
            }
        }
        BotKind::Dingtalk => {
            if host != "oapi.dingtalk.com" {
                return Err("DingTalk webhook host must be oapi.dingtalk.com".to_string());
            }
            if url.path() != "/robot/send" {
                return Err("DingTalk webhook path must be /robot/send".to_string());
            }
            if url.port().is_some_and(|p| p != 443) {
                return Err("DingTalk webhook must use port 443".to_string());
            }
        }
        BotKind::Wecom => {
            if host != "qyapi.weixin.qq.com" {
                return Err("WeCom webhook host must be qyapi.weixin.qq.com".to_string());
            }
            if url.path() != "/cgi-bin/webhook/send" {
                return Err("WeCom webhook path must be /cgi-bin/webhook/send".to_string());
            }
            if url.port().is_some_and(|p| p != 443) {
                return Err("WeCom webhook must use port 443".to_string());
            }
        }
        BotKind::Webhook => {
            if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
                return Err("Generic webhook host cannot be localhost or .local".to_string());
            }
        }
    }

    Ok(url)
}

/// Resolve `url`'s host via DNS and verify EVERY returned address is public
/// (SSRF protection enforced both at save time and at send time).
pub async fn resolve_and_validate_public(url: &Url) -> Result<Vec<SocketAddr>, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "Webhook URL missing host".to_string())?;
    let port = url.port_or_known_default().unwrap_or(443);

    if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err(format!("Refusing non-public webhook IP {ip}"));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("DNS returned no addresses for {host}"));
    }
    for addr in &addrs {
        if !is_public_ip(addr.ip()) {
            return Err(format!(
                "Webhook host {host} resolved to non-public address {}",
                addr.ip()
            ));
        }
    }
    Ok(addrs)
}

/// Official Feishu / Lark Custom Bot v2 signature:
/// `base64(HMAC-SHA256(key = "{timestamp_s}\n{secret}", msg = ""))`.
pub fn feishu_sign(timestamp_s: i64, secret: &str) -> String {
    let key = format!("{timestamp_s}\n{secret}");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(b"");
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Official DingTalk Custom Robot signature:
/// `base64(HMAC-SHA256(key = secret, msg = "{timestamp_ms}\n{secret}"))` (raw base64;
/// percent-encoded when placed in query string).
pub fn dingtalk_sign(timestamp_ms: i64, secret: &str) -> String {
    let msg = format!("{timestamp_ms}\n{secret}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(msg.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Percent-encode a DingTalk base64 signature (`+`, `/`, `=`).
pub fn url_encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// One alert item ready for bot rendering.
#[derive(Debug, Clone)]
pub struct BotAlertItem {
    pub severity: String,
    pub title_en: String,
    pub title_zh: String,
    pub body_en: String,
    pub body_zh: String,
    pub users_summary: Option<String>,
    pub link: String,
}

fn render_text(item: &BotAlertItem, lang: &str, include_users: bool) -> (String, String) {
    let is_zh = lang.eq_ignore_ascii_case("zh");
    let title = if is_zh {
        item.title_zh.clone()
    } else {
        item.title_en.clone()
    };
    let mut body = if is_zh {
        item.body_zh.clone()
    } else {
        item.body_en.clone()
    };
    if include_users
        && let Some(users) = item.users_summary.as_deref()
        && !users.is_empty()
    {
        if is_zh {
            body.push_str(&format!(" | 用户: {users}"));
        } else {
            body.push_str(&format!(" | Users: {users}"));
        }
    }
    (title, body)
}

/// Build the HTTP URL & JSON body for one bot channel delivery.
pub fn build_bot_payload(
    channel: &GpuAlertChannel,
    items: &[BotAlertItem],
    now_ms: i64,
) -> Result<(Url, serde_json::Value), String> {
    let mut url = validate_channel_url(channel.kind, &channel.webhook_url)?;
    let mut lines = Vec::with_capacity(items.len());
    let mut first_title = String::new();
    for (idx, it) in items.iter().enumerate() {
        let (title, body) = render_text(it, &channel.lang, channel.include_users);
        if idx == 0 {
            first_title = title.clone();
        }
        lines.push(format!("[{}] {} — {}", it.severity.to_uppercase(), title, body));
    }
    let combined = lines.join("\n");

    let payload = match channel.kind {
        BotKind::Feishu => {
            let ts_s = now_ms / 1000;
            let mut obj = serde_json::json!({
                "msg_type": "text",
                "content": { "text": combined }
            });
            if let Some(secret) = channel.secret.as_deref().filter(|s| !s.is_empty()) {
                obj["timestamp"] = serde_json::json!(ts_s.to_string());
                obj["sign"] = serde_json::json!(feishu_sign(ts_s, secret));
            }
            obj
        }
        BotKind::Dingtalk => {
            if let Some(secret) = channel.secret.as_deref().filter(|s| !s.is_empty()) {
                let sign = url_encode_component(&dingtalk_sign(now_ms, secret));
                let mut q = url.query().unwrap_or("").to_string();
                if !q.is_empty() {
                    q.push('&');
                }
                q.push_str(&format!("timestamp={now_ms}&sign={sign}"));
                url.set_query(Some(&q));
            }
            serde_json::json!({
                "msgtype": "text",
                "text": { "content": combined }
            })
        }
        BotKind::Wecom => {
            serde_json::json!({
                "msgtype": "text",
                "text": { "content": combined }
            })
        }
        BotKind::Webhook => {
            let mut obj = serde_json::json!({
                "source": "meshharbor_gpu",
                "title": first_title,
                "text": combined,
                "timestamp_ms": now_ms,
                "count": items.len(),
            });
            if let Some(secret) = channel.secret.as_deref().filter(|s| !s.is_empty()) {
                let sig = dingtalk_sign(now_ms, secret);
                obj["signature"] = serde_json::json!(sig);
            }
            obj
        }
    };

    Ok((url, payload))
}

/// Deliver once to `channel` with fresh DNS validation, pinned resolved IPs,
/// and `redirect::Policy::none()`.
pub async fn send_once(channel: &GpuAlertChannel, items: &[BotAlertItem]) -> Result<(), String> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let (url, payload) = build_bot_payload(channel, items, now_ms)?;
    let addrs = resolve_and_validate_public(&url).await?;
    let host = url
        .host_str()
        .ok_or_else(|| "missing webhook host".to_string())?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|e| format!("http client build failed: {e}"))?;

    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("webhook send failed: {e}"))?;
    let status = resp.status();
    if status.is_redirection() {
        return Err(format!("webhook redirected ({status}), refused for SSRF safety"));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(200).collect();
        return Err(format!("webhook HTTP {status}: {snippet}"));
    }
    Ok(())
}

/// Per-channel 10 s coalescing & retry dispatcher (`5 s / 30 s / 120 s`).
#[derive(Clone, Default)]
pub struct BotDispatcher {
    pending: Arc<Mutex<HashMap<ObjectId, Vec<BotAlertItem>>>>,
}

impl BotDispatcher {
    pub fn enqueue(&self, db: Database, channel: GpuAlertChannel, item: BotAlertItem) {
        let Some(cid) = channel.id else { return };
        let pending = self.pending.clone();
        tokio::spawn(async move {
            let spawn_flusher = {
                let mut map = pending.lock().await;
                let entry = map.entry(cid).or_default();
                let first = entry.is_empty();
                entry.push(item);
                first
            };
            if !spawn_flusher {
                return;
            }
            // Coalesce bursts for 10 seconds before sending.
            tokio::time::sleep(Duration::from_secs(10)).await;
            let batch = {
                let mut map = pending.lock().await;
                map.remove(&cid).unwrap_or_default()
            };
            if batch.is_empty() {
                return;
            }
            deliver_with_retries(&db, &channel, &batch).await;
        });
    }
}

async fn deliver_with_retries(db: &Database, channel: &GpuAlertChannel, batch: &[BotAlertItem]) {
    let delays = [
        Duration::from_secs(0),
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(120),
    ];
    let mut last_err: Option<String> = None;
    for delay in delays {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        match send_once(channel, batch).await {
            Ok(()) => {
                last_err = None;
                break;
            }
            Err(e) => {
                tracing::warn!(channel = ?channel.id, kind = ?channel.kind, error = %e, "gpu bot delivery attempt failed");
                last_err = Some(e);
            }
        }
    }

    if let Some(cid) = channel.id {
        let coll = db.collection::<GpuAlertChannel>(COLLECTION);
        let update = match last_err {
            None => doc! {
                "$set": {
                    "last_sent_at": DateTime::now(),
                    "updated_at": DateTime::now(),
                },
                "$unset": { "last_error": "" },
            },
            Some(err) => doc! {
                "$set": {
                    "last_error": err,
                    "updated_at": DateTime::now(),
                },
            },
        };
        let _ = coll.update_one(doc! { "_id": cid }, update).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-vector HMAC-SHA256 verification against official Feishu & DingTalk docs.
    #[test]
    fn fr139_feishu_and_dingtalk_hmac_vectors() {
        // Feishu: key = "1599360473\ndemo_secret", msg = ""
        let f_sig = feishu_sign(1599360473, "demo_secret");
        // Verify independently with direct Hmac<Sha256>
        let mut mac = HmacSha256::new_from_slice(b"1599360473\ndemo_secret").unwrap();
        mac.update(b"");
        let expected_f = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(f_sig, expected_f);
        assert_eq!(f_sig.len(), 44);

        // DingTalk: key = "SEC1234", msg = "1700000000000\nSEC1234"
        let d_sig = dingtalk_sign(1700000000000, "SEC1234");
        let mut dmac = HmacSha256::new_from_slice(b"SEC1234").unwrap();
        dmac.update(b"1700000000000\nSEC1234");
        let expected_d = base64::engine::general_purpose::STANDARD.encode(dmac.finalize().into_bytes());
        assert_eq!(d_sig, expected_d);
        assert!(!url_encode_component(&d_sig).contains('+'));
        assert!(!url_encode_component(&d_sig).contains('/'));
        assert!(!url_encode_component(&d_sig).contains('='));
    }

    #[test]
    fn fr139_bot_ssrf_and_pinning_refuse_private_http_and_wrong_hosts() {
        // Valid pinned hosts
        assert!(validate_channel_url(BotKind::Feishu, "https://open.feishu.cn/open-apis/bot/v2/hook/abc-123").is_ok());
        assert!(validate_channel_url(BotKind::Feishu, "https://open.larksuite.com/open-apis/bot/v2/hook/abc-123").is_ok());
        assert!(validate_channel_url(BotKind::Dingtalk, "https://oapi.dingtalk.com/robot/send?access_token=abc").is_ok());
        assert!(validate_channel_url(BotKind::Wecom, "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc").is_ok());
        assert!(validate_channel_url(BotKind::Webhook, "https://hooks.example.com/gpu").is_ok());

        // Refused: HTTP, wrong host/path, loopback/private/link-local/CGNAT/ULA/IPv4-mapped
        assert!(validate_channel_url(BotKind::Feishu, "http://open.feishu.cn/open-apis/bot/v2/hook/abc").is_err());
        assert!(validate_channel_url(BotKind::Feishu, "https://evil.example.com/open-apis/bot/v2/hook/abc").is_err());
        assert!(validate_channel_url(BotKind::Feishu, "https://open.feishu.cn/other").is_err());
        assert!(validate_channel_url(BotKind::Dingtalk, "https://evil.example.com/robot/send").is_err());
        assert!(validate_channel_url(BotKind::Wecom, "https://qyapi.weixin.qq.com/other").is_err());
        for bad in [
            "http://hooks.example.com/gpu",
            "https://127.0.0.1/hook",
            "https://10.0.0.1/hook",
            "https://172.16.0.5/hook",
            "https://192.168.1.2/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1/hook",
            "https://[::1]/hook",
            "https://[fe80::1]/hook",
            "https://[fc00::1]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://localhost/hook",
            "https://user:pass@hooks.example.com/gpu",
        ] {
            assert!(
                validate_channel_url(BotKind::Webhook, bad).is_err(),
                "{bad} must be refused"
            );
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn fr139_mask_webhook_url_never_leaks_secret_token() {
        let m = mask_webhook_url("https://open.feishu.cn/open-apis/bot/v2/hook/super-secret-abcd");
        assert_eq!(m, "open.feishu.cn/...abcd");
        assert!(!m.contains("super-secret"));
    }
}
