// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! T12 — Tauri IPC HTTP Range proxy for the centre's self-hosted boundary PMTiles
//! (`/geo/mh-boundaries-v1.pmtiles`).
//!
//! Routing byte-range fetches through Rust rather than raw WebView `fetch()`:
//! - avoids CORS failures between `tauri://localhost` / `http://tauri.localhost` and the centre;
//! - preserves any deployment base path (e.g. `https://centre.example.test/meshharbor`);
//! - honours FR-134 (zone management entry routing via `management_path::route_http`) and
//!   FR-135 (no system proxy unless explicitly opted in via `http_client::builder`).

use serde::Serialize;
use std::time::Duration;
use tokio::sync::Mutex;

/// Static path appended to the validated centre origin.
pub const PMTILES_ASSET_PATH: &str = "/geo/mh-boundaries-v1.pmtiles";

/// Upper bound on a single byte-range request (8 MiB).
pub const MAX_PMTILES_RANGE_BYTES: u64 = 8 * 1024 * 1024;

/// Stable error prefix recognized by the companion's JS PMTiles `Source` to trigger
/// `pmtiles.EtagMismatch` cache invalidation and retry.
pub const PMTILES_ETAG_MISMATCH_PREFIX: &str = "ETAG_MISMATCH";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PmTilesRangeReply {
    pub data_b64: String,
    pub etag: Option<String>,
    pub cache_control: Option<String>,
    pub expires: Option<String>,
}

/// Cached HTTP client keyed by the FR-134 management route generation so TLS/HTTP2
/// connections are reused across tile fetches and rebuilt immediately on route change.
static PMTILES_CLIENT: Mutex<Option<(u64, reqwest::Client)>> = Mutex::const_new(None);

/// Build the full PMTiles URL for `server_url`, validating scheme/origin via
/// [`crate::globe_url::validate_server_origin`] and preserving any deployment base path.
pub fn build_pmtiles_url(server_url: &str) -> Result<String, String> {
    let base = crate::globe_url::validate_server_origin(server_url)?;
    Ok(format!("{base}{PMTILES_ASSET_PATH}"))
}

/// Validate `(offset, length)` and return the inclusive HTTP byte range `(start, end)`.
pub fn validate_range(offset: u64, length: u64) -> Result<(u64, u64), String> {
    if length == 0 {
        return Err("PMTiles range length must be greater than zero.".to_string());
    }
    if length > MAX_PMTILES_RANGE_BYTES {
        return Err(format!(
            "PMTiles range length {length} exceeds maximum allowed {MAX_PMTILES_RANGE_BYTES} bytes."
        ));
    }
    let end = offset
        .checked_add(length - 1)
        .ok_or_else(|| "PMTiles byte range overflows u64.".to_string())?;
    Ok((offset, end))
}

/// Format an HTTP `Range` header value (`bytes={start}-{end}`) after validating bounds.
pub fn format_range_header(offset: u64, length: u64) -> Result<String, String> {
    let (start, end) = validate_range(offset, length)?;
    Ok(format!("bytes={start}-{end}"))
}

/// Normalize a server or client ETag per PMTiles v4 rules: weak ETags (`W/...`) are
/// ignored because byte ranges are not guaranteed stable across weak validators.
pub fn normalize_etag(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() || trimmed.starts_with("W/") || trimmed.starts_with("w/") {
        return None;
    }
    Some(trimmed.to_string())
}

/// Parse total archive size from a `Content-Range: bytes */{total}` header on HTTP 416.
pub fn parse_content_range_total(header_value: &str) -> Option<u64> {
    let total_str = header_value.trim().strip_prefix("bytes */")?;
    let total = total_str.trim().parse::<u64>().ok()?;
    (total > 0).then_some(total)
}

/// RFC 4648 standard base64 encoder (avoids adding any new crate dependency).
pub fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

async fn pmtiles_http_client() -> Result<reqwest::Client, String> {
    let route_gen = meshharbor_node_core::management_path::route_generation();
    let mut guard = PMTILES_CLIENT.lock().await;
    if let Some((cached_gen, client)) = guard.as_ref()
        && *cached_gen == route_gen
    {
        return Ok(client.clone());
    }
    let client = meshharbor_node_core::management_path::route_http(
        meshharbor_node_core::http_client::builder(),
    )
    .timeout(REQUEST_TIMEOUT)
    .build()
    .map_err(|e| format!("Could not build HTTP client for map tiles: {e}"))?;
    *guard = Some((route_gen, client.clone()));
    Ok(client)
}

fn header_str(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

async fn send_range_request(
    client: &reqwest::Client,
    url: &str,
    range_header: &str,
    if_match: Option<&str>,
) -> Result<reqwest::Response, String> {
    let mut req = client.get(url).header(reqwest::header::RANGE, range_header);
    if let Some(etag) = if_match {
        req = req.header(reqwest::header::IF_MATCH, etag);
    }
    req.send()
        .await
        .map_err(|e| format!("Failed to fetch map tile range: {e}"))
}

/// Fetch one byte range from the enrolled centre's `/geo/mh-boundaries-v1.pmtiles`
/// archive over the FR-134 / FR-135 compliant Rust HTTP client.
#[tauri::command]
pub async fn cmd_pmtiles_range(
    offset: u64,
    length: u64,
    etag: Option<String>,
) -> Result<PmTilesRangeReply, String> {
    let range_header = format_range_header(offset, length)?;
    let server = crate::commands::server_origin().await?;
    let url = build_pmtiles_url(&server)?;
    let requested_etag = normalize_etag(etag.as_deref());
    let client = pmtiles_http_client().await?;

    let mut resp =
        send_range_request(&client, &url, &range_header, requested_etag.as_deref()).await?;

    // PMTiles initial header probe asks for 16 KiB at offset 0; if an archive is smaller,
    // retry with the exact archive length advertised by Content-Range.
    if offset == 0
        && resp.status() == reqwest::StatusCode::RANGE_NOT_SATISFIABLE
        && let Some(cr) = header_str(resp.headers(), "content-range")
        && let Some(total) = parse_content_range_total(&cr)
        && total <= MAX_PMTILES_RANGE_BYTES
    {
        let clamped = format_range_header(0, total)?;
        resp = send_range_request(&client, &url, &clamped, requested_etag.as_deref()).await?;
    }

    let status = resp.status();
    let reply_etag = normalize_etag(header_str(resp.headers(), "etag").as_deref());

    if status == reqwest::StatusCode::PRECONDITION_FAILED
        || status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE
        || (requested_etag.is_some() && reply_etag.is_some() && requested_etag != reply_etag)
    {
        return Err(format!(
            "{PMTILES_ETAG_MISMATCH_PREFIX}: map boundary archive changed (HTTP {})",
            status.as_u16()
        ));
    }

    if status != reqwest::StatusCode::PARTIAL_CONTENT && status != reqwest::StatusCode::OK {
        return Err(format!(
            "Map boundary tile request failed (HTTP {})",
            status.as_u16()
        ));
    }

    if status == reqwest::StatusCode::OK {
        match resp.content_length() {
            Some(cl) if cl <= length && cl <= MAX_PMTILES_RANGE_BYTES => {}
            _ => {
                return Err(
                    "Server did not honour HTTP Range request for map boundaries.".to_string(),
                );
            }
        }
    }

    let cache_control = header_str(resp.headers(), "cache-control");
    let expires = header_str(resp.headers(), "expires");
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Failed reading map tile range body: {e}"))?;

    if (bytes.len() as u64) > MAX_PMTILES_RANGE_BYTES {
        return Err(format!(
            "Map tile range response ({} bytes) exceeded cap ({MAX_PMTILES_RANGE_BYTES} bytes).",
            bytes.len()
        ));
    }

    Ok(PmTilesRangeReply {
        data_b64: encode_base64(&bytes),
        etag: reply_etag,
        cache_control,
        expires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_pmtiles_url_preserving_base_path_and_validating_origin() {
        assert_eq!(
            build_pmtiles_url("https://centre.example.test///").unwrap(),
            "https://centre.example.test/geo/mh-boundaries-v1.pmtiles"
        );
        assert_eq!(
            build_pmtiles_url("https://centre.example.test/meshharbor/").unwrap(),
            "https://centre.example.test/meshharbor/geo/mh-boundaries-v1.pmtiles"
        );
        assert_eq!(
            build_pmtiles_url("http://127.0.0.1:5000/sub/").unwrap(),
            "http://127.0.0.1:5000/sub/geo/mh-boundaries-v1.pmtiles"
        );
        assert_eq!(
            build_pmtiles_url("http://[::1]:5000").unwrap(),
            "http://[::1]:5000/geo/mh-boundaries-v1.pmtiles"
        );

        for bad in [
            "",
            "   ",
            "http://centre.example.test",
            "ftp://centre.example.test",
            "javascript:alert(1)",
            "https://user:pass@centre.example.test",
            "https://centre.example.test?a=1",
            "https://centre.example.test#frag",
        ] {
            assert!(
                build_pmtiles_url(bad).is_err(),
                "expected build_pmtiles_url to reject {bad:?}"
            );
        }
    }

    #[test]
    fn validates_and_formats_byte_ranges() {
        assert_eq!(validate_range(0, 1).unwrap(), (0, 0));
        assert_eq!(validate_range(0, 16384).unwrap(), (0, 16383));
        assert_eq!(format_range_header(4096, 2048).unwrap(), "bytes=4096-6143");
        assert_eq!(
            validate_range(10, MAX_PMTILES_RANGE_BYTES).unwrap(),
            (10, 10 + MAX_PMTILES_RANGE_BYTES - 1)
        );
        assert!(validate_range(0, 0).is_err());
        assert!(validate_range(0, MAX_PMTILES_RANGE_BYTES + 1).is_err());
        assert!(validate_range(u64::MAX, 2).is_err());
    }

    #[test]
    fn normalizes_etags_and_parses_content_range_totals() {
        assert_eq!(
            normalize_etag(Some("\"abc123\"")),
            Some("\"abc123\"".into())
        );
        assert_eq!(normalize_etag(Some("  \"v1\"  ")), Some("\"v1\"".into()));
        assert_eq!(normalize_etag(Some("W/\"weak\"")), None);
        assert_eq!(normalize_etag(Some("w/\"weak\"")), None);
        assert_eq!(normalize_etag(Some("   ")), None);
        assert_eq!(normalize_etag(None), None);

        assert_eq!(parse_content_range_total("bytes */4096"), Some(4096));
        assert_eq!(parse_content_range_total("bytes */0"), None);
        assert_eq!(parse_content_range_total("bytes 0-10/100"), None);
    }

    #[test]
    fn encodes_rfc4648_base64_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode_base64(&[0x00, 0x01, 0xfe, 0xff]), "AAH+/w==");
    }
}
