// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! On-disk config for `roomler`.
//!
//! Mirrors `roomlerd`'s pattern: TOML file at the platform-specific
//! per-user config dir, populated by `meshharbor enroll` and read
//! by `forward` / `run` / `diagnose`. Env vars `ROOMLER_TUNNEL_SERVER`
//! and `ROOMLER_TUNNEL_TOKEN` override the file when both are set, so
//! CI / smoke tests don't need to drop a real file.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Base URL of the Roomler API (no trailing slash needed,
    /// e.g. `https://roomler.ai`). Used to derive the WS URL by
    /// rewriting the scheme to `wss://` and appending `/ws`.
    pub server_url: String,

    /// Long-lived `TunnelClient` JWT (audience = `tunnel-client`).
    /// Issued by `POST /api/tunnel-client/enroll` in exchange for
    /// the operator's `TunnelEnrollment` token.
    pub tunnel_client_token: String,

    /// Optional friendly name for diagnostics. Mirrors the agent's
    /// `machine_name`; populated by `enroll --name`.
    #[serde(default)]
    pub machine_name: String,

    /// FR-101 P1b — keep a plaintext `server_url` as written. Without it a
    /// remote `http://` URL is read as `https://`
    /// (`roomler_ai_remote_control::server_url`), so the token renewal, the
    /// self-update and the tunnel's socket all go over TLS. For a lab whose
    /// server serves no TLS; loopback is never promoted. The environment form
    /// is `ROOMLER_TUNNEL_ALLOW_PLAINTEXT=1`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_plaintext_server: bool,
}

impl TunnelConfig {
    /// FR-101 P1b — read `server_url` over TLS unless the owner kept
    /// plaintext; say so when it changed. Called by [`load`] on both of its
    /// paths, the file and the environment.
    fn secure_server_url(&mut self) {
        let s = roomler_ai_remote_control::server_url::secure(
            &self.server_url,
            self.allow_plaintext_server,
        );
        if s.promoted {
            tracing::warn!(
                was = %self.server_url,
                now = %s.url,
                "a plaintext server URL is read as TLS; set allow_plaintext_server = true \
                 (or ROOMLER_TUNNEL_ALLOW_PLAINTEXT=1) to keep plaintext"
            );
            self.server_url = s.url;
        }
    }
}

/// FR-101 P1b — the server URL an enrollment posts its token to and saves:
/// a remote `http://` is `https://`, as the agent's enrollment does, so the
/// token travels over TLS; loopback is left alone, and there is no plaintext
/// escape. Shared by `meshharbor enroll` and the setup wizard's tunnel role.
pub fn enrollment_server_url(raw: &str) -> String {
    let secured = roomler_ai_remote_control::server_url::secure(raw, false);
    if secured.promoted {
        tracing::warn!(
            original = %raw,
            "upgrading http:// to https:// — enrollment tokens must travel over TLS"
        );
    }
    secured.url.trim_end_matches('/').to_string()
}

// RETIRED-NAME-ANCHOR(4): ProjectDirs segment holding the ENROLLED credential on
// tunnel-only hosts.
/// Resolve the default per-user config path. On Windows this lands at
/// `%APPDATA%\roomler\roomler-tunnel\config.toml`; on Linux/macOS the
/// `directories` crate's `ProjectDirs::config_dir()` is honoured.
pub fn default_config_path() -> Result<PathBuf> {
    // RETIRED-NAME-ANCHOR(2): tunnel-only hosts keep their ENROLLED config here.
    // Renaming the segment orphans it, exactly as it would for appdirs::OLD_APP.
    // Migrating it needs the same new-then-old resolution appdirs has — P4, not a
    // drive-by. See docs/fr/FR-21.
    let dirs = directories::ProjectDirs::from("ai", "roomler", "roomler-tunnel")
        .context("no platform config dir available for roomler-tunnel")?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// Load config from `path` (or the default). Env-var overrides
/// short-circuit the file read when BOTH `ROOMLER_TUNNEL_SERVER` and
/// `ROOMLER_TUNNEL_TOKEN` are set — useful for CI / smoke tests where
/// dropping a file is more friction than setting two env vars.
pub fn load(path: Option<PathBuf>) -> Result<TunnelConfig> {
    if let (Ok(server), Ok(token)) = (
        std::env::var("ROOMLER_TUNNEL_SERVER"),
        std::env::var("ROOMLER_TUNNEL_TOKEN"),
    ) {
        let mut cfg = TunnelConfig {
            server_url: server,
            tunnel_client_token: token,
            machine_name: std::env::var("ROOMLER_TUNNEL_NAME").unwrap_or_default(),
            allow_plaintext_server: std::env::var("ROOMLER_TUNNEL_ALLOW_PLAINTEXT")
                .is_ok_and(|v| v == "1"),
        };
        cfg.secure_server_url();
        return Ok(cfg);
    }

    let resolved = match path {
        Some(p) => p,
        None => default_config_path()?,
    };
    if !resolved.exists() {
        bail!(
            "tunnel-client config not found at {}. Run `meshharbor enroll --server <url> --token <jwt> --name <label>` first.",
            resolved.display()
        );
    }
    let s = std::fs::read_to_string(&resolved)
        .with_context(|| format!("reading tunnel config {}", resolved.display()))?;
    let mut cfg: TunnelConfig = toml::from_str(&s)
        .with_context(|| format!("parsing tunnel config {}", resolved.display()))?;
    cfg.secure_server_url();
    if cfg.tunnel_client_token.is_empty() {
        bail!(
            "tunnel-client config at {} has empty tunnel_client_token. Re-run `meshharbor enroll`.",
            resolved.display()
        );
    }
    Ok(cfg)
}

/// Is the config coming from `ROOMLER_TUNNEL_SERVER` + `ROOMLER_TUNNEL_TOKEN`
/// rather than a file? Then [`load`] never reads one, and nothing may be
/// saved to one on its behalf.
pub fn from_environment() -> bool {
    std::env::var("ROOMLER_TUNNEL_SERVER").is_ok() && std::env::var("ROOMLER_TUNNEL_TOKEN").is_ok()
}

/// Persist `cfg` to `path` (or the default). Creates the parent
/// directory if absent. Idempotent overwrite.
///
/// FR-103 — atomic and private: a crash mid-write leaves the previous file,
/// never a torn one holding half a credential, and the file is owner-only
/// (`0600` on Unix; on Windows the per-user profile directory's ACL). It
/// holds a long-lived token.
pub fn save(cfg: &TunnelConfig, path: Option<&Path>) -> Result<PathBuf> {
    let target = match path {
        Some(p) => p.to_path_buf(),
        None => default_config_path()?,
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating tunnel config dir {}", parent.display()))?;
    }
    let serialised = toml::to_string_pretty(cfg).context("serialising tunnel config")?;
    write_private_atomic(&target, serialised.as_bytes())
        .with_context(|| format!("writing tunnel config {}", target.display()))?;
    Ok(target)
}

/// FR-103 — save a renewed token, compare-and-swap: only while the file still
/// holds `renewed_from`. A file holding a different token was re-enrolled
/// meanwhile (`meshharbor enroll`), and its token wins: nothing is written and
/// an error says why. Every other field is kept as the FILE has it.
pub fn save_renewed_token(
    cfg: &TunnelConfig,
    renewed_from: &str,
    path: Option<&Path>,
) -> Result<()> {
    let target = match path {
        Some(p) => p.to_path_buf(),
        None => default_config_path()?,
    };
    let current = std::fs::read_to_string(&target)
        .with_context(|| format!("reading tunnel config {}", target.display()))?;
    let mut on_disk: TunnelConfig = toml::from_str(&current)
        .with_context(|| format!("parsing tunnel config {}", target.display()))?;
    if on_disk.tunnel_client_token != renewed_from {
        bail!(
            "{} was re-enrolled while the token was being renewed; keeping its token",
            target.display()
        );
    }
    on_disk.tunnel_client_token = cfg.tunnel_client_token.clone();
    save(&on_disk, Some(&target)).map(|_| ())
}

/// Write `bytes` to `target` through an owner-only temp file beside it,
/// synced, then renamed over the target.
fn write_private_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let tmp = {
        let mut name = target.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".tmp-{}", std::process::id()));
        target.with_file_name(name)
    };
    // A leftover from a crashed run of the same pid would fail `create_new`.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let written = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, target)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Convert `server_url` into the WS URL the agent dials. Honours
/// `http://` → `ws://` and `https://` → `wss://`. Trims any trailing
/// slash so we don't end up with `//ws`.
pub fn derive_ws_url(server_url: &str) -> Result<String> {
    let trimmed = server_url.trim_end_matches('/');
    let ws = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        trimmed.to_string()
    } else {
        bail!("server_url must be http(s):// or ws(s)://, got {server_url}");
    };
    Ok(format!("{ws}/ws"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(token: &str) -> TunnelConfig {
        TunnelConfig {
            server_url: "https://example.invalid".to_string(),
            tunnel_client_token: token.to_string(),
            machine_name: "box".to_string(),
            allow_plaintext_server: false,
        }
    }

    /// FR-103 — the save leaves no temp file behind and, on Unix, an
    /// owner-only file: it holds a long-lived token.
    #[test]
    fn save_is_atomic_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        save(&cfg("tok-1"), Some(&path)).unwrap();
        save(&cfg("tok-2"), Some(&path)).unwrap();
        assert_eq!(
            load(Some(path.clone())).unwrap().tunnel_client_token,
            "tok-2"
        );
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 1, "no temp file left behind: {left:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner-only, got {mode:o}");
        }
    }

    /// FR-103 — a renewed token is saved only over the token it renewed: a
    /// file re-enrolled meanwhile keeps its own, and every other field stays
    /// as the file has it.
    #[test]
    fn a_renewed_token_never_overwrites_a_re_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut on_disk = cfg("old");
        on_disk.machine_name = "named-on-disk".to_string();
        save(&on_disk, Some(&path)).unwrap();

        save_renewed_token(&cfg("renewed"), "old", Some(&path)).unwrap();
        let after = load(Some(path.clone())).unwrap();
        assert_eq!(after.tunnel_client_token, "renewed");
        assert_eq!(after.machine_name, "named-on-disk");

        save(&cfg("re-enrolled"), Some(&path)).unwrap();
        let err = save_renewed_token(&cfg("renewed-again"), "renewed", Some(&path)).unwrap_err();
        assert!(err.to_string().contains("re-enrolled"), "{err:#}");
        assert_eq!(load(Some(path)).unwrap().tunnel_client_token, "re-enrolled");
    }

    #[test]
    fn derive_ws_url_https_becomes_wss() {
        assert_eq!(
            derive_ws_url("https://roomler.ai").unwrap(),
            "wss://roomler.ai/ws"
        );
    }

    #[test]
    fn derive_ws_url_strips_trailing_slash() {
        assert_eq!(
            derive_ws_url("https://roomler.ai/").unwrap(),
            "wss://roomler.ai/ws"
        );
    }

    #[test]
    fn derive_ws_url_http_becomes_ws() {
        assert_eq!(
            derive_ws_url("http://localhost:3000").unwrap(),
            "ws://localhost:3000/ws"
        );
    }

    #[test]
    fn derive_ws_url_passes_ws_through() {
        assert_eq!(
            derive_ws_url("wss://roomler.ai").unwrap(),
            "wss://roomler.ai/ws"
        );
    }

    #[test]
    fn derive_ws_url_rejects_unknown_scheme() {
        assert!(derive_ws_url("ftp://example.com").is_err());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tunnel.toml");
        let cfg = TunnelConfig {
            server_url: "https://test.example".to_string(),
            tunnel_client_token: "test-jwt".to_string(),
            machine_name: "test-laptop".to_string(),
            allow_plaintext_server: false,
        };
        save(&cfg, Some(&path)).unwrap();
        let loaded = load(Some(path)).unwrap();
        assert_eq!(loaded.server_url, cfg.server_url);
        assert_eq!(loaded.tunnel_client_token, cfg.tunnel_client_token);
        assert_eq!(loaded.machine_name, cfg.machine_name);
    }

    /// FR-101 P1b — a saved plaintext URL to a remote host is read as TLS,
    /// so the tunnel dials `wss://`; loopback stays as written, and so does
    /// everything under the owner's escape. Tested through a file: a test
    /// that set `ROOMLER_TUNNEL_*` would race every other test here.
    #[test]
    fn a_plaintext_server_url_is_read_as_tls_unless_loopback_or_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let load_with = |name: &str, server: &str, allow: bool| {
            let path = tmp.path().join(format!("{name}.toml"));
            let cfg = TunnelConfig {
                server_url: server.to_string(),
                tunnel_client_token: "jwt".to_string(),
                machine_name: String::new(),
                allow_plaintext_server: allow,
            };
            save(&cfg, Some(&path)).unwrap();
            load(Some(path)).unwrap()
        };
        let remote = load_with("remote", "http://roomler.ai", false);
        assert_eq!(remote.server_url, "https://roomler.ai");
        assert_eq!(
            derive_ws_url(&remote.server_url).unwrap(),
            "wss://roomler.ai/ws"
        );
        let local = load_with("local", "http://127.0.0.1:3000", false);
        assert_eq!(
            derive_ws_url(&local.server_url).unwrap(),
            "ws://127.0.0.1:3000/ws"
        );
        let lab = load_with("lab", "http://lab.example:3000", true);
        assert_eq!(lab.server_url, "http://lab.example:3000");
    }

    /// FR-101 P1b — `meshharbor enroll` and the wizard's tunnel role post the
    /// token over TLS, whatever the owner's escape says; loopback stays.
    #[test]
    fn an_enrollment_posts_its_token_over_tls() {
        assert_eq!(
            enrollment_server_url("http://roomler.ai/"),
            "https://roomler.ai"
        );
        assert_eq!(
            enrollment_server_url("HTTP:roomler.ai"),
            "https://roomler.ai"
        );
        assert_eq!(
            enrollment_server_url("https://roomler.ai/"),
            "https://roomler.ai"
        );
        assert_eq!(
            enrollment_server_url("http://127.0.0.1:3000/"),
            "http://127.0.0.1:3000"
        );
    }

    #[test]
    fn load_rejects_empty_token() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tunnel.toml");
        let cfg = TunnelConfig {
            server_url: "https://test.example".to_string(),
            tunnel_client_token: String::new(),
            machine_name: String::new(),
            allow_plaintext_server: false,
        };
        save(&cfg, Some(&path)).unwrap();
        let err = load(Some(path)).unwrap_err();
        assert!(
            err.to_string().contains("empty tunnel_client_token"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_missing_file_has_helpful_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent.toml");
        let err = load(Some(path)).unwrap_err();
        assert!(err.to_string().contains("meshharbor enroll"));
    }
}
