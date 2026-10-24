// SPDX-License-Identifier: MPL-2.0
//! Personal account data uses the existing server login and HttpOnly web session.
//! No agent token, password, or user JWT crosses the desktop IPC bridge.
use tauri::Manager;
pub const LABEL: &str = "meshharbor-account";
pub const DEFAULT_CENTER: &str = "https://www.itachi.fans/meshharbor";
/// The reused account window reads its current non-secret centre policy on every popup.
/// Reopening under a different server/prefix must not retain the first window's policy.
#[derive(Default)]
pub struct CenterPolicy(std::sync::Mutex<Option<tauri::Url>>);
impl CenterPolicy {
    fn replace(&self, base: tauri::Url) -> Result<(), String> {
        *self.0.lock().map_err(|_| "Account centre policy unavailable")? = Some(base);
        Ok(())
    }
    fn allows(&self, url: &tauri::Url) -> bool {
        self.0.lock().ok().and_then(|base| base.as_ref().map(|base| viewer_link(base, url))).unwrap_or(false)
    }
}

fn secure_server(server: &str) -> Result<tauri::Url, String> {
    let url: tauri::Url = server.trim().parse().map_err(|_| "Invalid account server URL")?;
    let loopback = url.host_str().and_then(|host| host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback());
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback)) {
        return Err("Account sign-in requires HTTPS, or literal loopback HTTP for local testing".into());
    }
    Ok(url)
}
pub fn account_url(server: &str, section: &str) -> Result<tauri::Url, String> {
    let mut url = secure_server(server)?;
    let (path, query) = match section {
        "devices" => ("my-devices", "desktop=1"),
        "received" => ("device-shares", "desktop=1&direction=received"),
        "sent" => ("device-shares", "desktop=1&direction=sent"),
        _ => return Err("Unknown personal account section".into()),
    };
    url.set_path(&format!("{}/{path}", url.path().trim_end_matches('/')));
    url.set_query(Some(query));
    Ok(url)
}
fn viewer_link(base: &tauri::Url, url: &tauri::Url) -> bool {
    if url.origin() != base.origin() || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some() { return false; }
    let prefix = format!("{}/", base.path().trim_end_matches('/'));
    let Some(path) = url.path().strip_prefix(&prefix) else { return false; };
    let p: Vec<_> = path.split('/').collect();
    let oid = |s: &str| s.len() == 24 && s.bytes().all(|b| b.is_ascii_hexdigit());
    match p.as_slice() {
        ["device-shares", id, "remote"] => oid(id),
        ["tenant", tid, "agent", aid, "remote"] => oid(tid) && oid(aid),
        _ => false,
    }
}
pub fn open<R: tauri::Runtime>(app: &tauri::AppHandle<R>, server: &str, section: &str) -> Result<(), String> {
    let base = secure_server(server)?;
    let url = account_url(server, section)?;
    if let Some(window) = app.get_webview_window(LABEL) {
        window.navigate(url).map_err(|_| "Cannot navigate the account window")?;
        app.state::<CenterPolicy>().replace(base)?;
        window.show().map_err(|_| "Cannot show the account window")?;
        window.set_focus().map_err(|_| "Cannot focus the account window")?;
        return Ok(());
    }
    app.state::<CenterPolicy>().replace(base)?;
    let handle = app.clone();
    // A data-only external-origin webview works on Windows, macOS and Linux.
    // Real desktop/file viewers still use the established Chromium/browser policy.
    tauri::WebviewWindowBuilder::new(app, LABEL, tauri::WebviewUrl::External(url))
        .title("MeshHarbor — My devices & sharing")
        .inner_size(1180.0, 820.0)
        .on_new_window(move |url, _| {
            if handle.state::<CenterPolicy>().allows(&url) {
                let handle = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = crate::commands::open_web_or_browser(&handle, url.as_str());
                });
            }
            tauri::webview::NewWindowResponse::Deny
        })
        .build().map_err(|_| "Cannot open the account window")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn personal_routes_preserve_deployment_prefix_and_never_accept_arbitrary_paths() {
        assert_eq!(account_url(DEFAULT_CENTER, "devices").unwrap().as_str(), "https://www.itachi.fans/meshharbor/my-devices?desktop=1");
        assert!(account_url(DEFAULT_CENTER, "sent").unwrap().as_str().ends_with("/device-shares?desktop=1&direction=sent"));
        assert!(account_url(DEFAULT_CENTER, "https://evil.test").is_err());
    }
    #[test]
    fn account_signin_has_strict_transport_and_no_credential_or_redirect_url_inputs() {
        for s in ["http://example.test", "http://localhost", "https://u:p@example.test", "https://example.test?token=x", "https://example.test/#else", "file:///tmp/page"] {
            assert!(account_url(s, "devices").is_err(), "{s}");
        }
        assert!(account_url("http://127.0.0.1:18081/base", "devices").is_ok());
    }
    #[test]
    fn external_viewers_are_same_center_strict_routes_without_tokens() {
        let base = secure_server(DEFAULT_CENTER).unwrap();
        assert!(viewer_link(&base, &"https://www.itachi.fans/meshharbor/device-shares/111111111111111111111111/remote".parse().unwrap()));
        for s in ["https://evil.test/meshharbor/device-shares/111111111111111111111111/remote", "https://www.itachi.fans/meshharbor-other/device-shares/111111111111111111111111/remote", "https://www.itachi.fans/meshharbor/device-shares/bad/remote", "https://www.itachi.fans/meshharbor/device-shares/111111111111111111111111/remote?token=secret"] {
            assert!(!viewer_link(&base, &s.parse().unwrap()));
        }
    }
    #[test]
    fn reused_window_policy_tracks_changed_center_and_same_origin_prefix() {
        let policy = CenterPolicy::default();
        let a: tauri::Url = "https://a.example/base/device-shares/111111111111111111111111/remote".parse().unwrap();
        let b: tauri::Url = "https://b.example/base/device-shares/111111111111111111111111/remote".parse().unwrap();
        let c: tauri::Url = "https://b.example/next/device-shares/111111111111111111111111/remote".parse().unwrap();
        assert_eq!(LABEL, "meshharbor-account");
        assert!(!policy.allows(&a));
        policy.replace(secure_server("https://a.example/base").unwrap()).unwrap();
        assert!(policy.allows(&a)); assert!(!policy.allows(&b));
        policy.replace(secure_server("https://b.example/base").unwrap()).unwrap();
        assert!(!policy.allows(&a)); assert!(policy.allows(&b));
        policy.replace(secure_server("https://b.example/next").unwrap()).unwrap();
        assert!(!policy.allows(&a)); assert!(!policy.allows(&b)); assert!(policy.allows(&c));
    }

}
