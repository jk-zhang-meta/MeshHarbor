// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Tray and desktop-companion UI language (`en` and `zh-CN`).
//!
//! Resolution order matches the web UI (`ui/src/plugins/i18n.ts`):
//! 1. Saved explicit choice (`"en"` or `"zh-CN"`) in per-user `desktop-state.json`.
//! 2. OS UI locale: any `zh*` (`zh`, `zh-CN`, `zh-Hans`, `zh-TW`, …) → `zh-CN`;
//!    everything else → `en`.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use meshharbor_node_core::desktop_state;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime};

/// Supported UI languages for the desktop companion and tray menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    En,
    ZhCn,
}

impl Lang {
    /// Canonical BCP-47 code persisted in state and exchanged with webviews.
    pub const fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhCn => "zh-CN",
        }
    }

    /// Parse a saved/explicit language choice (`"en"` or `"zh-CN"`).
    pub fn parse_saved(raw: &str) -> Option<Self> {
        let norm = raw.trim().replace('_', "-").to_ascii_lowercase();
        match norm.as_str() {
            "en" => Some(Lang::En),
            "zh-cn" => Some(Lang::ZhCn),
            _ => None,
        }
    }

    /// Map any OS locale tag (`zh`, `zh-CN`, `zh_CN.UTF-8`, `zh-TW`, `en_US.UTF-8`, …)
    /// to a supported language: any `zh*` → `ZhCn`, everything else → `En`.
    pub fn from_locale_tag(tag: &str) -> Self {
        let norm = tag.trim().replace('_', "-").to_ascii_lowercase();
        let primary = norm.split(['.', '@', ';', ' ']).next().unwrap_or("");
        if primary == "zh" || primary.starts_with("zh-") {
            Lang::ZhCn
        } else {
            Lang::En
        }
    }
}

/// Sentinel values for the cached language atomic (`0` = uninitialized).
const CACHE_UNSET: u8 = 0;
const CACHE_EN: u8 = 1;
const CACHE_ZH_CN: u8 = 2;

static CURRENT_LANG: AtomicU8 = AtomicU8::new(CACHE_UNSET);
static LANG_GENERATION: AtomicU64 = AtomicU64::new(0);

fn encode_lang(lang: Lang) -> u8 {
    match lang {
        Lang::En => CACHE_EN,
        Lang::ZhCn => CACHE_ZH_CN,
    }
}

fn decode_lang(v: u8) -> Option<Lang> {
    match v {
        CACHE_EN => Some(Lang::En),
        CACHE_ZH_CN => Some(Lang::ZhCn),
        _ => None,
    }
}

/// Resolve the effective language from an optional saved choice and an OS fallback.
pub fn resolve_lang(saved: Option<&str>, os_lang: Lang) -> Lang {
    saved.and_then(Lang::parse_saved).unwrap_or(os_lang)
}

/// Map a Win32 UI `LANGID` to a supported language.
/// Primary language ID (`lang_id & 0x03ff`) `0x04` is `LANG_CHINESE`, covering
/// `zh-CN`, `zh-TW`, `zh-HK`, `zh-SG`, `zh-Hans`, and `zh-Hant`.
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn lang_from_win32_langid(lang_id: u16) -> Lang {
    const LANG_CHINESE: u16 = 0x04;
    if (lang_id & 0x03ff) == LANG_CHINESE {
        Lang::ZhCn
    } else {
        Lang::En
    }
}

/// Pick the POSIX/gettext locale tag from standard environment variables:
/// `LC_ALL` → `LANGUAGE` (first colon-separated item) → `LC_MESSAGES` → `LANG`.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub fn detect_locale_from_env(
    lc_all: Option<&str>,
    language: Option<&str>,
    lc_messages: Option<&str>,
    lang: Option<&str>,
) -> Option<String> {
    let clean = |v: Option<&str>| -> Option<String> {
        let s = v?.trim();
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };
    if let Some(v) = clean(lc_all) {
        return Some(v);
    }
    if let Some(list) = clean(language)
        && let Some(first) = list.split(':').map(str::trim).find(|s| !s.is_empty())
    {
        return Some(first.to_string());
    }
    if let Some(v) = clean(lc_messages) {
        return Some(v);
    }
    clean(lang)
}

#[cfg(not(target_os = "windows"))]
fn env_locale_tag() -> Option<String> {
    let lc_all = std::env::var("LC_ALL").ok();
    let language = std::env::var("LANGUAGE").ok();
    let lc_messages = std::env::var("LC_MESSAGES").ok();
    let lang = std::env::var("LANG").ok();
    detect_locale_from_env(
        lc_all.as_deref(),
        language.as_deref(),
        lc_messages.as_deref(),
        lang.as_deref(),
    )
}

#[cfg(target_os = "windows")]
pub fn detect_os_lang() -> Lang {
    // SAFETY: `GetUserDefaultUILanguage` takes no pointers and returns the
    // current user's Win32 UI LANGID.
    let lang_id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
    lang_from_win32_langid(lang_id)
}

#[cfg(target_os = "macos")]
pub fn detect_os_lang() -> Lang {
    if let Some(tag) = env_locale_tag() {
        return Lang::from_locale_tag(&tag);
    }
    use std::ffi::{c_char, c_void};
    type CFArrayRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFIndex = isize;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFLocaleCopyPreferredLanguages() -> CFArrayRef;
        fn CFArrayGetCount(the_array: CFArrayRef) -> CFIndex;
        fn CFArrayGetValueAtIndex(the_array: CFArrayRef, idx: CFIndex) -> *const c_void;
        fn CFStringGetCString(
            the_string: CFStringRef,
            buffer: *mut c_char,
            buffer_size: CFIndex,
            encoding: u32,
        ) -> u8;
        fn CFRelease(cf: *const c_void);
    }
    // SAFETY: Standard macOS CoreFoundation ABI. `langs` is checked for null
    // and released once before return; `buf` is a live buffer of `buf.len()`.
    unsafe {
        let langs = CFLocaleCopyPreferredLanguages();
        if langs.is_null() {
            return Lang::En;
        }
        let result = if CFArrayGetCount(langs) > 0 {
            let first = CFArrayGetValueAtIndex(langs, 0) as CFStringRef;
            let mut buf = [0u8; 64];
            if !first.is_null()
                && CFStringGetCString(
                    first,
                    buf.as_mut_ptr().cast::<c_char>(),
                    buf.len() as CFIndex,
                    K_CF_STRING_ENCODING_UTF8,
                ) != 0
            {
                let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                std::str::from_utf8(&buf[..nul])
                    .map(Lang::from_locale_tag)
                    .unwrap_or(Lang::En)
            } else {
                Lang::En
            }
        } else {
            Lang::En
        };
        CFRelease(langs);
        result
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn detect_os_lang() -> Lang {
    env_locale_tag()
        .map(|tag| Lang::from_locale_tag(&tag))
        .unwrap_or(Lang::En)
}

/// Active language for the tray and companion (cached after first load).
pub fn current_lang() -> Lang {
    if let Some(lang) = decode_lang(CURRENT_LANG.load(Ordering::Acquire)) {
        return lang;
    }
    let state = desktop_state::load();
    let lang = resolve_lang(state.ui_language.as_deref(), detect_os_lang());
    CURRENT_LANG.store(encode_lang(lang), Ordering::Release);
    lang
}

/// Monotonic counter bumped whenever the language changes at runtime.
pub fn language_generation() -> u64 {
    LANG_GENERATION.load(Ordering::Acquire)
}

/// Update the in-memory language cache and bump the generation counter.
pub fn set_cached_lang(lang: Lang) {
    CURRENT_LANG.store(encode_lang(lang), Ordering::Release);
    LANG_GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// Payload returned by `get_ui_language` and `set_ui_language`.
#[derive(Debug, Clone, Serialize)]
pub struct UiLanguageView {
    /// Active effective language (`"en"` or `"zh-CN"`).
    pub language: &'static str,
    /// Saved explicit choice, or `None` when following the OS locale.
    pub saved: Option<&'static str>,
}

/// Return the companion's effective UI language and whether it was saved explicitly.
#[tauri::command]
pub fn get_ui_language() -> UiLanguageView {
    let state = desktop_state::load();
    let saved = state.ui_language.as_deref().and_then(Lang::parse_saved);
    let effective = saved.unwrap_or_else(detect_os_lang);
    CURRENT_LANG.store(encode_lang(effective), Ordering::Release);
    UiLanguageView {
        language: effective.code(),
        saved: saved.map(Lang::code),
    }
}

/// Save an explicit UI language (`"en"` or `"zh-CN"`), refresh the tray menu
/// immediately, and broadcast the change to every open webview.
#[tauri::command]
pub fn set_ui_language<R: Runtime>(
    app: AppHandle<R>,
    language: String,
) -> Result<UiLanguageView, String> {
    let lang = Lang::parse_saved(&language).ok_or_else(|| {
        format!("unsupported language: {language} (expected \"en\" or \"zh-CN\")")
    })?;
    let mut state = desktop_state::load();
    state.ui_language = Some(lang.code().to_string());
    desktop_state::save(&state).map_err(|e| format!("saving the desktop state: {e}"))?;
    set_cached_lang(lang);
    crate::tray::refresh_language(&app);
    let _ = app.emit("meshharbor:language", lang.code());
    Ok(UiLanguageView {
        language: lang.code(),
        saved: Some(lang.code()),
    })
}

// ─── Localized tray & dialog strings ────────────────────────────────────────

pub const fn app_name(_lang: Lang) -> &'static str {
    "MeshHarbor"
}

pub const fn login_ellipsis(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Log in…",
        Lang::ZhCn => "登录…",
    }
}

pub const fn sign_in_ellipsis(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Sign in…",
        Lang::ZhCn => "登录账号…",
    }
}

pub const fn sign_out_account(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Sign out of account (device stays on the network)…",
        Lang::ZhCn => "退出账号（本设备仍保持在线）…",
    }
}

pub const fn join_invite(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Join with an invite code…",
        Lang::ZhCn => "使用邀请码加入…",
    }
}

pub const fn network_devices(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Network devices",
        Lang::ZhCn => "网络中的设备",
    }
}

pub const fn invitations(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Invitations",
        Lang::ZhCn => "邀请",
    }
}

pub const fn open_meshharbor(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Open MeshHarbor",
        Lang::ZhCn => "打开 MeshHarbor",
    }
}

pub const fn open_globe(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Open globe",
        Lang::ZhCn => "打开地球",
    }
}

pub const fn admin_console(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Admin console…",
        Lang::ZhCn => "管理控制台…",
    }
}

pub const fn start_recording(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Start recording",
        Lang::ZhCn => "开始录制",
    }
}

pub fn stop_recording(lang: Lang, elapsed: &str) -> String {
    match lang {
        Lang::En => format!("Stop recording ({elapsed})"),
        Lang::ZhCn => format!("停止录制 ({elapsed})"),
    }
}

pub fn tooltip_recording(lang: Lang, elapsed: &str) -> String {
    match lang {
        Lang::En => format!("MeshHarbor — recording {elapsed}"),
        Lang::ZhCn => format!("MeshHarbor — 正在录制 {elapsed}"),
    }
}

pub fn tooltip_remote_recording(lang: Lang, who: &str, elapsed: &str) -> String {
    match lang {
        Lang::En => format!("MeshHarbor — {who} is recording, {elapsed}"),
        Lang::ZhCn => format!("MeshHarbor — {who} 正在录制，{elapsed}"),
    }
}

pub const fn keep_busy_off(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Keep busy: off",
        Lang::ZhCn => "保持活跃：关",
    }
}

pub const fn keep_busy_unavailable(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Keep busy: unavailable",
        Lang::ZhCn => "保持活跃：不可用",
    }
}

pub const fn start_keep_busy(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Start keep busy",
        Lang::ZhCn => "开启保持活跃",
    }
}

pub const fn keep_busy_pattern_fallback(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Pattern",
        Lang::ZhCn => "默认模式",
    }
}

pub fn stop_keep_busy(lang: Lang, pattern: &str, phase: &str) -> String {
    match lang {
        Lang::En => format!("Stop keep busy ({pattern} · {phase})"),
        Lang::ZhCn => format!("停止保持活跃（{pattern} · {phase}）"),
    }
}

pub const fn onboarding(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Onboarding…",
        Lang::ZhCn => "设备接入…",
    }
}

pub const fn welcome_tour(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Welcome tour…",
        Lang::ZhCn => "欢迎引导…",
    }
}

pub const fn check_updates(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Check for Updates",
        Lang::ZhCn => "检查更新",
    }
}

pub fn update_ready(lang: Lang, version: &str) -> String {
    let ver = version.strip_prefix("agent-v").unwrap_or(version);
    match lang {
        Lang::En => format!("Update Ready ({ver}) — Install"),
        Lang::ZhCn => format!("有新版本（{ver}）· 点击升级"),
    }
}

pub fn update_available(lang: Lang, version: &str) -> String {
    let ver = version.strip_prefix("agent-v").unwrap_or(version);
    match lang {
        Lang::En => format!("Update Available ({ver})"),
        Lang::ZhCn => format!("发现新版本（{ver}）"),
    }
}

pub const fn open_logs(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Open Logs Folder",
        Lang::ZhCn => "打开日志文件夹",
    }
}

pub const fn quit(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Quit",
        Lang::ZhCn => "退出",
    }
}

pub const fn choose_exposed_features(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Choose exposed features…",
        Lang::ZhCn => "选择开放的功能…",
    }
}

pub const fn no_devices_yet(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "No devices yet",
        Lang::ZhCn => "暂无设备",
    }
}

pub fn approve_in_browser(lang: Lang, code: &str) -> String {
    match lang {
        Lang::En => format!("Approve in your browser — code {code}"),
        Lang::ZhCn => format!("请在浏览器中批准 — 验证码 {code}"),
    }
}

pub const fn working(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Working…",
        Lang::ZhCn => "处理中…",
    }
}

pub fn failed(lang: Lang, err: &str) -> String {
    match lang {
        Lang::En => format!("Failed: {err}"),
        Lang::ZhCn => format!("失败：{err}"),
    }
}

pub const fn not_signed_in(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Not signed in",
        Lang::ZhCn => "未登录",
    }
}

pub const fn an_organization(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "an organization",
        Lang::ZhCn => "某个组织",
    }
}

pub fn format_remaining(lang: Lang, access_until_ms: i64, now_ms: i64) -> String {
    match lang {
        Lang::En => meshharbor_node_core::device_invite::remaining_words(access_until_ms, now_ms),
        Lang::ZhCn => {
            let mins = (access_until_ms - now_ms).max(0) / 60_000;
            if mins < 1 {
                "不足 1 分钟".to_string()
            } else if mins < 60 {
                format!("{mins} 分钟")
            } else if mins < 24 * 60 {
                format!("{} 小时 {} 分钟", mins / 60, mins % 60)
            } else {
                format!("{} 天 {} 小时", mins / (24 * 60), (mins / 60) % 24)
            }
        }
    }
}

pub fn temporary_device_left(lang: Lang, left: &str) -> String {
    match lang {
        Lang::En => format!("Temporary device · {left} left"),
        Lang::ZhCn => format!("临时设备 · 剩余 {left}"),
    }
}

pub fn managed_by_left(lang: Lang, inviter: &str, left: &str) -> String {
    match lang {
        Lang::En => format!("Managed by {inviter} · {left} left"),
        Lang::ZhCn => format!("由 {inviter} 管理 · 剩余 {left}"),
    }
}

pub fn invitations_next_ends(lang: Lang, count: usize, left: &str) -> String {
    match lang {
        Lang::En => format!("{count} invitations · next ends in {left}"),
        Lang::ZhCn => format!("{count} 个邀请 · 最早于 {left} 后到期"),
    }
}

pub const fn service_not_running(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "MeshHarbor service is not running",
        Lang::ZhCn => "MeshHarbor 服务未运行",
    }
}

pub const fn no_address_yet(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "no address yet",
        Lang::ZhCn => "暂无地址",
    }
}

pub fn device_status_offline(lang: Lang, name: &str, ip: &str) -> String {
    match lang {
        Lang::En => format!("{name} · {ip} (offline)"),
        Lang::ZhCn => format!("{name} · {ip}（离线）"),
    }
}

pub fn waiting_code_cancel(lang: Lang, code: &str) -> String {
    match lang {
        Lang::En => format!("Waiting ({code}) · click to cancel"),
        Lang::ZhCn => format!("等待批准 ({code}) · 点击取消"),
    }
}

pub const fn waiting_cancel(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Waiting… · click to cancel",
        Lang::ZhCn => "等待批准… · 点击取消",
    }
}

pub const fn signed_in(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Signed in",
        Lang::ZhCn => "已登录",
    }
}

pub fn signed_in_as(lang: Lang, email: &str) -> String {
    match lang {
        Lang::En => format!("Signed in as {email}"),
        Lang::ZhCn => format!("已登录：{email}"),
    }
}

pub fn session_unconfirmed(lang: Lang, email: &str) -> String {
    match lang {
        Lang::En => format!("{email} · offline / session unconfirmed"),
        Lang::ZhCn => format!("{email} · 离线或会话未确认"),
    }
}

pub fn leave_invite(lang: Lang, who: &str, left: &str) -> String {
    match lang {
        Lang::En => format!("Leave · {who} · {left} left"),
        Lang::ZhCn => format!("退出邀请 · {who} · 剩余 {left}"),
    }
}

// ─── FR-133 ("Move this device?" dialog strings) ───────────────────────────

pub const fn move_title(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Move this device?",
        Lang::ZhCn => "移动此设备？",
    }
}

pub const fn move_yes(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Move",
        Lang::ZhCn => "移动",
    }
}

pub const fn move_no(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Keep",
        Lang::ZhCn => "保留",
    }
}

pub fn move_belongs_to(lang: Lang, org: &str) -> String {
    match lang {
        Lang::En => format!("This device belongs to {org}."),
        Lang::ZhCn => format!("此设备属于 {org}。"),
    }
}

pub fn move_question(lang: Lang, org: &str) -> String {
    match lang {
        Lang::En => format!("This device belongs to {org}. Move it to your organization?"),
        Lang::ZhCn => format!("此设备属于 {org}。要将其移动到你的组织吗？"),
    }
}

pub fn move_open_link(lang: Lang, code: &str, url: &str) -> String {
    match lang {
        Lang::En => format!(
            "Open this link to approve moving the device, and check that the page shows the code {code}:\n\n{url}"
        ),
        Lang::ZhCn => {
            format!("请打开此链接批准移动此设备，并确认页面显示的验证码为 {code}：\n\n{url}")
        }
    }
}

pub const fn move_done_title(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Device moved",
        Lang::ZhCn => "设备已移动",
    }
}

pub fn move_done_body(lang: Lang, org: &str, notice: Option<&str>) -> String {
    match (lang, notice) {
        (Lang::En, Some(n)) => format!("This device is now enrolled in your organization.\n\n{n}"),
        (Lang::En, None) => {
            format!("This device has been moved to your organization and removed from {org}.")
        }
        (Lang::ZhCn, Some(n)) => format!("此设备现已加入你的组织。\n\n{n}"),
        (Lang::ZhCn, None) => format!("此设备已移动到你的组织，并已从 {org} 移除。"),
    }
}

pub const fn move_failed_title(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "The device was not moved",
        Lang::ZhCn => "设备未移动",
    }
}

#[allow(dead_code)]
pub const fn move_cancelled(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Move cancelled — device stayed in its current organization.",
        Lang::ZhCn => "已取消移动 — 设备仍保留在原组织中。",
    }
}

#[allow(dead_code)]
pub fn move_kept_notice(lang: Lang, org: &str) -> String {
    match lang {
        Lang::En => format!("Kept in {org}. Your account session was not linked to this device."),
        Lang::ZhCn => format!("已保留在 {org}。你的账号未与此设备关联。"),
    }
}

#[allow(dead_code)]
pub const fn move_in_progress(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "Moving this device…",
        Lang::ZhCn => "正在移动此设备…",
    }
}

#[allow(dead_code)]
pub fn move_failed(lang: Lang, err: &str) -> String {
    match lang {
        Lang::En => format!("Could not move this device: {err}"),
        Lang::ZhCn => format!("无法移动此设备：{err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_cjk(s: &str) -> bool {
        s.chars().any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c))
    }

    #[test]
    fn locale_tag_maps_any_zh_to_zh_cn_and_others_to_en() {
        for zh in [
            "zh",
            "zh-CN",
            "zh_CN",
            "zh_CN.UTF-8",
            "zh-Hans",
            "zh-Hans-CN",
            "zh-TW",
            "zh_HK.UTF-8",
            "ZH-SG",
        ] {
            assert_eq!(Lang::from_locale_tag(zh), Lang::ZhCn, "tag {zh}");
        }
        for other in [
            "",
            "C",
            "POSIX",
            "en",
            "en-US",
            "en_GB.UTF-8",
            "ja-JP",
            "zhx",
        ] {
            assert_eq!(Lang::from_locale_tag(other), Lang::En, "tag {other}");
        }
    }

    #[test]
    fn saved_choice_overrides_os_locale() {
        assert_eq!(resolve_lang(Some("en"), Lang::ZhCn), Lang::En);
        assert_eq!(resolve_lang(Some("zh-CN"), Lang::En), Lang::ZhCn);
        assert_eq!(resolve_lang(Some("zh_cn"), Lang::En), Lang::ZhCn);
        assert_eq!(resolve_lang(Some("fr-FR"), Lang::ZhCn), Lang::ZhCn);
        assert_eq!(resolve_lang(None, Lang::ZhCn), Lang::ZhCn);
        assert_eq!(resolve_lang(None, Lang::En), Lang::En);
    }

    #[test]
    fn env_precedence_and_win32_langid() {
        assert_eq!(
            detect_locale_from_env(Some("zh_CN.UTF-8"), Some("en"), Some("en"), Some("en")),
            Some("zh_CN.UTF-8".into())
        );
        assert_eq!(
            detect_locale_from_env(Some(""), Some("zh_TW:en_US"), Some("en"), Some("en")),
            Some("zh_TW".into())
        );
        assert_eq!(
            detect_locale_from_env(None, None, Some("zh_CN"), Some("en_US")),
            Some("zh_CN".into())
        );
        assert_eq!(
            detect_locale_from_env(None, None, None, Some("en_US.UTF-8")),
            Some("en_US.UTF-8".into())
        );
        assert_eq!(detect_locale_from_env(None, None, None, None), None);

        // Win32 LANGID primary language 0x04 = Chinese
        assert_eq!(lang_from_win32_langid(0x0804), Lang::ZhCn); // zh-CN
        assert_eq!(lang_from_win32_langid(0x0404), Lang::ZhCn); // zh-TW
        assert_eq!(lang_from_win32_langid(0x0c04), Lang::ZhCn); // zh-HK
        assert_eq!(lang_from_win32_langid(0x1004), Lang::ZhCn); // zh-SG
        assert_eq!(lang_from_win32_langid(0x0409), Lang::En); // en-US
        assert_eq!(lang_from_win32_langid(0x0411), Lang::En); // ja-JP
    }

    #[test]
    fn every_tray_label_and_fr133_prompt_has_non_empty_en_and_zh_cn() {
        let pairs: Vec<(&str, String, String)> = vec![
            (
                "login_ellipsis",
                login_ellipsis(Lang::En).into(),
                login_ellipsis(Lang::ZhCn).into(),
            ),
            (
                "sign_in_ellipsis",
                sign_in_ellipsis(Lang::En).into(),
                sign_in_ellipsis(Lang::ZhCn).into(),
            ),
            (
                "sign_out_account",
                sign_out_account(Lang::En).into(),
                sign_out_account(Lang::ZhCn).into(),
            ),
            (
                "join_invite",
                join_invite(Lang::En).into(),
                join_invite(Lang::ZhCn).into(),
            ),
            (
                "network_devices",
                network_devices(Lang::En).into(),
                network_devices(Lang::ZhCn).into(),
            ),
            (
                "invitations",
                invitations(Lang::En).into(),
                invitations(Lang::ZhCn).into(),
            ),
            (
                "open_meshharbor",
                open_meshharbor(Lang::En).into(),
                open_meshharbor(Lang::ZhCn).into(),
            ),
            (
                "open_globe",
                open_globe(Lang::En).into(),
                open_globe(Lang::ZhCn).into(),
            ),
            (
                "admin_console",
                admin_console(Lang::En).into(),
                admin_console(Lang::ZhCn).into(),
            ),
            (
                "start_recording",
                start_recording(Lang::En).into(),
                start_recording(Lang::ZhCn).into(),
            ),
            (
                "stop_recording",
                stop_recording(Lang::En, "1:23"),
                stop_recording(Lang::ZhCn, "1:23"),
            ),
            (
                "tooltip_recording",
                tooltip_recording(Lang::En, "1:23"),
                tooltip_recording(Lang::ZhCn, "1:23"),
            ),
            (
                "tooltip_remote_recording",
                tooltip_remote_recording(Lang::En, "Tester", "0:05"),
                tooltip_remote_recording(Lang::ZhCn, "Tester", "0:05"),
            ),
            (
                "keep_busy_off",
                keep_busy_off(Lang::En).into(),
                keep_busy_off(Lang::ZhCn).into(),
            ),
            (
                "keep_busy_unavailable",
                keep_busy_unavailable(Lang::En).into(),
                keep_busy_unavailable(Lang::ZhCn).into(),
            ),
            (
                "start_keep_busy",
                start_keep_busy(Lang::En).into(),
                start_keep_busy(Lang::ZhCn).into(),
            ),
            (
                "keep_busy_pattern_fallback",
                keep_busy_pattern_fallback(Lang::En).into(),
                keep_busy_pattern_fallback(Lang::ZhCn).into(),
            ),
            (
                "stop_keep_busy",
                stop_keep_busy(Lang::En, "Heart", "paused"),
                stop_keep_busy(Lang::ZhCn, "Heart", "paused"),
            ),
            (
                "onboarding",
                onboarding(Lang::En).into(),
                onboarding(Lang::ZhCn).into(),
            ),
            (
                "welcome_tour",
                welcome_tour(Lang::En).into(),
                welcome_tour(Lang::ZhCn).into(),
            ),
            (
                "check_updates",
                check_updates(Lang::En).into(),
                check_updates(Lang::ZhCn).into(),
            ),
            (
                "update_ready",
                update_ready(Lang::En, "agent-v0.4.217"),
                update_ready(Lang::ZhCn, "agent-v0.4.217"),
            ),
            (
                "update_available",
                update_available(Lang::En, "agent-v0.4.217"),
                update_available(Lang::ZhCn, "agent-v0.4.217"),
            ),
            (
                "open_logs",
                open_logs(Lang::En).into(),
                open_logs(Lang::ZhCn).into(),
            ),
            ("quit", quit(Lang::En).into(), quit(Lang::ZhCn).into()),
            (
                "choose_exposed_features",
                choose_exposed_features(Lang::En).into(),
                choose_exposed_features(Lang::ZhCn).into(),
            ),
            (
                "no_devices_yet",
                no_devices_yet(Lang::En).into(),
                no_devices_yet(Lang::ZhCn).into(),
            ),
            (
                "approve_in_browser",
                approve_in_browser(Lang::En, "ABCD-1234"),
                approve_in_browser(Lang::ZhCn, "ABCD-1234"),
            ),
            (
                "working",
                working(Lang::En).into(),
                working(Lang::ZhCn).into(),
            ),
            (
                "failed",
                failed(Lang::En, "timeout"),
                failed(Lang::ZhCn, "timeout"),
            ),
            (
                "not_signed_in",
                not_signed_in(Lang::En).into(),
                not_signed_in(Lang::ZhCn).into(),
            ),
            (
                "an_organization",
                an_organization(Lang::En).into(),
                an_organization(Lang::ZhCn).into(),
            ),
            (
                "temporary_device_left",
                temporary_device_left(Lang::En, "2 h"),
                temporary_device_left(Lang::ZhCn, "2 小时"),
            ),
            (
                "managed_by_left",
                managed_by_left(Lang::En, "Alex", "2 h"),
                managed_by_left(Lang::ZhCn, "Alex", "2 小时"),
            ),
            (
                "invitations_next_ends",
                invitations_next_ends(Lang::En, 2, "1 h"),
                invitations_next_ends(Lang::ZhCn, 2, "1 小时"),
            ),
            (
                "service_not_running",
                service_not_running(Lang::En).into(),
                service_not_running(Lang::ZhCn).into(),
            ),
            (
                "no_address_yet",
                no_address_yet(Lang::En).into(),
                no_address_yet(Lang::ZhCn).into(),
            ),
            (
                "device_status_offline",
                device_status_offline(Lang::En, "device-a", "192.0.2.10"),
                device_status_offline(Lang::ZhCn, "device-a", "192.0.2.10"),
            ),
            (
                "waiting_code_cancel",
                waiting_code_cancel(Lang::En, "ABCD-1234"),
                waiting_code_cancel(Lang::ZhCn, "ABCD-1234"),
            ),
            (
                "waiting_cancel",
                waiting_cancel(Lang::En).into(),
                waiting_cancel(Lang::ZhCn).into(),
            ),
            (
                "signed_in",
                signed_in(Lang::En).into(),
                signed_in(Lang::ZhCn).into(),
            ),
            (
                "signed_in_as",
                signed_in_as(Lang::En, "user@example.test"),
                signed_in_as(Lang::ZhCn, "user@example.test"),
            ),
            (
                "session_unconfirmed",
                session_unconfirmed(Lang::En, "user@example.test"),
                session_unconfirmed(Lang::ZhCn, "user@example.test"),
            ),
            (
                "leave_invite",
                leave_invite(Lang::En, "Alex", "2 h"),
                leave_invite(Lang::ZhCn, "Alex", "2 小时"),
            ),
            // FR-133 "Move this device?" coordination strings
            (
                "move_title",
                move_title(Lang::En).into(),
                move_title(Lang::ZhCn).into(),
            ),
            (
                "move_yes",
                move_yes(Lang::En).into(),
                move_yes(Lang::ZhCn).into(),
            ),
            (
                "move_no",
                move_no(Lang::En).into(),
                move_no(Lang::ZhCn).into(),
            ),
            (
                "move_belongs_to",
                move_belongs_to(Lang::En, "Acme"),
                move_belongs_to(Lang::ZhCn, "Acme"),
            ),
            (
                "move_question",
                move_question(Lang::En, "Acme"),
                move_question(Lang::ZhCn, "Acme"),
            ),
            (
                "move_open_link",
                move_open_link(Lang::En, "ABCD-1234", "https://centre.example.test/login"),
                move_open_link(Lang::ZhCn, "ABCD-1234", "https://centre.example.test/login"),
            ),
            (
                "move_done_title",
                move_done_title(Lang::En).into(),
                move_done_title(Lang::ZhCn).into(),
            ),
            (
                "move_done_body_clean",
                move_done_body(Lang::En, "Acme", None),
                move_done_body(Lang::ZhCn, "Acme", None),
            ),
            (
                "move_done_body_notice",
                move_done_body(Lang::En, "Acme", Some("Admin must remove old row.")),
                move_done_body(Lang::ZhCn, "Acme", Some("Admin must remove old row.")),
            ),
            (
                "move_failed_title",
                move_failed_title(Lang::En).into(),
                move_failed_title(Lang::ZhCn).into(),
            ),
            (
                "move_cancelled",
                move_cancelled(Lang::En).into(),
                move_cancelled(Lang::ZhCn).into(),
            ),
            (
                "move_kept_notice",
                move_kept_notice(Lang::En, "Acme"),
                move_kept_notice(Lang::ZhCn, "Acme"),
            ),
            (
                "move_in_progress",
                move_in_progress(Lang::En).into(),
                move_in_progress(Lang::ZhCn).into(),
            ),
            (
                "move_failed",
                move_failed(Lang::En, "denied"),
                move_failed(Lang::ZhCn, "denied"),
            ),
        ];

        assert_eq!(app_name(Lang::En), "MeshHarbor");
        assert_eq!(app_name(Lang::ZhCn), "MeshHarbor");
        assert_eq!(
            format_remaining(Lang::ZhCn, 50 * 3_600_000, 0),
            "2 天 2 小时"
        );
        assert_eq!(format_remaining(Lang::ZhCn, 3_600_000, 0), "1 小时 0 分钟");
        assert_eq!(format_remaining(Lang::ZhCn, 120_000, 0), "2 分钟");
        assert_eq!(format_remaining(Lang::ZhCn, 10_000, 0), "不足 1 分钟");

        for (key, en, zh) in pairs {
            assert!(!en.trim().is_empty(), "{key}: en is empty");
            assert!(!zh.trim().is_empty(), "{key}: zh-CN is empty");
            assert!(
                has_cjk(&zh),
                "{key}: zh-CN has no Chinese characters: {zh:?}"
            );
            assert_ne!(en, zh, "{key}: en and zh-CN must differ");
        }
        assert!(move_question(Lang::En, "Acme").contains("Acme"));
        assert!(move_question(Lang::ZhCn, "Acme").contains("Acme"));
    }
}
