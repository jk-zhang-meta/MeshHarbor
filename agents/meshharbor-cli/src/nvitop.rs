// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — `mh nvitop` (alias `mh gpu`): fleet GPU monitor, live TUI watch,
//! per-user GPU·h summary, and `free` GPU picker over the daemon's LocalAPI.
//!
//! Pure rendering and selection helpers take all inputs explicitly so they are
//! unit-tested without a live daemon or TTY.

use std::io::{self, IsTerminal as _, Write as _};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use clap::{Args, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use serde::Serialize;
use tunnel_core::localapi::{
    self, DirectoryError, GpuCardView, GpuFleetPage, GpuHostView, GpuUsersPage,
};
use unicode_width::{UnicodeWidthChar as _, UnicodeWidthStr as _};

/// Arguments for `mh nvitop` (alias `mh gpu`).
#[derive(Debug, Args)]
pub struct NvitopArgs {
    #[command(subcommand)]
    pub subcommand: Option<NvitopSubcommand>,

    /// Optional host names or agent IDs to filter by.
    #[arg(value_name = "HOST")]
    pub hosts: Vec<String>,

    /// Read the server's latest cached snapshot without requesting a live 2 s lease.
    #[arg(long)]
    pub cached: bool,

    /// Interactive full-screen watch TUI (keys: q, /, s, p, Enter, ↑/↓, PgUp/PgDn, ?).
    #[arg(short = 'w', long)]
    pub watch: bool,

    /// Refresh interval in seconds for `--watch` (default 2, minimum 1).
    #[arg(long, default_value_t = 2)]
    pub interval: u64,

    /// Enrollment label (`meshharbord org ls`; default: primary).
    #[arg(long)]
    pub org: Option<String>,

    /// Emit machine-readable JSON instead of formatted tables.
    #[arg(long)]
    pub json: bool,

    /// Output language: `en` or `zh` (defaults to system locale).
    #[arg(long)]
    pub lang: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum NvitopSubcommand {
    /// Per-Linux-user GPU·h held/busy usage table across visible GPU servers.
    Users {
        /// Time window: `24h`, `7d`, or `30d`.
        #[arg(long, default_value = "24h")]
        range: String,
        /// Enrollment label (default: primary).
        #[arg(long)]
        org: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Output language: `en` or `zh`.
        #[arg(long)]
        lang: Option<String>,
    },
    /// Pick qualifying free GPUs and print UUIDs + `CUDA_VISIBLE_DEVICES`.
    /// Exits non-zero if fewer than `-n` qualifying GPUs are free.
    Free {
        /// Number of free GPUs required (default 1).
        #[arg(short = 'n', long = "count", default_value_t = 1)]
        count: usize,
        /// Minimum free VRAM per GPU (e.g. `40G`, `24GiB`, `16384M`, `1T`).
        #[arg(long)]
        min_free: Option<String>,
        /// Require all `-n` GPUs to be on the same host.
        #[arg(long)]
        same_host: bool,
        /// Optional host names or agent IDs to restrict selection to.
        #[arg(value_name = "HOST")]
        hosts: Vec<String>,
        /// Enrollment label (default: primary).
        #[arg(long)]
        org: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Output language: `en` or `zh`.
        #[arg(long)]
        lang: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

impl Lang {
    pub fn resolve(flag: Option<&str>) -> Self {
        if let Some(raw) = flag {
            let low = raw.trim().to_ascii_lowercase();
            if low.starts_with("zh") {
                return Self::Zh;
            }
            return Self::En;
        }
        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(val) = std::env::var(var) {
                let low = val.trim().to_ascii_lowercase();
                if !low.is_empty() {
                    if low.starts_with("zh") {
                        return Self::Zh;
                    }
                    return Self::En;
                }
            }
        }
        Self::En
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Host,
    Free,
    Util,
    Mem,
    Temp,
}

impl SortBy {
    fn next(self) -> Self {
        match self {
            Self::Host => Self::Free,
            Self::Free => Self::Util,
            Self::Util => Self::Mem,
            Self::Mem => Self::Temp,
            Self::Temp => Self::Host,
        }
    }

    fn label(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Self::Host, Lang::En) => "host",
            (Self::Free, Lang::En) => "free",
            (Self::Util, Lang::En) => "util",
            (Self::Mem, Lang::En) => "vram",
            (Self::Temp, Lang::En) => "temp",
            (Self::Host, Lang::Zh) => "主机",
            (Self::Free, Lang::Zh) => "空闲",
            (Self::Util, Lang::Zh) => "利用率",
            (Self::Mem, Lang::Zh) => "显存",
            (Self::Temp, Lang::Zh) => "温度",
        }
    }
}

/// Pure rendering options for fleet tables.
#[derive(Debug, Clone)]
pub struct RenderOpts {
    pub color: bool,
    pub lang: Lang,
    pub width: usize,
    pub show_procs: bool,
    pub sort: SortBy,
    pub filter: String,
    pub expanded_host: Option<String>,
}

impl Default for RenderOpts {
    fn default() -> Self {
        Self {
            color: false,
            lang: Lang::En,
            width: 100,
            show_procs: true,
            sort: SortBy::Host,
            filter: String::new(),
            expanded_host: None,
        }
    }
}

/// Selected free GPU for `mh nvitop free`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FreeGpuPick {
    pub host: String,
    pub agent_id: String,
    pub source: String,
    pub idx: u16,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_mb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_mb: Option<u32>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FreeGpuSelection {
    pub count: usize,
    pub same_host: bool,
    pub min_free_mb: u32,
    pub gpus: Vec<FreeGpuPick>,
    pub exports: Vec<HostExport>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostExport {
    pub host: String,
    pub cuda_visible_devices: String,
    pub export_cmd: String,
}

/// Entry point called from `cli::run_from`.
pub async fn run(args: NvitopArgs) -> Result<()> {
    match args.subcommand {
        Some(NvitopSubcommand::Users {
            range,
            org,
            json,
            lang,
        }) => {
            let lang = Lang::resolve(lang.as_deref().or(args.lang.as_deref()));
            let org_ref = org.as_deref().or(args.org.as_deref()).unwrap_or("");
            run_users(org_ref, &range, json || args.json, lang).await
        }
        Some(NvitopSubcommand::Free {
            count,
            min_free,
            same_host,
            hosts,
            org,
            json,
            lang,
        }) => {
            let lang = Lang::resolve(lang.as_deref().or(args.lang.as_deref()));
            let org_ref = org.as_deref().or(args.org.as_deref()).unwrap_or("");
            let host_list = if hosts.is_empty() { args.hosts } else { hosts };
            run_free(
                org_ref,
                count,
                min_free.as_deref(),
                same_host,
                &host_list,
                json || args.json,
                lang,
            )
            .await
        }
        None => {
            let lang = Lang::resolve(args.lang.as_deref());
            let org_ref = args.org.as_deref().unwrap_or("");
            if args.watch && !args.json {
                run_watch(
                    org_ref,
                    !args.cached,
                    args.interval.clamp(1, 60),
                    &args.hosts,
                    lang,
                )
                .await
            } else {
                run_oneshot(org_ref, !args.cached, &args.hosts, args.json, lang).await
            }
        }
    }
}

fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|t| t.eq_ignore_ascii_case("dumb")) {
        return false;
    }
    io::stdout().is_terminal()
}

fn terminal_width() -> usize {
    terminal::size()
        .map(|(w, _)| usize::from(w).max(60))
        .unwrap_or(100)
}

fn map_directory_err(err: DirectoryError) -> anyhow::Error {
    match err {
        DirectoryError::Io(e) => anyhow!(
            "cannot reach local meshharbord ({e}). Is the daemon running? Try `mh status`."
        ),
        DirectoryError::UnsupportedDaemon { message } => anyhow!(
            "the running meshharbord predates `mh nvitop` ({message}) — upgrade the daemon first"
        ),
        DirectoryError::Upstream {
            code,
            message,
            status,
        } => match code.as_str() {
            "unsupported_server" => anyhow!(
                "the server does not expose GPU monitoring endpoints yet (HTTP {})",
                status.unwrap_or(404)
            ),
            _ => anyhow!("server error ({code}): {message}"),
        },
    }
}

async fn run_oneshot(
    org: &str,
    live: bool,
    hosts: &[String],
    json: bool,
    lang: Lang,
) -> Result<()> {
    let mut client = localapi::connect().await.map_err(|e| {
        anyhow!("cannot reach local meshharbord ({e}). Is the daemon running? Try `mh status`.")
    })?;
    let wait_ms = if live { 2000 } else { 0 };
    let page = client
        .gpu_fleet(org, live, wait_ms, hosts)
        .await
        .map_err(map_directory_err)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&page)?);
        return Ok(());
    }

    let opts = RenderOpts {
        color: color_enabled(),
        lang,
        width: terminal_width(),
        show_procs: true,
        sort: SortBy::Host,
        filter: String::new(),
        expanded_host: None,
    };
    let rendered = render_fleet_text(&page, &opts);
    print!("{rendered}");
    Ok(())
}

async fn run_users(org: &str, range: &str, json: bool, lang: Lang) -> Result<()> {
    let mut client = localapi::connect().await.map_err(|e| {
        anyhow!("cannot reach local meshharbord ({e}). Is the daemon running? Try `mh status`.")
    })?;
    let page = client
        .gpu_users(org, range)
        .await
        .map_err(map_directory_err)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&page)?);
        return Ok(());
    }
    let rendered = render_users_table(&page, color_enabled(), lang, terminal_width());
    print!("{rendered}");
    Ok(())
}

async fn run_free(
    org: &str,
    count: usize,
    min_free: Option<&str>,
    same_host: bool,
    hosts: &[String],
    json: bool,
    lang: Lang,
) -> Result<()> {
    if count == 0 {
        bail!("--count (-n) must be at least 1");
    }
    let min_free_mb = match min_free {
        Some(raw) => parse_min_free_mb(raw)?,
        None => 0,
    };
    let mut client = localapi::connect().await.map_err(|e| {
        anyhow!("cannot reach local meshharbord ({e}). Is the daemon running? Try `mh status`.")
    })?;
    let page = client
        .gpu_fleet(org, true, 2000, hosts)
        .await
        .map_err(map_directory_err)?;
    let selection = select_free_gpus(&page, count, min_free_mb, same_host, lang)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&selection)?);
        return Ok(());
    }
    print!("{}", render_free_selection(&selection, color_enabled(), lang));
    Ok(())
}

/// RAII guard restoring raw mode, cursor visibility, and main screen on exit.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut out = io::stdout();
        if let Err(e) = execute!(out, EnterAlternateScreen, cursor::Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(e);
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = execute!(out, cursor::Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

async fn run_watch(
    org: &str,
    live: bool,
    interval_secs: u64,
    hosts: &[String],
    lang: Lang,
) -> Result<()> {
    if !io::stdout().is_terminal() {
        bail!("`mh nvitop --watch` requires an interactive terminal (TTY)");
    }

    let mut client = localapi::connect().await.map_err(|e| {
        anyhow!("cannot reach local meshharbord ({e}). Is the daemon running? Try `mh status`.")
    })?;

    let _guard = TerminalGuard::enter()?;
    let color = color_enabled();
    let interval = Duration::from_secs(interval_secs.max(1));

    let mut page = GpuFleetPage::default();
    let mut last_err: Option<String> = None;
    let mut first_fetch = true;
    let mut next_refresh = Instant::now();

    let mut show_procs = true;
    let mut sort = SortBy::Host;
    let mut filter = String::new();
    let mut filter_editing = false;
    let mut show_help = false;
    let mut selected_host_idx: usize = 0;
    let mut expanded_host: Option<String> = None;
    let mut scroll_offset: usize = 0;

    loop {
        if Instant::now() >= next_refresh {
            let wait_ms = if first_fetch && live { 1500 } else { 0 };
            first_fetch = false;
            match client.gpu_fleet(org, live, wait_ms, hosts).await {
                Ok(p) => {
                    page = p;
                    last_err = None;
                }
                Err(e) => {
                    last_err = Some(map_directory_err(e).to_string());
                    if let Ok(reconn) = localapi::connect().await {
                        client = reconn;
                    }
                }
            }
            next_refresh = Instant::now() + interval;
        }

        let (cols, rows) = terminal::size().unwrap_or((100, 30));
        let width = usize::from(cols).max(60);
        let height = usize::from(rows).max(12);

        let visible_hosts = filtered_sorted_hosts(&page.hosts, &filter, sort);
        if !visible_hosts.is_empty() && selected_host_idx >= visible_hosts.len() {
            selected_host_idx = visible_hosts.len() - 1;
        }

        let opts = RenderOpts {
            color,
            lang,
            width,
            show_procs,
            sort,
            filter: filter.clone(),
            expanded_host: expanded_host.clone(),
        };
        let mut lines: Vec<String> = render_fleet_text(&page, &opts)
            .lines()
            .map(ToString::to_string)
            .collect();

        if show_help {
            lines.push(String::new());
            lines.push(match lang {
                Lang::En => "Keys: q quit | / filter | s sort | p procs | Enter detail | ↑/↓/PgUp/PgDn scroll | ? help".to_string(),
                Lang::Zh => "快捷键: q 退出 | / 过滤 | s 排序 | p 进程 | Enter 详情 | ↑/↓/PgUp/PgDn 滚动 | ? 帮助".to_string(),
            });
        }
        if let Some(err) = &last_err {
            lines.push(format!("! {err}"));
        }

        let body_rows = height.saturating_sub(2);
        let max_scroll = lines.len().saturating_sub(body_rows);
        if scroll_offset > max_scroll {
            scroll_offset = max_scroll;
        }

        let status_bar = format_watch_footer(
            lang,
            sort,
            show_procs,
            &filter,
            filter_editing,
            interval_secs,
            visible_hosts
                .get(selected_host_idx)
                .map(|h| host_label(h))
                .unwrap_or("—"),
            width,
        );

        let mut frame = String::with_capacity(width * height);
        // DEC 2026 synchronized output prevents mid-frame flicker.
        frame.push_str("\x1b[?2026h\x1b[H\x1b[2J");
        for line in lines.iter().skip(scroll_offset).take(body_rows) {
            frame.push_str(line);
            frame.push_str("\r\n");
        }
        frame.push_str(&format!("\x1b[{};1H", height));
        if color {
            frame.push_str("\x1b[7m");
            frame.push_str(&pad_right(&status_bar, width));
            frame.push_str("\x1b[0m");
        } else {
            frame.push_str(&truncate_width(&status_bar, width));
        }
        frame.push_str("\x1b[?2026l");

        let mut out = io::stdout();
        out.write_all(frame.as_bytes())?;
        out.flush()?;

        // Poll input in short slices so refresh stays responsive.
        let poll_budget = next_refresh
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(120));
        if event::poll(poll_budget)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                break;
            }
            if filter_editing {
                match key.code {
                    KeyCode::Enter => filter_editing = false,
                    KeyCode::Esc => {
                        filter.clear();
                        filter_editing = false;
                    }
                    KeyCode::Backspace => {
                        filter.pop();
                    }
                    KeyCode::Char(c) => filter.push(c),
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('/') => filter_editing = true,
                    KeyCode::Char('s') => sort = sort.next(),
                    KeyCode::Char('p') => show_procs = !show_procs,
                    KeyCode::Char('?') => show_help = !show_help,
                    KeyCode::Char('r') => next_refresh = Instant::now(),
                    KeyCode::Enter | KeyCode::Char('d') => {
                        if let Some(h) = visible_hosts.get(selected_host_idx) {
                            if expanded_host.as_deref() == Some(h.agent_id.as_str()) {
                                expanded_host = None;
                            } else {
                                expanded_host = Some(h.agent_id.clone());
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if scroll_offset < max_scroll {
                            scroll_offset += 1;
                        }
                        if selected_host_idx + 1 < visible_hosts.len() {
                            selected_host_idx += 1;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        scroll_offset = scroll_offset.saturating_sub(1);
                        selected_host_idx = selected_host_idx.saturating_sub(1);
                    }
                    KeyCode::PageDown => {
                        scroll_offset = (scroll_offset + body_rows.max(1)).min(max_scroll);
                    }
                    KeyCode::PageUp => {
                        scroll_offset = scroll_offset.saturating_sub(body_rows.max(1));
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn format_watch_footer(
    lang: Lang,
    sort: SortBy,
    show_procs: bool,
    filter: &str,
    filter_editing: bool,
    interval_secs: u64,
    selected: &str,
    width: usize,
) -> String {
    let raw = if filter_editing {
        match lang {
            Lang::En => format!(" Filter: {filter}_   (Enter apply, Esc clear)"),
            Lang::Zh => format!(" 过滤: {filter}_   (Enter 确认, Esc 清除)"),
        }
    } else {
        let f_part = if filter.is_empty() {
            String::new()
        } else {
            format!(" | /{filter}")
        };
        match lang {
            Lang::En => format!(
                " q quit | / filter | s sort:{} | p procs:{} | Enter detail({}) | ? help | {}s{}",
                sort.label(lang),
                if show_procs { "on" } else { "off" },
                selected,
                interval_secs,
                f_part,
            ),
            Lang::Zh => format!(
                " q 退出 | / 过滤 | s 排序:{} | p 进程:{} | Enter 详情({}) | ? 帮助 | {}s{}",
                sort.label(lang),
                if show_procs { "开" } else { "关" },
                selected,
                interval_secs,
                f_part,
            ),
        }
    };
    truncate_width(&raw, width)
}

// ─── Pure selection & parsing ───────────────────────────────────────────────

/// Parse `--min-free` size strings into MiB: e.g. `"40G"`, `"40GiB"`, `"24576M"`,
/// `"24576MiB"`, `"1T"`, or bare MiB integer `"16384"`.
pub fn parse_min_free_mb(raw: &str) -> Result<u32> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let num_str = &s[..split];
    let unit = s[split..].trim().to_ascii_lowercase();
    let val: f64 = num_str
        .parse()
        .map_err(|_| anyhow!("invalid --min-free size {raw:?}; expected e.g. 40G, 24GiB, 16384M"))?;
    if !val.is_finite() || val < 0.0 {
        bail!("--min-free must be a non-negative size (got {raw:?})");
    }
    let mult_mib = match unit.as_str() {
        "" | "m" | "mb" | "mib" => 1.0,
        "g" | "gb" | "gib" => 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0,
        _ => bail!("unknown --min-free unit {unit:?}; use M, G/GiB, or T"),
    };
    let mib = (val * mult_mib).round();
    if mib > f64::from(u32::MAX) {
        bail!("--min-free value {raw:?} overflows MiB range");
    }
    Ok(mib as u32)
}

/// Select `count` qualifying free GPUs matching `min_free_mb` and `same_host`.
pub fn select_free_gpus(
    page: &GpuFleetPage,
    count: usize,
    min_free_mb: u32,
    same_host: bool,
    lang: Lang,
) -> Result<FreeGpuSelection> {
    let mut per_host: Vec<(String, Vec<FreeGpuPick>)> = Vec::new();
    let mut hosts_sorted: Vec<&GpuHostView> = page.hosts.iter().collect();
    hosts_sorted.sort_by(|a, b| host_label(a).cmp(host_label(b)));

    for h in hosts_sorted {
        if !h.is_online || h.freshness == "offline" || h.status != "ok" {
            continue;
        }
        let mut qualifying: Vec<FreeGpuPick> = h
            .gpus
            .iter()
            .filter(|g| g.state == "free" && !g.lost)
            .filter_map(|g| {
                let free_mb = match (g.mem_total_mb, g.mem_used_mb) {
                    (Some(tot), Some(used)) => Some(tot.saturating_sub(used)),
                    _ => None,
                };
                if min_free_mb > 0 && free_mb.unwrap_or(0) < min_free_mb {
                    return None;
                }
                Some(FreeGpuPick {
                    host: host_label(h).to_string(),
                    agent_id: h.agent_id.clone(),
                    source: h.source.clone(),
                    idx: g.idx,
                    uuid: g.uuid.clone(),
                    name: g.name.clone(),
                    free_mb,
                    total_mb: g.mem_total_mb,
                })
            })
            .collect();
        qualifying.sort_by_key(|g| g.idx);
        if !qualifying.is_empty() {
            per_host.push((host_label(h).to_string(), qualifying));
        }
    }

    let picked: Vec<FreeGpuPick> = if same_host {
        // Prefer the host with enough cards and the fewest surplus cards (best-fit),
        // tie-breaking by highest aggregate free VRAM then host name.
        per_host
            .into_iter()
            .filter(|(_, gpus)| gpus.len() >= count)
            .min_by(|(ha, ga), (hb, gb)| {
                ga.len()
                    .cmp(&gb.len())
                    .then_with(|| {
                        let sum_a: u64 = ga.iter().map(|g| u64::from(g.free_mb.unwrap_or(0))).sum();
                        let sum_b: u64 = gb.iter().map(|g| u64::from(g.free_mb.unwrap_or(0))).sum();
                        sum_b.cmp(&sum_a)
                    })
                    .then_with(|| ha.cmp(hb))
            })
            .map(|(_, mut gpus)| {
                gpus.truncate(count);
                gpus
            })
            .unwrap_or_default()
    } else {
        per_host
            .into_iter()
            .flat_map(|(_, gpus)| gpus)
            .take(count)
            .collect()
    };

    if picked.len() < count {
        let msg = match lang {
            Lang::En => format!(
                "requested {count} free GPU(s){} (min free {} MiB), only {} available",
                if same_host { " on the same host" } else { "" },
                min_free_mb,
                picked.len()
            ),
            Lang::Zh => format!(
                "需要 {count} 张空闲 GPU{}（最小空闲 {} MiB），当前仅找到 {} 张",
                if same_host { "（同机）" } else { "" },
                min_free_mb,
                picked.len()
            ),
        };
        bail!("{msg}");
    }

    // Group exports by host while preserving selection order.
    let mut exports: Vec<HostExport> = Vec::new();
    for g in &picked {
        if let Some(ex) = exports.iter_mut().find(|e| e.host == g.host) {
            ex.cuda_visible_devices.push(',');
            ex.cuda_visible_devices.push_str(&g.uuid);
            ex.export_cmd = format!(
                "export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES={}",
                ex.cuda_visible_devices
            );
        } else {
            let devs = g.uuid.clone();
            exports.push(HostExport {
                host: g.host.clone(),
                export_cmd: format!(
                    "export CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES={devs}"
                ),
                cuda_visible_devices: devs,
            });
        }
    }

    Ok(FreeGpuSelection {
        count,
        same_host,
        min_free_mb,
        gpus: picked,
        exports,
    })
}

// ─── Pure rendering ─────────────────────────────────────────────────────────

fn host_label(h: &GpuHostView) -> &str {
    h.display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&h.name)
}

fn filtered_sorted_hosts<'a>(
    hosts: &'a [GpuHostView],
    filter: &str,
    sort: SortBy,
) -> Vec<&'a GpuHostView> {
    let needle = filter.trim().to_ascii_lowercase();
    let mut out: Vec<&GpuHostView> = hosts
        .iter()
        .filter(|h| {
            if needle.is_empty() {
                return true;
            }
            if host_label(h).to_ascii_lowercase().contains(&needle)
                || h.name.to_ascii_lowercase().contains(&needle)
                || h.source.to_ascii_lowercase().contains(&needle)
            {
                return true;
            }
            h.gpus.iter().any(|g| {
                g.name
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains(&needle)
                    || g.state.to_ascii_lowercase().contains(&needle)
                    || g.procs.as_ref().is_some_and(|ps| {
                        ps.iter().any(|p| {
                            p.user
                                .as_deref()
                                .unwrap_or("")
                                .to_ascii_lowercase()
                                .contains(&needle)
                                || p.cmd
                                    .as_deref()
                                    .unwrap_or("")
                                    .to_ascii_lowercase()
                                    .contains(&needle)
                        })
                    })
            })
        })
        .collect();

    out.sort_by(|a, b| match sort {
        SortBy::Host => b
            .is_online
            .cmp(&a.is_online)
            .then_with(|| host_label(a).cmp(host_label(b))),
        SortBy::Free => b
            .free_count
            .cmp(&a.free_count)
            .then_with(|| host_label(a).cmp(host_label(b))),
        SortBy::Util => max_util(b)
            .cmp(&max_util(a))
            .then_with(|| host_label(a).cmp(host_label(b))),
        SortBy::Mem => max_mem_used(b)
            .cmp(&max_mem_used(a))
            .then_with(|| host_label(a).cmp(host_label(b))),
        SortBy::Temp => max_temp(b)
            .cmp(&max_temp(a))
            .then_with(|| host_label(a).cmp(host_label(b))),
    });
    out
}

fn max_util(h: &GpuHostView) -> u8 {
    h.gpus.iter().filter_map(|g| g.util_pct).max().unwrap_or(0)
}

fn max_mem_used(h: &GpuHostView) -> u32 {
    h.gpus
        .iter()
        .filter_map(|g| g.mem_used_mb)
        .max()
        .unwrap_or(0)
}

fn max_temp(h: &GpuHostView) -> i16 {
    h.gpus
        .iter()
        .filter_map(|g| g.temp_c)
        .max()
        .unwrap_or(i16::MIN)
}

fn state_word(state: &str, lang: Lang) -> &'static str {
    match (state, lang) {
        ("free", Lang::En) => "FREE",
        ("busy", Lang::En) => "BUSY",
        ("held_idle", Lang::En) => "IDLE!",
        ("unattributed_busy", Lang::En) => "UNATTR",
        ("fault", Lang::En) => "FAULT",
        (_, Lang::En) => "UNK",
        ("free", Lang::Zh) => "空闲",
        ("busy", Lang::Zh) => "忙碌",
        ("held_idle", Lang::Zh) => "占空!",
        ("unattributed_busy", Lang::Zh) => "未归属",
        ("fault", Lang::Zh) => "故障",
        (_, Lang::Zh) => "未知",
    }
}

fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn paint_state(state: &str, lang: Lang, color: bool) -> String {
    // Color-blind-safe palette: cyan/blue for FREE, orange/yellow for BUSY/IDLE!,
    // bright magenta for FAULT, dim gray for UNK.
    let word = pad_right(state_word(state, lang), 6);
    match state {
        "free" => paint(&word, "1;36", color),
        "busy" => paint(&word, "33", color),
        "held_idle" | "unattributed_busy" => paint(&word, "1;33", color),
        "fault" => paint(&word, "1;35", color),
        _ => paint(&word, "90", color),
    }
}

fn source_badge(h: &GpuHostView, lang: Lang) -> &'static str {
    match (h.source.as_str(), h.read_only, lang) {
        ("invited", _, Lang::En) => " [invited]",
        ("invited", _, Lang::Zh) => " [邀请]",
        ("shared", true, Lang::En) => " [shared RO]",
        ("shared", true, Lang::Zh) => " [共享只读]",
        ("shared", false, Lang::En) => " [shared]",
        ("shared", false, Lang::Zh) => " [共享]",
        _ => "",
    }
}

fn format_vram(g: &GpuCardView) -> String {
    match (g.mem_used_mb, g.mem_total_mb) {
        (Some(u), Some(t)) => {
            if t >= 2048 {
                format!("{:.1}/{:.1}G", f64::from(u) / 1024.0, f64::from(t) / 1024.0)
            } else {
                format!("{u}/{t}M")
            }
        }
        (Some(u), None) => format!("{:.1}G{}", f64::from(u) / 1024.0, if g.unified { " uni" } else { "" }),
        _ => "—".to_string(),
    }
}

fn format_age(age_s: Option<u64>) -> String {
    let Some(s) = age_s else {
        return "—".to_string();
    };
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d{}h", s / 86_400, (s % 86_400) / 3600)
    }
}

/// Pure fleet table renderer (safe for piping, `NO_COLOR`, and CJK widths).
pub fn render_fleet_text(page: &GpuFleetPage, opts: &RenderOpts) -> String {
    let mut out = String::new();
    let s = &page.summary;
    let header = match opts.lang {
        Lang::En => format!(
            "GPU Servers: {}/{} online | GPUs: {} free / {} total (busy {}, idle! {}, fault {})",
            s.hosts_online,
            s.hosts_total,
            s.gpus_free,
            s.gpus_total,
            s.gpus_busy,
            s.gpus_held_idle,
            s.gpus_fault
        ),
        Lang::Zh => format!(
            "GPU 服务器: {}/{} 在线 | GPU: {} 空闲 / {} 总计 (忙碌 {}, 占空! {}, 故障 {})",
            s.hosts_online,
            s.hosts_total,
            s.gpus_free,
            s.gpus_total,
            s.gpus_busy,
            s.gpus_held_idle,
            s.gpus_fault
        ),
    };
    out.push_str(&paint(&truncate_width(&header, opts.width), "1", opts.color));
    out.push('\n');

    let hosts = filtered_sorted_hosts(&page.hosts, &opts.filter, opts.sort);
    if hosts.is_empty() {
        out.push_str(match opts.lang {
            Lang::En => "(no marked GPU servers match)\n",
            Lang::Zh => "（没有匹配的 GPU 服务器）\n",
        });
        return out;
    }

    for h in hosts {
        out.push('\n');
        let fresh_tag = match (h.freshness.as_str(), opts.lang) {
            ("live", _) => "",
            ("stale", Lang::En) => " [STALE]",
            ("stale", Lang::Zh) => " [陈旧]",
            ("offline", Lang::En) => " [OFFLINE]",
            ("offline", Lang::Zh) => " [离线]",
            _ => "",
        };
        let status_tag = if h.status != "ok" && !h.status.is_empty() {
            format!(" [{}]", h.status)
        } else {
            String::new()
        };
        let drv = h
            .driver_version
            .as_deref()
            .map(|d| format!(" drv {d}"))
            .unwrap_or_default();
        let host_line = format!(
            "{}{}{}{} ({}/{} free{})",
            host_label(h),
            source_badge(h, opts.lang),
            fresh_tag,
            status_tag,
            h.free_count,
            h.total_count,
            drv
        );
        let style = if !h.is_online || h.freshness == "offline" {
            "90"
        } else {
            "1;34"
        };
        out.push_str(&paint(&truncate_width(&host_line, opts.width), style, opts.color));
        out.push('\n');

        if let Some(load) = &h.host {
            let cpu = load
                .cpu_pct
                .map(|c| format!("CPU {c}%"))
                .unwrap_or_else(|| "CPU —".into());
            let load1 = load
                .load_1m
                .map(|l| format!(" load {l:.2}"))
                .unwrap_or_default();
            let ram = match (load.mem_used_mb, load.mem_total_mb) {
                (Some(u), Some(t)) => {
                    format!(" RAM {:.1}/{:.1}G", f64::from(u) / 1024.0, f64::from(t) / 1024.0)
                }
                _ => String::new(),
            };
            let disk = load
                .root_used_pct
                .map(|d| format!(" disk {d}%"))
                .unwrap_or_default();
            let summary = format!("  {cpu}{load1}{ram}{disk}");
            out.push_str(&paint(&truncate_width(&summary, opts.width), "90", opts.color));
            out.push('\n');
        }

        if h.gpus.is_empty() {
            out.push_str(match opts.lang {
                Lang::En => "  (no GPU telemetry reported yet)\n",
                Lang::Zh => "  （暂无 GPU 遥测数据）\n",
            });
            continue;
        }

        let name_col = opts.width.saturating_sub(54).clamp(12, 26);
        let expanded = opts.expanded_host.as_deref() == Some(h.agent_id.as_str());
        for g in &h.gpus {
            let gname = truncate_width(g.name.as_deref().unwrap_or("GPU"), name_col);
            let util = g
                .util_pct
                .map(|u| format!("{u:>3}%"))
                .unwrap_or_else(|| "  — ".into());
            let vram = format_vram(g);
            let temp = g
                .temp_c
                .map(|t| format!("{t:>3}C"))
                .unwrap_or_else(|| "  — ".into());
            let power = match (g.power_w, g.power_limit_w) {
                (Some(w), Some(l)) => format!("{w:>3}/{l}W"),
                (Some(w), None) => format!("{w:>3}W"),
                _ => "—".into(),
            };
            let state_cell = paint_state(&g.state, opts.lang, opts.color);
            let row = format!(
                "  #{:<2} {}  {}  {}  {:>11}  {}  {:>8}",
                g.idx,
                pad_right(&gname, name_col),
                state_cell,
                util,
                vram,
                temp,
                power,
            );
            out.push_str(&row);
            out.push('\n');

            if expanded {
                let mut extras = Vec::new();
                extras.push(format!("uuid={}", g.uuid));
                if let Some(bus) = &g.pci_bus {
                    extras.push(format!("pci={bus}"));
                }
                if let Some(fan) = g.fan_pct {
                    extras.push(format!("fan={fan}%"));
                }
                if let Some(clk) = g.sm_clock_mhz {
                    extras.push(format!("sm={clk}MHz"));
                }
                if let Some(ecc) = g.ecc_uncorrected
                    && ecc > 0
                {
                    extras.push(format!("ecc_uncorr={ecc}"));
                }
                if let Some(xids) = &g.xid_errors
                    && !xids.is_empty()
                {
                    extras.push(format!("xid={xids:?}"));
                }
                if let Some(th) = &g.throttle
                    && !th.is_empty()
                {
                    extras.push(format!("throttle={}", th.join(",")));
                }
                let detail = format!("      {}", extras.join("  "));
                out.push_str(&paint(&truncate_width(&detail, opts.width), "90", opts.color));
                out.push('\n');
            }

            if opts.show_procs {
                if let Some(procs) = &g.procs {
                    for p in procs {
                        let user = p.user.as_deref().unwrap_or("—");
                        let mem = p
                            .mem_mb
                            .map(|m| format!("{m}M"))
                            .unwrap_or_else(|| "—".into());
                        let cmd = p.cmd.as_deref().unwrap_or("—");
                        let age = format_age(p.age_s);
                        let pline = format!(
                            "      pid {:<7} {:<12} {:>7} {:>6}  {}",
                            p.pid,
                            truncate_width(user, 12),
                            mem,
                            age,
                            cmd
                        );
                        out.push_str(&truncate_width(&pline, opts.width));
                        out.push('\n');
                    }
                } else if g.procs_state == "off_local" {
                    let note = match opts.lang {
                        Lang::En => "      (process list disabled locally on this host)",
                        Lang::Zh => "      （该主机本地已关闭进程明细上报）",
                    };
                    out.push_str(&paint(note, "90", opts.color));
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// Pure renderer for `mh nvitop users`.
pub fn render_users_table(page: &GpuUsersPage, color: bool, lang: Lang, width: usize) -> String {
    let mut out = String::new();
    let title = match lang {
        Lang::En => format!("GPU Usage by User (range: {})", page.range),
        Lang::Zh => format!("按用户统计 GPU 使用量（周期: {}）", page.range),
    };
    out.push_str(&paint(&title, "1", color));
    out.push('\n');

    if page.users.is_empty() {
        out.push_str(match lang {
            Lang::En => "(no attributed GPU usage in this window)\n",
            Lang::Zh => "（该时间段内暂无已归属的 GPU 使用记录）\n",
        });
        return out;
    }

    let hdr = match lang {
        Lang::En => format!(
            "{}  {:>9}  {:>9}  {:>9}  {:>9}  {}",
            pad_right("USER", 14),
            "HELD(h)",
            "BUSY(h)",
            "LIVE GPUs",
            "LIVE VRAM",
            "HOSTS"
        ),
        Lang::Zh => format!(
            "{}  {:>9}  {:>9}  {:>9}  {:>9}  {}",
            pad_right("用户", 14),
            "占用(卡·时)",
            "计算(卡·时)",
            "当前卡数",
            "当前显存",
            "主机"
        ),
    };
    out.push_str(&paint(&truncate_width(&hdr, width), "1", color));
    out.push('\n');

    for u in &page.users {
        let vram = if u.live_mem_mb >= 1024 {
            format!("{:.1}G", u.live_mem_mb as f64 / 1024.0)
        } else {
            format!("{}M", u.live_mem_mb)
        };
        let hosts_str = u.hosts.join(",");
        let line = format!(
            "{}  {:>9.2}  {:>9.2}  {:>9}  {:>9}  {}",
            pad_right(&truncate_width(&u.user, 14), 14),
            u.held_gpu_hours,
            u.busy_gpu_hours,
            u.live_gpus,
            vram,
            hosts_str
        );
        out.push_str(&truncate_width(&line, width));
        out.push('\n');
    }
    out
}

/// Pure renderer for `mh nvitop free`.
pub fn render_free_selection(sel: &FreeGpuSelection, color: bool, lang: Lang) -> String {
    let mut out = String::new();
    let hdr = match lang {
        Lang::En => format!("Selected {} free GPU(s):", sel.gpus.len()),
        Lang::Zh => format!("已选出 {} 张空闲 GPU：", sel.gpus.len()),
    };
    out.push_str(&paint(&hdr, "1;36", color));
    out.push('\n');

    for g in &sel.gpus {
        let free_str = match (g.free_mb, g.total_mb) {
            (Some(f), Some(t)) => {
                format!("{:.1}/{:.1}G free", f64::from(f) / 1024.0, f64::from(t) / 1024.0)
            }
            _ => "—".into(),
        };
        out.push_str(&format!(
            "  {}  #{}  {}  {}  {}\n",
            g.host,
            g.idx,
            g.name.as_deref().unwrap_or("GPU"),
            free_str,
            g.uuid
        ));
    }
    out.push('\n');
    for ex in &sel.exports {
        out.push_str(&format!("# {}\n{}\n", ex.host, ex.export_cmd));
    }
    out
}

/// Truncate `s` to at most `max_w` terminal display cells using `unicode-width`,
/// appending `…` when truncated.
pub fn truncate_width(s: &str, max_w: usize) -> String {
    if max_w == 0 {
        return String::new();
    }
    if s.width() <= max_w {
        return s.to_string();
    }
    if max_w == 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for ch in s.chars() {
        let cw = ch.width().unwrap_or(0);
        if w + cw + 1 > max_w {
            break;
        }
        out.push(ch);
        w += cw;
    }
    out.push('…');
    out
}

/// Right-pad `s` with spaces to `target_w` display cells (`unicode-width` aware).
pub fn pad_right(s: &str, target_w: usize) -> String {
    let w = s.width();
    if w >= target_w {
        s.to_string()
    } else {
        let mut out = String::with_capacity(s.len() + (target_w - w));
        out.push_str(s);
        for _ in 0..(target_w - w) {
            out.push(' ');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_core::localapi::{GpuFleetSummary, GpuHostLoadView, GpuProcView, GpuUserRow};

    fn sample_page() -> GpuFleetPage {
        GpuFleetPage {
            hosts: vec![
                GpuHostView {
                    agent_id: "aid1".into(),
                    name: "gpu-node-a".into(),
                    display_name: Some("lab-a100".into()),
                    os: "linux".into(),
                    source: "org".into(),
                    read_only: false,
                    is_online: true,
                    freshness: "live".into(),
                    status: "ok".into(),
                    backend: Some("nvml".into()),
                    driver_version: Some("550.90".into()),
                    received_at_ms: Some(1_760_000_000_000),
                    interval_ms: 2000,
                    free_count: 1,
                    busy_count: 1,
                    held_idle_count: 0,
                    total_count: 2,
                    host: Some(GpuHostLoadView {
                        cpu_pct: Some(22),
                        load_1m: Some(1.5),
                        mem_used_mb: Some(65_536),
                        mem_total_mb: Some(262_144),
                        swap_used_mb: None,
                        swap_total_mb: None,
                        root_used_pct: Some(42),
                        net_rx_mbps: None,
                        net_tx_mbps: None,
                    }),
                    gpus: vec![
                        GpuCardView {
                            uuid: "GPU-AAAA-0000".into(),
                            idx: 0,
                            name: Some("NVIDIA A100-SXM4-80GB".into()),
                            state: "free".into(),
                            mem_used_mb: Some(512),
                            mem_total_mb: Some(81_920),
                            util_pct: Some(0),
                            temp_c: Some(32),
                            power_w: Some(45),
                            power_limit_w: Some(400),
                            fan_pct: Some(30),
                            sm_clock_mhz: Some(210),
                            throttle: None,
                            ecc_uncorrected: Some(0),
                            remapped_rows: Some(0),
                            xid_errors: None,
                            mig: false,
                            lost: false,
                            unified: false,
                            pci_bus: Some("0000:01:00.0".into()),
                            idle_since: None,
                            procs_state: "ok".into(),
                            procs: Some(vec![]),
                        },
                        GpuCardView {
                            uuid: "GPU-AAAA-0001".into(),
                            idx: 1,
                            name: Some("NVIDIA A100-SXM4-80GB".into()),
                            state: "busy".into(),
                            mem_used_mb: Some(61_440),
                            mem_total_mb: Some(81_920),
                            util_pct: Some(96),
                            temp_c: Some(68),
                            power_w: Some(340),
                            power_limit_w: Some(400),
                            fan_pct: Some(65),
                            sm_clock_mhz: Some(1410),
                            throttle: None,
                            ecc_uncorrected: Some(0),
                            remapped_rows: Some(0),
                            xid_errors: None,
                            mig: false,
                            lost: false,
                            unified: false,
                            pci_bus: Some("0000:02:00.0".into()),
                            idle_since: None,
                            procs_state: "ok".into(),
                            procs: Some(vec![GpuProcView {
                                pid: 4242,
                                user: Some("alice".into()),
                                uid: Some(1000),
                                mem_mb: Some(61_440),
                                cmd: Some("python train.py".into()),
                                age_s: Some(3900),
                                kind: Some("c".into()),
                            }]),
                        },
                    ],
                },
                GpuHostView {
                    agent_id: "aid2".into(),
                    name: "shared-node-b".into(),
                    display_name: None,
                    os: "linux".into(),
                    source: "shared".into(),
                    read_only: true,
                    is_online: true,
                    freshness: "live".into(),
                    status: "ok".into(),
                    backend: Some("nvml".into()),
                    driver_version: Some("550.90".into()),
                    received_at_ms: Some(1_760_000_000_000),
                    interval_ms: 2000,
                    free_count: 2,
                    busy_count: 0,
                    held_idle_count: 0,
                    total_count: 2,
                    host: None,
                    gpus: vec![
                        GpuCardView {
                            uuid: "GPU-BBBB-0000".into(),
                            idx: 0,
                            name: Some("RTX 4090".into()),
                            state: "free".into(),
                            mem_used_mb: Some(100),
                            mem_total_mb: Some(24_576),
                            util_pct: Some(0),
                            temp_c: Some(35),
                            power_w: Some(25),
                            power_limit_w: Some(450),
                            fan_pct: None,
                            sm_clock_mhz: None,
                            throttle: None,
                            ecc_uncorrected: None,
                            remapped_rows: None,
                            xid_errors: None,
                            mig: false,
                            lost: false,
                            unified: false,
                            pci_bus: None,
                            idle_since: None,
                            procs_state: "ok".into(),
                            procs: Some(vec![]),
                        },
                        GpuCardView {
                            uuid: "GPU-BBBB-0001".into(),
                            idx: 1,
                            name: Some("RTX 4090".into()),
                            state: "free".into(),
                            mem_used_mb: Some(100),
                            mem_total_mb: Some(24_576),
                            util_pct: Some(0),
                            temp_c: Some(34),
                            power_w: Some(25),
                            power_limit_w: Some(450),
                            fan_pct: None,
                            sm_clock_mhz: None,
                            throttle: None,
                            ecc_uncorrected: None,
                            remapped_rows: None,
                            xid_errors: None,
                            mig: false,
                            lost: false,
                            unified: false,
                            pci_bus: None,
                            idle_since: None,
                            procs_state: "ok".into(),
                            procs: Some(vec![]),
                        },
                    ],
                },
            ],
            summary: GpuFleetSummary {
                hosts_total: 2,
                hosts_online: 2,
                gpus_total: 4,
                gpus_free: 3,
                gpus_busy: 1,
                gpus_held_idle: 0,
                gpus_fault: 0,
            },
            server_time_ms: 1_760_000_000_500,
            org: "primary".into(),
        }
    }

    #[test]
    fn fr139_parse_min_free_mb_units() {
        assert_eq!(parse_min_free_mb("40G").unwrap(), 40_960);
        assert_eq!(parse_min_free_mb("40GiB").unwrap(), 40_960);
        assert_eq!(parse_min_free_mb("8192M").unwrap(), 8_192);
        assert_eq!(parse_min_free_mb("16384").unwrap(), 16_384);
        assert_eq!(parse_min_free_mb("1T").unwrap(), 1_048_576);
        assert!(parse_min_free_mb("bad").is_err());
        assert!(parse_min_free_mb("10X").is_err());
    }

    #[test]
    fn fr139_select_free_gpus_same_host_and_min_free() {
        let page = sample_page();

        // Request 1 GPU with >= 40G free -> must pick lab-a100 #0 (80G), not RTX 4090 (24G).
        let sel1 = select_free_gpus(&page, 1, 40 * 1024, false, Lang::En).unwrap();
        assert_eq!(sel1.gpus.len(), 1);
        assert_eq!(sel1.gpus[0].uuid, "GPU-AAAA-0000");
        assert!(
            sel1.exports[0]
                .export_cmd
                .contains("CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=GPU-AAAA-0000")
        );

        // Request 2 GPUs on same host (no min-free) -> must pick shared-node-b's 2 free 4090s.
        let sel2 = select_free_gpus(&page, 2, 0, true, Lang::En).unwrap();
        assert_eq!(sel2.gpus.len(), 2);
        assert!(sel2.gpus.iter().all(|g| g.host == "shared-node-b"));
        assert_eq!(
            sel2.exports[0].cuda_visible_devices,
            "GPU-BBBB-0000,GPU-BBBB-0001"
        );

        // Request 2 GPUs with >= 40G free -> only 1 qualifies -> must error (non-zero exit).
        assert!(select_free_gpus(&page, 2, 40 * 1024, false, Lang::En).is_err());
    }

    #[test]
    fn fr139_render_fleet_no_color_explicit_words() {
        let page = sample_page();
        let text = render_fleet_text(&page, &RenderOpts::default());
        assert!(!text.contains("\x1b["), "NO_COLOR output must contain zero ANSI escapes");
        assert!(text.contains("FREE"));
        assert!(text.contains("BUSY"));
        assert!(text.contains("[shared RO]"));
        assert!(text.contains("alice"));
        assert!(text.contains("python train.py"));
        assert!(!text.contains('○') && !text.contains('●'));
    }

    #[test]
    fn fr139_render_fleet_zh_locale_and_unicode_width() {
        let page = sample_page();
        let opts = RenderOpts {
            color: false,
            lang: Lang::Zh,
            width: 80,
            ..Default::default()
        };
        let text = render_fleet_text(&page, &opts);
        assert!(text.contains("空闲"));
        assert!(text.contains("忙碌"));
        assert!(text.contains("[共享只读]"));

        // CJK wide chars take 2 cells each; truncating to 5 cells gives 2 chars + '…' (width 5).
        let trunc = truncate_width("中文GPU测试", 5);
        assert!(trunc.width() <= 5);
        assert!(trunc.ends_with('…'));
    }

    #[test]
    fn fr139_render_users_table_plain() {
        let page = GpuUsersPage {
            range: "7d".into(),
            users: vec![GpuUserRow {
                user: "alice".into(),
                held_gpu_hours: 12.5,
                busy_gpu_hours: 10.25,
                live_gpus: 2,
                live_mem_mb: 49_152,
                hosts: vec!["lab-a100".into()],
            }],
            org: "primary".into(),
        };
        let text = render_users_table(&page, false, Lang::En, 100);
        assert!(text.contains("alice"));
        assert!(text.contains("12.50"));
        assert!(text.contains("48.0G"));
        assert!(text.contains("lab-a100"));
    }
}
