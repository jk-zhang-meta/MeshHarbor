// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor #20 slice 4a: the owned nftables backend for managed forwards
//! (v039 §6), with a commit-confirm watchdog.
//!
//! MeshHarbor owns exactly one table, `inet meshharbor_fwd`:
//! - its `prerouting` chain DNATs each forward's `bind:port` for the admitted
//!   source CIDRs only;
//! - its `postrouting` chain masquerades a masquerading forward's flows, and
//!   only those. The match is on the connection's original destination
//!   (`ct original`), so no other traffic to the same destination is
//!   rewritten and no conntrack mark is taken from anyone else.
//!
//! Only packets arriving from other hosts are forwarded; the node's own
//! outbound traffic, its control connection included, meets no MeshHarbor
//! hook. A preserve-source forward needs the destination's replies to come
//! back through this node; the planner checks that before anything is sent
//! here.
//!
//! Every change is one `nft -f` transaction that replaces the whole owned
//! table (`add table` + `delete table` + the new table), after an `nft -c`
//! preflight of the same text. Nothing else is touched: no
//! `flush ruleset`, no foreign table, chain or set, no sysctl.
//!
//! **Commit-confirm.** Before a change, the last confirmed table (or its
//! absence) is saved as a restore script, and a rollback is armed that runs
//! it [`CONFIRM_WINDOW`] later unless the server confirms that it still
//! hears this node:
//! - a transient systemd timer where systemd runs, independent of this
//!   process, so it also fires if roomlerd hangs or dies;
//! - always, an in-process deadline ([`NftBackend::expire`]).
//!
//! A change made while another is still unconfirmed keeps the older,
//! confirmed baseline as its rollback target.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use roomler_ai_remote_control::net_inventory::L4;
use tracing::{info, warn};

use crate::managed_forward::{State, Status};

pub const TABLE: &str = "meshharbor_fwd";
/// How long a change waits for the server's confirmation before the
/// watchdog restores the last confirmed table.
pub const CONFIRM_WINDOW: Duration = Duration::from_secs(30);
/// Every rollback timer's unit name starts with this.
pub const UNIT_PREFIX: &str = "roomlerd-mf-rollback-";
const CMD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatForward {
    pub id: String,
    pub revision: u64,
    pub bind: SocketAddr,
    pub proto: L4,
    pub sources: Vec<(IpAddr, u8)>,
    pub dest: SocketAddr,
    /// `false` keeps the client's source address (preserve-source).
    pub masquerade: bool,
}

/// This process can run the backend: root, and an `nft` binary.
pub fn available() -> bool {
    // SAFETY: `geteuid` reads the caller's own credentials; it cannot fail.
    let root = unsafe { libc::geteuid() == 0 };
    root && std::path::Path::new(&Nft::system().argv[0]).is_absolute()
}

/// The comment tagging each rule with its forward and revision.
fn tag(f: &NatForward) -> String {
    format!("mf:{}:{}", f.id, f.revision)
}

/// A forward id goes into the ruleset text, so it must be a plain token.
fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn l4(p: L4) -> &'static str {
    match p {
        L4::Tcp => "tcp",
        L4::Udp => "udp",
    }
}

/// The prerouting and postrouting rules of one forward.
fn rules(f: &NatForward) -> Result<(String, Option<String>), String> {
    if !id_ok(&f.id) {
        return Err("forward id is not a plain token".into());
    }
    if f.bind.is_ipv4() != f.dest.is_ipv4() {
        return Err("ingress and destination are different address families".into());
    }
    let (fam, ver) = if f.bind.is_ipv4() {
        ("ip", 4)
    } else {
        ("ip6", 6)
    };
    let sources: Vec<String> = f
        .sources
        .iter()
        .filter(|(ip, _)| ip.is_ipv4() == (ver == 4))
        .map(|(ip, len)| format!("{ip}/{len}"))
        .collect();
    if sources.is_empty() {
        return Err(format!("no source CIDR in the ingress's family (IPv{ver})"));
    }
    let to = match f.dest {
        SocketAddr::V4(d) => d.to_string(),
        SocketAddr::V6(d) => format!("[{}]:{}", d.ip(), d.port()),
    };
    let (p, t) = (l4(f.proto), tag(f));
    let pre = format!(
        "{fam} daddr {} {p} dport {} {fam} saddr {{ {} }} dnat {fam} to {to} comment \"{t}\"",
        f.bind.ip(),
        f.bind.port(),
        sources.join(", "),
    );
    let post = f.masquerade.then(|| {
        format!(
            "meta l4proto {p} {fam} daddr {} {p} dport {} ct original {fam} daddr {} ct original proto-dst {} masquerade comment \"{t}\"",
            f.dest.ip(),
            f.dest.port(),
            f.bind.ip(),
            f.bind.port(),
        )
    });
    Ok((pre, post))
}

/// The owned table's full text for `set`, and each forward that cannot be
/// expressed with its reason (it is left out, never approximated).
pub fn render(set: &[NatForward]) -> (String, Vec<(usize, String)>) {
    let (mut pre, mut post, mut bad) = (Vec::new(), Vec::new(), Vec::new());
    for (i, f) in set.iter().enumerate() {
        match rules(f) {
            Ok((a, b)) => {
                pre.push(a);
                post.extend(b);
            }
            Err(e) => bad.push((i, e)),
        }
    }
    let mut t = format!("table inet {TABLE} {{\n");
    t += "\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n";
    for r in &pre {
        t += &format!("\t\t{r}\n");
    }
    t += "\t}\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n";
    for r in &post {
        t += &format!("\t\t{r}\n");
    }
    t += "\t}\n}\n";
    (t, bad)
}

/// The script that makes the owned table exactly `table` (`None`: absent),
/// as one transaction. `add` first, so `delete` never fails on a fresh host.
pub fn replace_script(table: Option<&str>) -> String {
    let mut s = format!("add table inet {TABLE}\ndelete table inet {TABLE}\n");
    if let Some(t) = table {
        s += t;
    }
    s
}

/// How `nft` is invoked: `argv[0]` and any leading arguments (a test runs it
/// inside a network namespace through `ip netns exec`).
#[derive(Clone, Debug)]
pub struct Nft {
    pub argv: Vec<String>,
}

impl Nft {
    pub fn system() -> Self {
        let path = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
            .into_iter()
            .find(|p| std::path::Path::new(p).is_file())
            .unwrap_or("nft");
        Self {
            argv: vec![path.into()],
        }
    }

    async fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        use tokio::io::AsyncWriteExt;
        let mut cmd = tokio::process::Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..])
            .args(args)
            .env("LC_ALL", "C")
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("nft: {e}"))?;
        if let (Some(text), Some(mut w)) = (stdin, child.stdin.take()) {
            w.write_all(text.as_bytes())
                .await
                .map_err(|e| format!("nft stdin: {e}"))?;
        }
        let out = tokio::time::timeout(CMD_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| "nft: timed out".to_string())?
            .map_err(|e| format!("nft: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            let mut first = err
                .lines()
                .find(|l| l.starts_with("Error") || l.contains("Error:"))
                .or_else(|| err.lines().next())
                .unwrap_or("nft failed")
                .trim()
                .to_string();
            roomler_ai_remote_control::net_inventory::truncate_str(&mut first, 200);
            Err(first)
        }
    }

    /// The owned table as `nft` prints it, or `None` when it is absent.
    pub async fn current(&self) -> Result<Option<String>, String> {
        let tables = self.run(&["list", "tables", "inet"], None).await?;
        if !tables
            .lines()
            .any(|l| l.trim() == format!("table inet {TABLE}"))
        {
            return Ok(None);
        }
        self.run(&["list", "table", "inet", TABLE], None)
            .await
            .map(Some)
    }

    /// Preflight `script`, then commit it.
    pub async fn apply(&self, script: &str) -> Result<(), String> {
        self.run(&["-c", "-f", "-"], Some(script)).await?;
        self.run(&["-f", "-"], Some(script)).await.map(|_| ())
    }

    /// The `(id, revision)` tags of the owned table's prerouting rules.
    pub async fn installed(&self) -> Result<Vec<(String, u64)>, String> {
        let Some(text) = self.current().await? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut in_pre = false;
        for l in text.lines().map(str::trim) {
            if l.starts_with("chain ") {
                in_pre = l == "chain prerouting {";
            } else if in_pre
                && let Some(c) = l.split("comment \"mf:").nth(1)
                && let Some((id, rev)) = c.trim_end_matches('"').rsplit_once(':')
                && let Ok(rev) = rev.parse()
            {
                out.push((id.to_string(), rev));
            }
        }
        Ok(out)
    }
}

/// The independent rollback timer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Watchdog {
    /// A transient systemd timer (`systemd-run --on-active`).
    Systemd,
    /// Only the in-process deadline (no systemd, or a test).
    InProcess,
}

impl Watchdog {
    pub fn detect() -> Self {
        if std::path::Path::new("/run/systemd/system").is_dir() {
            Watchdog::Systemd
        } else {
            Watchdog::InProcess
        }
    }
}

struct Pending {
    generation: u64,
    deadline: Instant,
    unit: Option<String>,
}

pub struct NftBackend {
    nft: Nft,
    watchdog: Watchdog,
    window: Duration,
    /// Holds the rollback script.
    dir: PathBuf,
    generation: u64,
    pending: Option<Pending>,
    /// What this process last committed: the rendered set, and the table as
    /// `nft` listed it right after. Both must still match for a set to be
    /// unchanged, so a hand edit of the owned table is overwritten.
    last: Option<(String, Option<String>)>,
}

impl NftBackend {
    pub fn new(nft: Nft, watchdog: Watchdog, window: Duration, dir: PathBuf) -> Self {
        Self {
            nft,
            watchdog,
            window,
            dir,
            generation: 0,
            pending: None,
            last: None,
        }
    }

    pub fn system() -> Self {
        Self::new(
            Nft::system(),
            Watchdog::detect(),
            CONFIRM_WINDOW,
            PathBuf::from("/run/roomlerd"),
        )
    }

    fn rollback_file(&self) -> PathBuf {
        self.dir.join("managed-forward-rollback.nft")
    }

    /// The generation waiting for confirmation, if any.
    pub fn pending(&self) -> Option<u64> {
        self.pending.as_ref().map(|p| p.generation)
    }

    async fn arm(&mut self) -> Result<Option<String>, String> {
        if self.watchdog != Watchdog::Systemd {
            return Ok(None);
        }
        let unit = format!("{UNIT_PREFIX}{}-{}", std::process::id(), self.generation);
        let file = self.rollback_file();
        let secs = format!("--on-active={}", self.window.as_secs().max(1));
        let mut args: Vec<String> = vec![
            format!("--unit={unit}"),
            secs,
            "--timer-property=AccuracySec=1s".into(),
            "--collect".into(),
            "--quiet".into(),
        ];
        args.extend(self.nft.argv.iter().cloned());
        args.push("-f".into());
        args.push(file.display().to_string());
        let out = tokio::process::Command::new("systemd-run")
            .args(&args)
            .stdin(std::process::Stdio::null())
            .output()
            .await
            .map_err(|e| format!("systemd-run: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "systemd-run: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(Some(unit))
    }

    async fn disarm(unit: &str) {
        let _ = tokio::process::Command::new("systemctl")
            .args(["stop", &format!("{unit}.timer")])
            .stdin(std::process::Stdio::null())
            .output()
            .await;
    }

    /// Make the owned table carry exactly `set`, under commit-confirm.
    /// Returns each forward's state and the generation to confirm (`None`
    /// when nothing changed or the change was refused).
    pub async fn apply(&mut self, set: &[NatForward]) -> (Vec<Status>, Option<u64>) {
        let (table, bad) = render(set);
        let fail_all = |why: String| -> Vec<Status> {
            set.iter()
                .map(|f| Status {
                    id: f.id.clone(),
                    revision: f.revision,
                    state: State::Failed(why.clone()),
                })
                .collect()
        };
        let before = match self.nft.current().await {
            Ok(t) => t,
            Err(e) => return (fail_all(e), None),
        };
        let want = if set.is_empty() {
            String::new()
        } else {
            table.clone()
        };
        let unchanged = match &self.last {
            Some((r, l)) => *r == want && *l == before,
            None => before.is_none() && set.is_empty(),
        };
        let generation = if unchanged {
            self.pending()
        } else {
            // The baseline: the last confirmed table, kept across changes
            // that are not yet confirmed.
            if self.pending.is_none() {
                let restore = replace_script(before.as_deref());
                if let Err(e) = write_private(&self.rollback_file(), &restore) {
                    return (fail_all(format!("rollback script: {e}")), None);
                }
            }
            if let Some(p) = self.pending.take()
                && let Some(u) = p.unit
            {
                Self::disarm(&u).await;
            }
            self.generation += 1;
            let unit = match self.arm().await {
                Ok(u) => u,
                Err(e) => {
                    warn!(%e, "managed forward: rollback timer not armed; refusing the change");
                    return (fail_all(e), None);
                }
            };
            self.pending = Some(Pending {
                generation: self.generation,
                deadline: Instant::now() + self.window,
                unit,
            });
            let script = replace_script((!set.is_empty()).then_some(table.as_str()));
            if let Err(e) = self.nft.apply(&script).await {
                warn!(%e, "managed forward: nft refused the change");
                self.rollback("nft refused the change").await;
                return (fail_all(e), None);
            }
            self.last = Some((want, self.nft.current().await.ok().flatten()));
            info!(
                generation = self.generation,
                forwards = set.len(),
                "managed forward: nft table replaced, awaiting confirmation"
            );
            Some(self.generation)
        };
        (self.statuses(set, &bad).await, generation)
    }

    async fn statuses(&self, set: &[NatForward], bad: &[(usize, String)]) -> Vec<Status> {
        let installed = self.nft.installed().await;
        set.iter()
            .enumerate()
            .map(|(i, f)| {
                let state = if let Some((_, why)) = bad.iter().find(|(j, _)| *j == i) {
                    State::Failed(why.clone())
                } else {
                    match &installed {
                        Ok(have) if have.contains(&(f.id.clone(), f.revision)) => State::Listening,
                        Ok(_) => State::Failed("not in the owned table after apply".into()),
                        Err(e) => State::Failed(e.clone()),
                    }
                };
                Status {
                    id: f.id.clone(),
                    revision: f.revision,
                    state,
                }
            })
            .collect()
    }

    /// The server heard this node after `generation`: keep it. A late or
    /// foreign confirmation changes nothing.
    pub async fn confirm(&mut self, generation: u64) -> bool {
        let Some(p) = self.pending.as_ref() else {
            return false;
        };
        if p.generation != generation || Instant::now() >= p.deadline {
            return false;
        }
        let p = self.pending.take().expect("checked above");
        if let Some(u) = p.unit {
            Self::disarm(&u).await;
        }
        let _ = std::fs::remove_file(self.rollback_file());
        info!(generation, "managed forward: nft change confirmed");
        true
    }

    /// Past the deadline without confirmation: restore the baseline.
    /// Returns whether it rolled back.
    pub async fn expire(&mut self) -> bool {
        match &self.pending {
            Some(p) if Instant::now() >= p.deadline => {
                self.rollback("not confirmed in time").await;
                true
            }
            _ => false,
        }
    }

    async fn rollback(&mut self, why: &str) {
        self.last = None;
        if let Some(p) = self.pending.take()
            && let Some(u) = p.unit
        {
            Self::disarm(&u).await;
        }
        let file = self.rollback_file();
        match std::fs::read_to_string(&file) {
            Ok(script) => match self.nft.apply(&script).await {
                Ok(()) => warn!(why, "managed forward: nft table rolled back"),
                Err(e) => warn!(why, %e, "managed forward: nft rollback failed"),
            },
            Err(e) => warn!(why, %e, "managed forward: no rollback script"),
        }
        let _ = std::fs::remove_file(file);
    }

    /// Remove the owned table and every pending rollback (the connection
    /// ended, or the process starts). A stale timer must not restore a
    /// table later.
    pub async fn clear(&mut self) -> Result<(), String> {
        if let Some(p) = self.pending.take()
            && let Some(u) = p.unit
        {
            Self::disarm(&u).await;
        }
        if self.watchdog == Watchdog::Systemd {
            Self::disarm(&format!("{UNIT_PREFIX}*")).await;
        }
        let _ = std::fs::remove_file(self.rollback_file());
        self.last = None;
        if self.nft.current().await?.is_some() {
            self.nft.apply(&replace_script(None)).await?;
        }
        Ok(())
    }
}

fn write_private(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(id: &str, bind: &str, dest: &str, sources: &[&str], masq: bool) -> NatForward {
        NatForward {
            id: id.into(),
            revision: 3,
            bind: bind.parse().unwrap(),
            proto: L4::Tcp,
            sources: sources
                .iter()
                .map(|s| {
                    let (ip, len) = s.split_once('/').unwrap();
                    (ip.parse().unwrap(), len.parse().unwrap())
                })
                .collect(),
            dest: dest.parse().unwrap(),
            masquerade: masq,
        }
    }

    #[test]
    fn render_dnats_admitted_sources_and_masquerades_only_the_forwards_flows() {
        let (t, bad) = render(&[
            fwd(
                "a1",
                "100.64.0.2:15432",
                "10.0.0.5:5432",
                &["100.64.0.0/10", "fd00::/8"],
                true,
            ),
            fwd(
                "b2",
                "[fd00::2]:8443",
                "[fd00::5]:443",
                &["fd00::/8"],
                false,
            ),
        ]);
        assert!(bad.is_empty(), "{bad:?}");
        assert!(t.contains(
            "ip daddr 100.64.0.2 tcp dport 15432 ip saddr { 100.64.0.0/10 } dnat ip to 10.0.0.5:5432 comment \"mf:a1:3\""
        ), "{t}");
        assert!(t.contains(
            "meta l4proto tcp ip daddr 10.0.0.5 tcp dport 5432 ct original ip daddr 100.64.0.2 ct original proto-dst 15432 masquerade comment \"mf:a1:3\""
        ), "{t}");
        assert!(t.contains(
            "ip6 daddr fd00::2 tcp dport 8443 ip6 saddr { fd00::/8 } dnat ip6 to [fd00::5]:443 comment \"mf:b2:3\""
        ), "{t}");
        assert_eq!(
            t.matches("masquerade").count(),
            1,
            "preserve-source is not masqueraded"
        );
        assert!(!t.contains("flush"));
        assert_eq!(t.matches("table inet ").count(), 1);
    }

    #[test]
    fn render_leaves_out_what_it_cannot_express() {
        let (t, bad) = render(&[
            fwd("ok", "10.0.0.1:80", "10.0.0.2:80", &["10.0.0.0/8"], true),
            fwd(
                "x\" ; flush ruleset",
                "10.0.0.1:81",
                "10.0.0.2:80",
                &["10.0.0.0/8"],
                true,
            ),
            fwd(
                "mixed",
                "10.0.0.1:82",
                "[fd00::5]:80",
                &["10.0.0.0/8"],
                true,
            ),
            fwd("v6src", "10.0.0.1:83", "10.0.0.2:80", &["fd00::/8"], true),
        ]);
        assert_eq!(
            bad.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(!t.contains("flush"));
        assert_eq!(t.matches("dnat").count(), 1);
    }

    #[test]
    fn the_replace_script_is_one_owned_transaction() {
        assert_eq!(
            replace_script(None),
            "add table inet meshharbor_fwd\ndelete table inet meshharbor_fwd\n"
        );
        let s = replace_script(Some("table inet meshharbor_fwd {\n}\n"));
        assert!(s.starts_with(
            "add table inet meshharbor_fwd\ndelete table inet meshharbor_fwd\ntable inet"
        ));
    }

    /// A stand-in `nft` that refuses any preflight carrying a DNAT and logs
    /// every call.
    fn fake_nft(dir: &std::path::Path) -> Nft {
        let log = dir.join("calls");
        let script = format!(
            "echo \"$*\" >> {log}; case \"$*\" in *'-c -f -'*) if grep -q dnat; then echo 'Error: refused' >&2; exit 1; fi;; *) cat >/dev/null;; esac; exit 0",
            log = log.display()
        );
        Nft {
            argv: vec!["sh".into(), "-c".into(), script, "nft".into()],
        }
    }

    #[tokio::test]
    async fn a_refused_change_is_rolled_back_and_leaves_nothing_pending() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = NftBackend::new(
            fake_nft(dir.path()),
            Watchdog::InProcess,
            Duration::from_secs(30),
            dir.path().into(),
        );
        let (st, g) = b
            .apply(&[fwd(
                "a1",
                "10.9.0.1:8080",
                "10.9.0.2:80",
                &["10.0.0.0/8"],
                false,
            )])
            .await;
        assert_eq!(g, None);
        assert_eq!(st[0].state, State::Failed("Error: refused".into()));
        assert_eq!(b.pending(), None);
        assert!(!dir.path().join("managed-forward-rollback.nft").exists());
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        // list, the refused preflight, then the restore's preflight and commit.
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            vec!["list tables inet", "-c -f -", "-c -f -", "-f -"],
            "{calls}"
        );
    }

    /// A private network namespace, deleted on drop.
    struct Netns(String);

    impl Netns {
        fn new() -> Self {
            let name = format!("mhfwd-{}-{}", std::process::id(), rand_suffix());
            let ok = std::process::Command::new("ip")
                .args(["netns", "add", &name])
                .status()
                .is_ok_and(|s| s.success());
            assert!(ok, "ip netns add {name} (needs root)");
            Netns(name)
        }
        fn nft(&self) -> Nft {
            let nft = Nft::system().argv.remove(0);
            Nft {
                argv: vec![
                    "ip".into(),
                    "netns".into(),
                    "exec".into(),
                    self.0.clone(),
                    nft,
                ],
            }
        }
    }

    impl Drop for Netns {
        fn drop(&mut self) {
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &self.0])
                .status();
        }
    }

    fn rand_suffix() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    }

    async fn ruleset(nft: &Nft) -> String {
        nft.run(&["list", "ruleset"], None).await.unwrap()
    }

    fn foreign_only(r: &str) -> String {
        // Everything outside the owned table.
        let mut out = String::new();
        let mut skip = false;
        for l in r.lines() {
            if l.starts_with("table ") {
                skip = l.starts_with(&format!("table inet {TABLE} "));
            }
            if !skip {
                out += l;
                out += "\n";
            }
        }
        out
    }

    /// Real nft in a throwaway namespace: apply, confirm, a change that is
    /// never confirmed rolls back to the confirmed table, clear removes
    /// only the owned table, and a foreign table is byte-for-byte the same
    /// throughout. Root only: `cargo test -- --ignored nft_`.
    #[tokio::test]
    #[ignore]
    async fn nft_commit_confirm_rollback_and_foreign_tables_untouched() {
        let ns = Netns::new();
        let nft = ns.nft();
        nft.apply(
            "table ip foreign {\n\tchain hostfw {\n\t\ttype filter hook forward priority 0; policy accept;\n\t\ttcp dport 22 accept\n\t}\n}\n",
        )
        .await
        .unwrap();
        let foreign = foreign_only(&ruleset(&nft).await);
        let dir = tempfile::tempdir().unwrap();
        let mut b = NftBackend::new(
            nft.clone(),
            Watchdog::InProcess,
            Duration::from_millis(300),
            dir.path().into(),
        );
        // DNAT only: the WSL kernel may lack nft_ct, which masquerade's
        // `ct original` match needs.
        let one = fwd("a1", "10.9.0.1:8080", "10.9.0.2:80", &["10.0.0.0/8"], false);
        let (st, g1) = b.apply(std::slice::from_ref(&one)).await;
        assert_eq!(st[0].state, State::Listening, "{st:?}");
        let g1 = g1.expect("a change awaits confirmation");
        assert!(b.confirm(g1).await);
        assert!(!b.confirm(g1).await, "confirms once");

        // Re-applying the same set changes nothing and needs no confirmation.
        let (_, g) = b.apply(std::slice::from_ref(&one)).await;
        assert_eq!(g, None);

        // A change that is never confirmed is undone.
        let two = fwd("b2", "10.9.0.1:8081", "10.9.0.2:81", &["10.0.0.0/8"], false);
        let (st, g2) = b.apply(&[one.clone(), two.clone()]).await;
        assert!(st.iter().all(|s| s.state == State::Listening), "{st:?}");
        assert!(g2.is_some());
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(b.expire().await);
        assert_eq!(
            nft.installed().await.unwrap(),
            vec![("a1".into(), 3)],
            "back to the confirmed table"
        );
        assert!(
            !b.confirm(g2.unwrap()).await,
            "a late confirmation keeps nothing"
        );

        assert_eq!(foreign_only(&ruleset(&nft).await), foreign);
        b.clear().await.unwrap();
        assert_eq!(nft.current().await.unwrap(), None);
        assert_eq!(ruleset(&nft).await, foreign);
    }

    /// The systemd timer restores the baseline with no help from this
    /// process. Root and systemd only.
    #[tokio::test]
    #[ignore]
    async fn nft_systemd_timer_rolls_back_without_the_process() {
        if Watchdog::detect() != Watchdog::Systemd {
            eprintln!("no systemd: skipped");
            return;
        }
        let ns = Netns::new();
        let nft = ns.nft();
        let dir = tempfile::tempdir().unwrap();
        let mut b = NftBackend::new(
            nft.clone(),
            Watchdog::Systemd,
            Duration::from_secs(2),
            dir.path().into(),
        );
        let one = fwd("a1", "10.9.0.1:8080", "10.9.0.2:80", &["10.0.0.0/8"], false);
        let (st, g) = b.apply(std::slice::from_ref(&one)).await;
        assert_eq!(st[0].state, State::Listening, "{st:?}");
        assert!(g.is_some());
        // Never call expire(): only the timer can undo it.
        let gone = async {
            for _ in 0..40 {
                if nft.current().await.unwrap().is_none() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            false
        };
        assert!(gone.await, "the timer restored the empty baseline");
        b.clear().await.unwrap();
    }
}
