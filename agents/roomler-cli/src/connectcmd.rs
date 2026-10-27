// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-9-2b — `meshharbor connect <handle>`: a local endpoint that signs in
//! to a secret's upstream (a database, an HTTP API, a Kubernetes API server,
//! an SSH host) as the secret's user. The value stays in this device's daemon
//! and never reaches you (`docs/vault.md` §23).
//!
//! In the foreground (decision 25): the daemon holds the endpoint for as long
//! as this command's connection to it stays open, renewing its leases
//! meanwhile, each renewal a request the vault decides and records again.
//! Ctrl-C ends it. So does the vault taking it back for good, and then this
//! says why.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use tunnel_core::localapi::{self, ConnectArgs, EndpointState, Request, Response};

use crate::localclient::daemon_err;
use crate::sshcmd::{PrivateDir, write_private};

/// How often the command asks the daemon where its endpoint stands.
const POLL: Duration = Duration::from_secs(5);

/// `meshharbor connect`: open the endpoint, say how to use it, and hold it until
/// Ctrl-C (`Ok`) or until it closes (an error saying why).
pub async fn run(args: ConnectArgs, json: bool) -> Result<()> {
    let mut client = localapi::connect().await.map_err(daemon_err)?;
    let (id, endpoint) = match client
        .request(&Request::Connect { args })
        .await
        .map_err(daemon_err)?
    {
        Response::Connected { id, endpoint } => (id, endpoint),
        Response::Error { message } => bail!("{}", refused(&message)),
        other => bail!("the roomler daemon answered something else: {other:?}"),
    };
    // The files a client reads by path. Nothing in them is secret, and they
    // go when this does.
    let dir = if files_of(&endpoint).is_empty() {
        None
    } else {
        Some(PrivateDir::named("roomler-connect")?)
    };
    let written = match &dir {
        Some(dir) => write_files(dir, &endpoint)?,
        None => Vec::new(),
    };
    if json {
        let files: serde_json::Map<String, Value> = written
            .iter()
            .map(|(what, path)| (what.to_string(), json!(path)))
            .collect();
        println!(
            "{}",
            json!({ "id": id, "endpoint": endpoint, "files": files })
        );
    } else {
        print!("{}", describe(id, &endpoint, &written));
    }
    hold(&mut client, id, json).await
}

/// Ask where endpoint `id` stands every [`POLL`], say what changed, and end
/// at Ctrl-C or when it closes. One Ctrl-C future for the whole hold: one
/// made afresh each turn would miss a Ctrl-C that came while a status was
/// asked, once the first had taken the signal from its default.
async fn hold(client: &mut localapi::Client, id: u64, json: bool) -> Result<()> {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let ask = Request::ConnectStatus { id };
    let mut last: Option<EndpointState> = None;
    loop {
        tokio::select! {
            _ = &mut ctrl_c => return Ok(()),
            () = tokio::time::sleep(POLL) => {}
        }
        let answer = tokio::select! {
            _ = &mut ctrl_c => return Ok(()),
            answer = client.request(&ask) => answer,
        };
        let state = match answer {
            Ok(Response::ConnectState(state)) => state,
            Ok(Response::Error { message }) => bail!("the endpoint is gone: {message}"),
            Ok(other) => bail!("the roomler daemon answered something else: {other:?}"),
            Err(e) => {
                bail!("the roomler daemon ended the connection, and the endpoint with it: {e}")
            }
        };
        if json {
            if moved(last.as_ref(), &state) {
                println!("{}", serde_json::to_string(&state)?);
            }
        } else if let Some(said) = news(last.as_ref(), &state) {
            println!("{said}");
        }
        if let Some(why) = &state.closed {
            bail!("the endpoint closed: {why}");
        }
        last = Some(state);
    }
}

/// Whether anything but the time left changed: what `--json` reports.
fn moved(last: Option<&EndpointState>, now: &EndpointState) -> bool {
    let was = last.cloned().unwrap_or_default();
    (was.renewals, &was.refused, &was.closed) != (now.renewals, &now.refused, &now.closed)
}

/// What changed since `last`, in words, or `None`. Its close is the command's
/// own error, so it is not said here.
fn news(last: Option<&EndpointState>, now: &EndpointState) -> Option<String> {
    let was = last.cloned().unwrap_or_default();
    if now.refused.is_some() && now.refused != was.refused {
        return Some(format!(
            "the vault refused to renew it ({}): it serves until its leases end, in {} s",
            now.refused.as_deref().unwrap_or_default(),
            now.left_s
        ));
    }
    (now.renewals > was.renewals).then(|| {
        format!(
            "renewed: its leases have {} s again ({} renewal{} so far)",
            now.left_s,
            now.renewals,
            if now.renewals == 1 { "" } else { "s" }
        )
    })
}

/// A refusal as the person reads it. A daemon older than the verb does not
/// know it, which is not a refusal at all.
fn refused(message: &str) -> String {
    if message.starts_with("bad request: unknown variant") {
        return "this device's roomler daemon is older than `meshharbor connect`: update it".into();
    }
    message.to_string()
}

/// The files the answer carries for a client to read by path: a Kubernetes
/// endpoint's kubeconfig, an SSH endpoint's known_hosts.
fn files_of(endpoint: &Value) -> Vec<(&'static str, &'static str, String)> {
    [
        ("KUBECONFIG", "kubeconfig", "kubeconfig"),
        ("known_hosts", "known_hosts", "known_hosts"),
    ]
    .into_iter()
    .filter_map(|(what, key, file)| {
        endpoint[key]
            .as_str()
            .map(|text| (what, file, text.to_string()))
    })
    .collect()
}

/// Write [`files_of`] into `dir`, owner-only: what each is, and where.
fn write_files(dir: &PrivateDir, endpoint: &Value) -> Result<Vec<(&'static str, PathBuf)>> {
    files_of(endpoint)
        .into_iter()
        .map(|(what, file, text)| {
            let path = dir.path().join(file);
            write_private(&path, text.as_bytes())?;
            Ok((what, path))
        })
        .collect()
}

/// What the person is told about endpoint `id`: where it is, what to set,
/// the files written for it, and the daemon's own note.
fn describe(id: u64, endpoint: &Value, files: &[(&'static str, PathBuf)]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "endpoint {id}: {} to {}, signed in as the secret's user",
        endpoint["engine"].as_str().unwrap_or("?"),
        endpoint["upstream"].as_str().unwrap_or("?")
    );
    let mut row = |what: &str, value: &str| {
        let _ = writeln!(out, "  {what:<13} {value}");
    };
    if let Some(uri) = endpoint["uri"].as_str() {
        row("uri", uri);
    }
    if let Some(env) = endpoint["env"].as_object() {
        for (name, value) in env {
            if let Some(value) = value.as_str() {
                row(name, value);
            }
        }
    }
    for (what, path) in files {
        row(what, &path.display().to_string());
    }
    if let Some(ttl) = endpoint["ttl_s"].as_u64() {
        row("its leases", &format!("{ttl} s, renewed before they end"));
    }
    if let Some(note) = endpoint["note"].as_str() {
        let _ = writeln!(out, "{note}");
    }
    out.push_str("Leave this running while you use it: Ctrl-C closes it.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(left_s: u64, renewals: u32, refused: Option<&str>) -> EndpointState {
        EndpointState {
            left_s,
            renewals,
            refused: refused.map(String::from),
            closed: None,
        }
    }

    /// A renewal and a refusal are said once each, the time left alone
    /// never; `--json` reports the same moments.
    #[test]
    fn a_renewal_and_a_refusal_are_said_once_and_time_passing_never() {
        let first = state(280, 0, None);
        assert_eq!(news(None, &first), None, "nothing happened yet");
        assert!(!moved(None, &first));
        let later = state(150, 0, None);
        assert_eq!(news(Some(&first), &later), None, "only time passed");
        assert!(!moved(Some(&first), &later));
        let renewed = state(300, 1, None);
        assert_eq!(
            news(Some(&later), &renewed).as_deref(),
            Some("renewed: its leases have 300 s again (1 renewal so far)")
        );
        assert!(moved(Some(&later), &renewed));
        let refused = state(90, 1, Some("git/bot#token: the vault refused: denied"));
        assert_eq!(
            news(Some(&renewed), &refused).as_deref(),
            Some(
                "the vault refused to renew it (git/bot#token: the vault refused: denied): it \
                 serves until its leases end, in 90 s"
            )
        );
        assert!(moved(Some(&renewed), &refused));
        let still = state(40, 1, Some("git/bot#token: the vault refused: denied"));
        assert_eq!(news(Some(&refused), &still), None, "said once");
        assert!(!moved(Some(&refused), &still));
    }

    /// A daemon older than the verb is told apart from a refusal; a refusal
    /// is shown as the daemon words it.
    #[test]
    fn an_older_daemon_is_told_apart_from_a_refusal() {
        assert_eq!(
            refused("bad request: unknown variant `connect`, expected one of `status`"),
            "this device's roomler daemon is older than `meshharbor connect`: update it"
        );
        let word = "meshharbor connect lends this device's owner's vault grants, so here only root";
        assert_eq!(refused(word), word);
    }

    /// The endpoint as the person reads it: where it is, what to set, the
    /// files written for it and the daemon's note; and a kubeconfig and a
    /// known_hosts become files, nothing else does.
    #[test]
    fn the_endpoint_is_described_with_what_to_set_and_the_files_written() {
        let endpoint = json!({
            "engine": "kubernetes",
            "upstream": "https://api.k8s.internal:6443",
            "uri": "http://127.0.0.1:50123",
            "env": {},
            "ttl_s": 300,
            "kubeconfig": "apiVersion: v1\n",
            "note": "Write kubeconfig to a file of your own.",
            "id": 3,
        });
        let files = files_of(&endpoint);
        assert_eq!(
            files,
            [("KUBECONFIG", "kubeconfig", "apiVersion: v1\n".to_string())]
        );
        let written = [(
            "KUBECONFIG",
            PathBuf::from("/tmp/roomler-connect-x/kubeconfig"),
        )];
        assert_eq!(
            describe(3, &endpoint, &written),
            "endpoint 3: kubernetes to https://api.k8s.internal:6443, signed in as the \
             secret's user\n  uri           http://127.0.0.1:50123\n  KUBECONFIG    \
             /tmp/roomler-connect-x/kubeconfig\n  its leases    300 s, renewed before they \
             end\nWrite kubeconfig to a file of your own.\nLeave this running while you use \
             it: Ctrl-C closes it.\n"
        );
        let postgres = json!({
            "engine": "postgres",
            "upstream": "db.internal:5432",
            "uri": "postgresql:///?host=%2Frun%2Fx&port=5432",
            "env": { "PGHOST": "/run/x", "PGPORT": "5432" },
            "ttl_s": 120,
        });
        assert!(files_of(&postgres).is_empty(), "a database needs no file");
        let said = describe(4, &postgres, &[]);
        assert!(said.contains("  PGHOST        /run/x\n"), "{said}");
        assert!(said.contains("  PGPORT        5432\n"), "{said}");
    }

    /// The files are written owner-only into a directory of their own, which
    /// goes with them.
    #[test]
    fn the_files_go_with_the_directory() {
        let endpoint = json!({ "known_hosts": "[db.internal]:22 ssh-ed25519 KEY\n" });
        let dir = PrivateDir::named("roomler-connect-test").unwrap();
        let root = dir.path().to_path_buf();
        let written = write_files(&dir, &endpoint).unwrap();
        assert_eq!(written, [("known_hosts", root.join("known_hosts"))]);
        assert_eq!(
            std::fs::read_to_string(root.join("known_hosts")).unwrap(),
            "[db.internal]:22 ssh-ed25519 KEY\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("known_hosts"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        drop(dir);
        assert!(!root.exists(), "gone with its directory");
    }
}
