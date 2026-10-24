// SPDX-License-Identifier: MPL-2.0
//! Cross-account single-device SSH. Uses an approved user's access JWT, not an
//! enrollment/tenant credential, and verifies the device's actual SSH host key.
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
#[derive(Deserialize)]
struct Device {
    id: String,
    host_pubkey: String,
}
struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// SSH is a shell with the chosen local OS account's capabilities, NOT a network
/// or filesystem sandbox. The product bridge grants no overlay/LAN/transit role.
pub async fn run(
    server: &str,
    share: &str,
    token_file: PathBuf,
    session_secs: u64,
    args: &[String],
) -> Result<i32> {
    let share = bson::oid::ObjectId::parse_str(share).context("share must be an exact grant ID")?;
    let bytes = std::fs::metadata(&token_file)
        .context("access-token file metadata")?
        .len();
    if bytes == 0 || bytes > 16 * 1024 {
        bail!("access-token file must contain one bounded access JWT");
    }
    let token = std::fs::read_to_string(&token_file).context("reading access-token file")?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        bail!("access-token file is empty");
    }
    run_with_token(server, &share.to_hex(), token, session_secs, args).await
}
/// In-memory Access credential from native login or the backwards-compatible file.
/// The JWT still has general account API authority; transport grants only this share.
pub(crate) async fn run_with_token(
    server: &str,
    share: &str,
    token: String,
    session_secs: u64,
    args: &[String],
) -> Result<i32> {
    let share = bson::oid::ObjectId::parse_str(share).context("share must be an exact grant ID")?;
    let server = crate::native_auth::legacy_server_base(server)?;
    let http = crate::native_auth::http_client(&server)?;
    let r = http
        .get(format!(
            "{}/api/device-shares/{share}/ssh",
            server.trim_end_matches('/')
        ))
        .bearer_auth(&token)
        .send()
        .await
        .context("shared SSH device lookup")?;
    if !r.status().is_success() {
        bail!(
            "shared SSH device authorization failed (HTTP {})",
            r.status()
        );
    }
    let device: Device = crate::native_auth::bounded_json(r).await?;
    let agent = bson::oid::ObjectId::parse_str(&device.id)
        .context("server returned an invalid device ID")?;
    let host =
        ssh_key::PublicKey::from_openssh(&device.host_pubkey).context("device SSH host key")?;
    if host.algorithm() != ssh_key::Algorithm::Ed25519 {
        bail!("device SSH host key is not Ed25519");
    }
    let key = crate::sshcmd::mint_session_key()?;
    let public = key.public_key().to_openssh()?;
    let dir = crate::sshcmd::PrivateDir::named("meshharbor-share-ssh")?;
    let private = dir.path().join("id");
    crate::sshcmd::write_private(
        &private,
        key.to_openssh(ssh_key::LineEnding::LF)?.as_bytes(),
    )?;
    let (ready, rx) = tokio::sync::oneshot::channel();
    let ready = Arc::new(Mutex::new(Some(ready)));
    let hook: tunnel_core::driver::ListeningHook = Arc::new(move |addr| {
        if let Some(tx) = ready.lock().expect("share SSH ready mutex").take() {
            let _ = tx.send(addr);
        }
    });
    let mut transport = Task(tokio::spawn(crate::forward::run_shared_ssh_transport(
        server,
        token,
        share,
        public,
        session_secs,
        agent,
        hook,
    )));
    let addr = tokio::select! {
        ready=tokio::time::timeout(Duration::from_secs(20),rx)=>ready.context("shared SSH tunnel setup timeout")?.context("shared SSH listener never became ready")?,
        result=&mut transport.0=>{let _=result.context("shared SSH transport task")??;bail!("shared SSH transport ended before it was ready");}
    };
    let kh = dir.path().join("known_hosts");
    crate::sshcmd::write_private(
        &kh,
        format!("[127.0.0.1]:{} {}\n", addr.port(), device.host_pubkey).as_bytes(),
    )?;
    let mut child = tokio::process::Command::new("ssh")
        .arg("-i")
        .arg(private)
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("IdentityAgent=none")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("roomler@127.0.0.1")
        .args(args)
        .kill_on_drop(true)
        .spawn()
        .context("starting the SSH client (embedded server requires no OS SSH service)")?;
    let status = tokio::select! {
        status=child.wait()=>status.context("waiting for SSH client")?,
        outcome=&mut transport.0=>{
            let _=outcome;
            tokio::time::timeout(Duration::from_secs(2),child.wait()).await.context("shared SSH carrier ended")?.context("waiting for SSH after carrier close")?
        }
    };
    Ok(status.code().unwrap_or(1))
}
