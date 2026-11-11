// SPDX-License-Identifier: AGPL-3.0-only
//! Item 17 — releases served from the center's own directory
//! (`releases.local_dir`, `docs/self-hosted-releases.md`), against a real
//! server: the manifest the updater reads lists the directory with the
//! center's own URLs and a digest of the exact bytes, the artifact route
//! streams those bytes, and an artifact published without its `.asc` is not
//! served at all.

use sha2::{Digest, Sha256};

use crate::fixtures::test_app::TestApp;

const DEB: &str = "meshharbord-0.4.152-x86_64-unknown-linux-gnu.deb";
const BASE: &str = "https://center.test/meshharbor";

struct Dir(std::path::PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn release_dir(files: &[(&str, &[u8])]) -> Dir {
    let root = std::env::temp_dir().join(format!("mh-rel-it-{}", uuid::Uuid::new_v4().simple()));
    for (rel, bytes) in files {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    Dir(root)
}

async fn app_on(dir: &Dir) -> TestApp {
    let d = dir.0.to_str().unwrap().to_string();
    TestApp::spawn_with_settings(move |s| {
        s.releases.local_dir = Some(d);
        // `own_urls` builds client-facing URLs from this, and refuses
        // anything but explicit HTTPS.
        s.app.frontend_url = BASE.to_string();
    })
    .await
}

#[tokio::test]
async fn the_updater_manifest_lists_the_local_directory_with_own_urls_and_digests() {
    let payload: &[u8] = b"a daemon package from the center's own disk";
    let dir = release_dir(&[
        (&format!("agent-v0.4.152/{DEB}"), payload),
        (&format!("agent-v0.4.152/{DEB}.asc"), b"detached signature"),
        // Another family in the same directory: never listed as an agent.
        (
            "tunnel-v0.4.152/mh-0.4.152-x86_64-unknown-linux-gnu.tar.gz",
            b"t",
        ),
        (
            "tunnel-v0.4.152/mh-0.4.152-x86_64-unknown-linux-gnu.tar.gz.asc",
            b"s",
        ),
    ]);
    let app = app_on(&dir).await;

    let resp = app
        .client
        .get(app.url("/api/agent/latest-release"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let releases: serde_json::Value = resp.json().await.unwrap();
    let list = releases.as_array().unwrap();
    assert_eq!(list.len(), 1, "{releases}");
    assert_eq!(list[0]["tag_name"], "agent-v0.4.152");
    let deb = list[0]["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == DEB)
        .unwrap();
    assert_eq!(
        deb["browser_download_url"],
        format!("{BASE}/api/agent/artifacts/agent-v0.4.152/{DEB}")
    );
    assert_eq!(
        deb["digest"],
        format!("sha256:{}", hex::encode(Sha256::digest(payload)))
    );
    assert_eq!(deb["size"], payload.len());
    let text = releases.to_string();
    assert!(
        !text.contains(dir.0.to_str().unwrap()),
        "a server path leaked: {text}"
    );
    assert!(!text.contains("local_path"), "{text}");

    // The bytes behind that URL are exactly the bytes the digest names.
    let got = app
        .client
        .get(app.url(&format!("/api/agent/artifacts/agent-v0.4.152/{DEB}")))
        .send()
        .await
        .unwrap();
    assert_eq!(got.status(), 200);
    assert_eq!(got.bytes().await.unwrap().as_ref(), payload);
    let sig = app
        .client
        .get(app.url(&format!("/api/agent/artifacts/agent-v0.4.152/{DEB}.asc")))
        .send()
        .await
        .unwrap();
    assert_eq!(sig.status(), 200);
    assert_eq!(sig.bytes().await.unwrap().as_ref(), b"detached signature");
}

/// The agents refuse an artifact without its `.asc`; the center refuses to
/// serve one, so a publishing mistake is a 404, not a fleet-wide refusal storm.
#[tokio::test]
async fn an_artifact_without_its_signature_is_not_served() {
    let dir = release_dir(&[(&format!("agent-v0.4.152/{DEB}"), b"unsigned")]);
    let app = app_on(&dir).await;
    let resp = app
        .client
        .get(app.url(&format!("/api/agent/artifacts/agent-v0.4.152/{DEB}")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Path tokens are validated before the directory is touched, exactly as on
/// the GitHub path: no traversal out of the release directory.
#[tokio::test]
async fn traversal_out_of_the_release_directory_is_refused() {
    let dir = release_dir(&[
        (&format!("agent-v0.4.152/{DEB}"), b"x"),
        (&format!("agent-v0.4.152/{DEB}.asc"), b"y"),
    ]);
    let app = app_on(&dir).await;
    for path in [
        "/api/agent/artifacts/agent-v0.4.152/..%2F..%2Fetc%2Fpasswd",
        "/api/agent/artifacts/..%2F..%2Fetc/passwd",
        "/api/agent/artifacts/agent-v0.4.152/.hidden",
    ] {
        let status = app.client.get(app.url(path)).send().await.unwrap().status();
        assert!(status == 400 || status == 404, "{path} answered {status}");
    }
}
