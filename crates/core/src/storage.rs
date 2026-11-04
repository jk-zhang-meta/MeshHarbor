// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! File-storage backend — local disk (dev/test default) or S3/MinIO (prod).
//!
//! Until S0 every upload and export artifact was written straight to
//! `ROOMLER_UPLOAD_DIR` (default `/tmp/roomler-ai-uploads`), which inside the
//! k8s pod is ephemeral: every redeploy wiped all file bytes while the Mongo
//! `files` records survived. MinIO + `ROOMLER__S3__*` creds were already
//! deployed but unused. This module is the missing backend: routes call
//! [`FileStorage::put`]/[`FileStorage::get`] with a relative storage key
//! (`<tenant>/room/<room>/<uuid>`, `exports/<name>`) and the backend is picked
//! once at startup from `s3.enabled`.
//!
//! Legacy compatibility: pre-S0 export tasks recorded an ABSOLUTE
//! `file_path`; the Local backend resolves absolute keys as-is so those
//! downloads keep working, while the S3 backend treats them as ordinary
//! (missing) keys → 404, which is the accepted answer for artifacts that
//! lived on a wiped `/tmp` anyway.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use object_store::{ObjectStore, aws::AmazonS3Builder, path::Path as ObjectPath};
use tracing::{info, warn};

/// Directory used by the Local backend AND as the migration source when the
/// S3 backend is enabled on a host that still has locally-written files.
pub fn local_upload_dir() -> PathBuf {
    let dir = std::env::var("ROOMLER_UPLOAD_DIR")
        .unwrap_or_else(|_| "/tmp/roomler-ai-uploads".to_string());
    PathBuf::from(dir)
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("object not found")]
    NotFound,
    #[error("{0}")]
    Other(String),
}

pub enum FileStorage {
    Local { base: PathBuf },
    S3 { store: Arc<dyn ObjectStore> },
}

impl FileStorage {
    pub fn from_settings(s3: &meshharbor_config::S3Settings) -> anyhow::Result<Self> {
        if !s3.enabled {
            return Ok(Self::Local {
                base: local_upload_dir(),
            });
        }
        let store = AmazonS3Builder::new()
            .with_endpoint(s3.endpoint.as_str())
            // MinIO in-cluster is plain http; allow_http only widens what the
            // endpoint URL may be, it never downgrades an https endpoint.
            .with_allow_http(true)
            .with_bucket_name(s3.bucket.as_str())
            .with_region(s3.region.as_str())
            .with_access_key_id(s3.access_key.as_str())
            .with_secret_access_key(s3.secret_key.as_str())
            // Path-style addressing — MinIO's default; virtual-hosted style
            // would try `bucket.minio.svc...` which doesn't resolve.
            .with_virtual_hosted_style_request(false)
            .build()?;
        info!(endpoint = %s3.endpoint, bucket = %s3.bucket, "S3 file-storage backend enabled");
        Ok(Self::S3 {
            store: Arc::new(store),
        })
    }

    /// The `storage_bucket` value recorded on new `files` documents.
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::S3 { .. } => "s3",
        }
    }

    pub async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), StorageError> {
        match self {
            Self::Local { base } => {
                let path = resolve_local(base, key);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| StorageError::Other(format!("create dir: {e}")))?;
                }
                tokio::fs::write(&path, &bytes)
                    .await
                    .map_err(|e| StorageError::Other(format!("write: {e}")))
            }
            Self::S3 { store } => store
                .put(&ObjectPath::from(key), bytes::Bytes::from(bytes).into())
                .await
                .map(|_| ())
                .map_err(|e| StorageError::Other(e.to_string())),
        }
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        match self {
            Self::Local { base } => {
                let path = resolve_local(base, key);
                match tokio::fs::read(&path).await {
                    Ok(bytes) => Ok(bytes),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Err(StorageError::NotFound)
                    }
                    Err(e) => Err(StorageError::Other(format!("read: {e}"))),
                }
            }
            Self::S3 { store } => match store.get(&ObjectPath::from(key)).await {
                Ok(result) => result
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|e| StorageError::Other(e.to_string())),
                Err(object_store::Error::NotFound { .. }) => Err(StorageError::NotFound),
                Err(e) => Err(StorageError::Other(e.to_string())),
            },
        }
    }

    /// One-off startup sweep: when the S3 backend is enabled and the legacy
    /// local upload dir still holds files (written by a pre-S0 pod), copy them
    /// up so their `files` records resolve again. Local files are left in
    /// place (the dir is ephemeral; deleting buys nothing and costs the only
    /// remaining copy if an upload fails). No-op on the Local backend.
    pub async fn migrate_local_to_s3(&self) {
        let Self::S3 { store } = self else { return };
        let base = local_upload_dir();
        let listing = tokio::task::spawn_blocking(move || collect_local_files(&base)).await;
        let files = match listing {
            Ok(files) => files,
            Err(e) => {
                warn!("local→S3 migration: file walk task failed: {e}");
                return;
            }
        };
        if files.is_empty() {
            return;
        }
        let (mut migrated, mut skipped, mut failed) = (0u64, 0u64, 0u64);
        for (abs, key) in files {
            let path = ObjectPath::from(key.as_str());
            if store.head(&path).await.is_ok() {
                skipped += 1;
                continue;
            }
            let bytes = match tokio::fs::read(&abs).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(?abs, "local→S3 migration: read failed: {e}");
                    failed += 1;
                    continue;
                }
            };
            match store.put(&path, bytes::Bytes::from(bytes).into()).await {
                Ok(_) => migrated += 1,
                Err(e) => {
                    warn!(%key, "local→S3 migration: upload failed: {e}");
                    failed += 1;
                }
            }
        }
        info!(
            migrated,
            skipped, failed, "local→S3 upload-dir migration finished"
        );
    }
}

/// Relative keys land under `base`; absolute keys (legacy `file_path`s from
/// pre-S0 export tasks) are used as-is.
fn resolve_local(base: &Path, key: &str) -> PathBuf {
    let p = Path::new(key);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(key)
    }
}

/// Blocking recursive walk of the local upload dir → `(absolute, storage_key)`
/// pairs, storage keys normalised to `/` separators. Missing dir → empty.
fn collect_local_files(base: &Path) -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else if let Ok(rel) = path.strip_prefix(base) {
                let key = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                if !key.is_empty() {
                    out.push((path.clone(), key));
                }
            }
        }
    }
    let mut out = Vec::new();
    if base.is_dir() {
        walk(base, base, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_put_get_roundtrip_and_notfound() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::Local {
            base: dir.path().to_path_buf(),
        };
        storage
            .put("t1/room/r1/abc", b"hello".to_vec())
            .await
            .unwrap();
        assert_eq!(storage.get("t1/room/r1/abc").await.unwrap(), b"hello");
        assert!(matches!(
            storage.get("t1/room/r1/missing").await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn local_resolves_legacy_absolute_paths() {
        let dir = tempfile::tempdir().unwrap();
        let abs = dir.path().join("legacy-export.xlsx");
        tokio::fs::write(&abs, b"legacy").await.unwrap();
        let storage = FileStorage::Local {
            base: PathBuf::from("/nonexistent-base"),
        };
        let key = abs.to_string_lossy().to_string();
        assert_eq!(storage.get(&key).await.unwrap(), b"legacy");
    }

    #[test]
    fn collect_local_files_walks_nested_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("tid").join("room").join("rid");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("f1"), b"x").unwrap();
        std::fs::write(dir.path().join("top"), b"y").unwrap();
        let mut keys: Vec<String> = collect_local_files(dir.path())
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["tid/room/rid/f1".to_string(), "top".to_string()]);
    }
}
