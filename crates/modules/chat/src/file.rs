// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, Query, State},
    response::Response,
};
use bson::oid::ObjectId;
use meshharbor_services::quota;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use meshharbor_core::{ApiError, extractors::auth::AuthUser};

use crate::ChatState;
use meshharbor_db::models::{FileContext, FileContextType};
use meshharbor_services::dao::base::PaginationParams;

/// FR-11 file-grid params. Flat (never `#[serde(flatten)]` behind axum
/// `Query` — the AuditQuery postmortem); every field optional/defaulted so a
/// parameterless request behaves exactly as before.
#[derive(Debug, Deserialize)]
pub struct FileListQuery {
    #[serde(default = "file_default_page")]
    pub page: u64,
    #[serde(default = "file_default_per_page")]
    pub per_page: u64,
    /// Case-insensitive substring over filename/display_name.
    pub q: Option<String>,
    /// `filename` | `size` | `created_at` (default, desc). Unknown → 400.
    pub sort: Option<String>,
    /// `asc` (default for explicit sorts) | `desc`.
    pub dir: Option<String>,
}
fn file_default_page() -> u64 {
    1
}
fn file_default_per_page() -> u64 {
    25
}

fn file_sort_args(params: &FileListQuery) -> Result<(Option<&str>, bool), ApiError> {
    let sort = params.sort.as_deref();
    if let Some(k) = sort
        && !matches!(k, "filename" | "size" | "created_at")
    {
        return Err(ApiError::BadRequest(format!("Unknown sort key: {k}")));
    }
    let desc = match params.dir.as_deref() {
        None | Some("asc") => false,
        Some("desc") => true,
        Some(other) => {
            return Err(ApiError::BadRequest(format!("Unknown dir: {other}")));
        }
    };
    Ok((sort, desc))
}

#[derive(Debug, Serialize)]
pub struct FileResponse {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub url: String,
    pub uploaded_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_name: Option<String>,
}

fn to_response(f: meshharbor_db::models::File) -> FileResponse {
    let room_id = f.context.room_id.map(|rid| rid.to_hex());
    FileResponse {
        id: f.id.unwrap().to_hex(),
        filename: f.filename,
        content_type: f.content_type,
        size: f.size,
        url: f.url,
        uploaded_by: f.uploaded_by.to_hex(),
        created_at: f.created_at.try_to_rfc3339_string().unwrap_or_default(),
        room_id,
        room_name: None,
    }
}

/// List files for a room.
pub async fn list(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    Query(params): Query<FileListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let (sort, desc) = file_sort_args(&params)?;
    let page_params = PaginationParams {
        page: params.page.max(1),
        per_page: params.per_page.clamp(1, 100),
        before: None,
    };
    let result = state
        .files
        .find_by_room(tid, rid, &page_params, params.q.as_deref(), sort, desc)
        .await?;

    let items: Vec<FileResponse> = result.items.into_iter().map(to_response).collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
        "total_pages": result.total_pages,
    })))
}

/// List all files across all rooms in a tenant.
pub async fn list_tenant_files(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(params): Query<FileListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let (sort, desc) = file_sort_args(&params)?;
    let page_params = PaginationParams {
        page: params.page.max(1),
        per_page: params.per_page.clamp(1, 100),
        before: None,
    };
    let result = state
        .files
        .find_by_tenant(tid, &page_params, params.q.as_deref(), sort, desc)
        .await?;

    // Collect unique room IDs and look up room names
    let room_ids: Vec<ObjectId> = result
        .items
        .iter()
        .filter_map(|f| f.context.room_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let mut room_names: HashMap<ObjectId, String> = HashMap::new();
    for rid in &room_ids {
        if let Ok(room) = state.rooms.base.find_by_id(*rid).await {
            room_names.insert(*rid, room.name);
        }
    }

    let items: Vec<FileResponse> = result
        .items
        .into_iter()
        .map(|f| {
            let mut resp = to_response(f.clone());
            if let Some(rid) = f.context.room_id {
                resp.room_name = room_names.get(&rid).cloned();
            }
            resp
        })
        .collect();

    Ok(Json(serde_json::json!({
        "items": items,
        "total": result.total,
        "page": result.page,
        "per_page": result.per_page,
        "total_pages": result.total_pages,
    })))
}

/// Shared upload logic used by both `upload` and `upload_room`.
async fn do_upload(
    state: &ChatState,
    tid: ObjectId,
    rid: ObjectId,
    user_id: ObjectId,
    file_data: (String, String, Vec<u8>),
) -> Result<FileResponse, ApiError> {
    let (filename, content_type, bytes) = file_data;
    let size = bytes.len() as u64;

    let storage_key = format!(
        "{}/room/{}/{}",
        tid.to_hex(),
        rid.to_hex(),
        uuid::Uuid::new_v4()
    );
    state
        .storage
        .put(&storage_key, bytes)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to store file: {}", e)))?;

    let context = FileContext {
        context_type: FileContextType::Room,
        entity_id: rid,
        room_id: Some(rid),
    };

    let file = state
        .files
        .create(
            tid,
            user_id,
            context,
            filename,
            content_type,
            size,
            state.storage.backend_name().to_string(),
            storage_key,
            String::new(),
        )
        .await?;

    let file_id_hex = file.id.unwrap().to_hex();
    let url = format!("/api/tenant/{}/file/{}/download", tid.to_hex(), file_id_hex);
    state
        .files
        .base
        .update_one(
            bson::doc! { "_id": file.id.unwrap() },
            bson::doc! { "$set": { "url": &url } },
        )
        .await?;

    let mut resp = to_response(file);
    resp.url = url;
    Ok(resp)
}

/// Upload a file via multipart form data.
/// Fields: `file` (binary), `room_id` (text)
pub async fn upload(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<FileResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let mut file_data: Option<(String, String, Vec<u8>)> = None;
    let mut room_id_str: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Multipart error: {}", e)))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                let filename = field.file_name().unwrap_or("unnamed").to_string();
                let claimed = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("Failed to read file: {}", e)))?;
                // The client wrote `claimed` into its own multipart part, so
                // it is a claim. Store what the BYTES say instead.
                let content_type = crate::media_type::resolve(&claimed, &filename, &bytes);
                file_data = Some((filename, content_type, bytes.to_vec()));
            }
            "room_id" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("Failed to read field: {}", e)))?;
                room_id_str = Some(text);
            }
            _ => {}
        }
    }

    let data = file_data.ok_or_else(|| ApiError::BadRequest("Missing 'file' field".to_string()))?;

    // FR-32 P1b — plan `storage_bytes` cap. Uses the DELTA form: a tenant at
    // 99 MB of 100 MB must be refused a 10 MB file and ALLOWED a 100 KB one,
    // which a bare "are you at the cap" test cannot express. The size is only
    // knowable here, after the multipart body has been read.
    {
        let tenant = state.tenants.base.find_by_id(tid).await?;
        let current = state.files.sum_storage_for_tenant(tid).await?;
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) = meshharbor_core::quota::check_delta(
            &state,
            &tenant,
            quota::Limit::StorageBytes,
            current,
            data.2.len() as u64,
        ) {
            return Err(ApiError::Forbidden(d.message()));
        }
    }
    let room_id_val =
        room_id_str.ok_or_else(|| ApiError::BadRequest("Missing 'room_id' field".to_string()))?;
    let rid = ObjectId::parse_str(&room_id_val)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    let resp = do_upload(&state, tid, rid, auth.user_id, data).await?;
    Ok(Json(resp))
}

pub async fn get(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, file_id)): Path<(String, String)>,
) -> Result<Json<FileResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let fid = ObjectId::parse_str(&file_id)
        .map_err(|_| ApiError::BadRequest("Invalid file_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let file = state.files.base.find_by_id_in_tenant(tid, fid).await?;
    Ok(Json(to_response(file)))
}

pub async fn download(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, file_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let fid = ObjectId::parse_str(&file_id)
        .map_err(|_| ApiError::BadRequest("Invalid file_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let file = state.files.base.find_by_id_in_tenant(tid, fid).await?;
    let contents = state
        .storage
        .get(&file.storage_key)
        .await
        .map_err(|e| match e {
            // tolerate-404: records whose bytes were lost on a pre-S0
            // pod-ephemeral /tmp (wiped on every deploy) resolve to a clear
            // 404 rather than a 500.
            meshharbor_core::storage::StorageError::NotFound => {
                ApiError::NotFound("File content is no longer available on the server".to_string())
            }
            meshharbor_core::storage::StorageError::Other(msg) => {
                ApiError::Internal(format!("Failed to read file: {}", msg))
            }
        })?;

    // Sanitize the stored filename before it lands in a response
    // header. `Response::builder()…unwrap()` panics if any header
    // value contains a CR/LF/0x00, so an unsanitized filename was
    // both an HTTP-header-injection risk AND a panic hazard. We
    // emit BOTH a sanitized ASCII `filename=` (legacy clients) and
    // an RFC 5987 `filename*=UTF-8''<pct-encoded>` (everything else)
    // so unicode + special chars survive round-trip.
    let (ascii_name, encoded_name) = sanitize_content_disposition_filename(&file.filename);
    let disposition = format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        ascii_name, encoded_name
    );

    Ok(Response::builder()
        .header("Content-Type", &file.content_type)
        .header("Content-Disposition", disposition)
        .body(Body::from(contents))
        .unwrap())
}

/// Sanitize a stored filename for the `Content-Disposition` header.
/// Returns `(ascii_quoted, rfc5987_encoded)`:
/// - `ascii_quoted` is safe to place inside `filename="…"` — control
///   chars, `"`, and `\` are stripped, non-ASCII is replaced with `_`,
///   and an empty result falls back to `"download"`.
/// - `rfc5987_encoded` percent-encodes everything outside RFC 5987's
///   `attr-char` set so it can sit after `filename*=UTF-8''`.
fn sanitize_content_disposition_filename(raw: &str) -> (String, String) {
    let mut ascii = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == '"' || ch == '\\' || (ch as u32) < 0x20 || ch == 0x7f as char {
            continue;
        }
        if ch.is_ascii() {
            ascii.push(ch);
        } else {
            ascii.push('_');
        }
    }
    if ascii.trim().is_empty() {
        ascii = "download".to_string();
    }

    // RFC 5987 attr-char = ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+"
    //                    / "-" / "." / "^" / "_" / "`" / "|" / "~"
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        let b = *byte;
        let is_attr_char = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            );
        if is_attr_char {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{:02X}", b));
        }
    }
    if encoded.is_empty() {
        encoded = "download".to_string();
    }

    (ascii, encoded)
}

pub async fn delete(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, file_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let fid = ObjectId::parse_str(&file_id)
        .map_err(|_| ApiError::BadRequest("Invalid file_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    state.files.soft_delete(tid, fid).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// Upload a file attached to a room (with 100MB body limit).
pub async fn upload_room(
    State(state): State<ChatState>,
    auth: AuthUser,
    Path((tenant_id, room_id)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<FileResponse>, ApiError> {
    let tid = ObjectId::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant_id".to_string()))?;
    let rid = ObjectId::parse_str(&room_id)
        .map_err(|_| ApiError::BadRequest("Invalid room_id".to_string()))?;

    if !state.tenants.is_member(tid, auth.user_id).await? {
        return Err(ApiError::NotAMember);
    }

    let mut file_data: Option<(String, String, Vec<u8>)> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Multipart error: {}", e)))?
    {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            let filename = field.file_name().unwrap_or("unnamed").to_string();
            let claimed = field
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_string();
            let bytes = field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(format!("Failed to read file: {}", e)))?;
            // The client wrote `claimed` into its own multipart part, so it is
            // a claim. Store what the BYTES say instead.
            let content_type = crate::media_type::resolve(&claimed, &filename, &bytes);
            file_data = Some((filename, content_type, bytes.to_vec()));
        }
    }

    let data = file_data.ok_or_else(|| ApiError::BadRequest("Missing 'file' field".to_string()))?;

    // FR-32 P1b — plan `storage_bytes` cap. Uses the DELTA form: a tenant at
    // 99 MB of 100 MB must be refused a 10 MB file and ALLOWED a 100 KB one,
    // which a bare "are you at the cap" test cannot express. The size is only
    // knowable here, after the multipart body has been read.
    {
        let tenant = state.tenants.base.find_by_id(tid).await?;
        let current = state.files.sum_storage_for_tenant(tid).await?;
        // FR-102 P4 — through core, which also counts the collision per org.
        if let Err(d) = meshharbor_core::quota::check_delta(
            &state,
            &tenant,
            quota::Limit::StorageBytes,
            current,
            data.2.len() as u64,
        ) {
            return Err(ApiError::Forbidden(d.message()));
        }
    }

    let resp = do_upload(&state, tid, rid, auth.user_id, data).await?;
    Ok(Json(resp))
}

#[cfg(test)]
mod content_disposition_tests {
    use super::sanitize_content_disposition_filename;

    #[test]
    fn strips_crlf_and_quotes() {
        // Hostile name: CR/LF would split the header; embedded quote
        // would terminate the quoted-string early.
        let raw = "evil\r\nX-Injected: 1\"\".txt";
        let (ascii, _) = sanitize_content_disposition_filename(raw);
        assert!(!ascii.contains('\r'));
        assert!(!ascii.contains('\n'));
        assert!(!ascii.contains('"'));
    }

    #[test]
    fn empty_falls_back_to_download() {
        let (ascii, encoded) = sanitize_content_disposition_filename("");
        assert_eq!(ascii, "download");
        assert_eq!(encoded, "download");
    }

    #[test]
    fn unicode_preserved_in_rfc5987_dropped_in_ascii() {
        // 'é' is 0xC3 0xA9 in UTF-8 → percent-encoded as %C3%A9.
        let (ascii, encoded) = sanitize_content_disposition_filename("résumé.pdf");
        assert!(!ascii.is_empty());
        // ASCII fallback replaces non-ASCII with `_` so the legacy
        // `filename=` token stays HTTP-safe.
        assert!(ascii.contains('_'));
        assert!(encoded.contains("%C3%A9"));
    }

    #[test]
    fn percent_itself_is_encoded() {
        // `%` is NOT an RFC 5987 attr-char, so a literal `%` in the
        // source filename must come out as `%25` — a name that LOOKS
        // pre-encoded ("%50off.txt") double-encodes to "%2550off.txt"
        // and round-trips back to the literal, closing the
        // smuggle-a-percent-sequence hole.
        let (_, encoded) = sanitize_content_disposition_filename("%50off.txt");
        assert!(encoded.contains("%2550off"));
    }
}
