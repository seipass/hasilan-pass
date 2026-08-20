use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use hasilan_protocol::{
    AttachmentChunkRange, AttachmentCompleteRequest, AttachmentInitiateRequest, AttachmentResponse,
    AttachmentState,
};
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::{auth::AuthSession, error::AppError, organizations, state::AppState};

const FORMAT: &str = "hp-attachment.v1";
const TAG_BYTES: u64 = 16;
const MIN_CHUNK_SIZE: u32 = 64 * 1024;
const MAX_CHUNK_SIZE: u32 = 2 * 1024 * 1024;
const MAX_CHUNKS: u32 = 100_000;
const MAX_ATTACHMENTS_PER_OBJECT: i64 = 100;

#[derive(Clone, FromRow)]
struct AttachmentRow {
    id: Uuid,
    object_id: Uuid,
    uploader_account_id: Uuid,
    object_revision: i64,
    format: String,
    chunk_size: i32,
    chunk_count: i32,
    ciphertext_size: i64,
    state: i16,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, FromRow)]
struct ObjectAccessRow {
    kind: i16,
    owner_type: i16,
    owner_id: Uuid,
    collection_ids: Vec<Uuid>,
    object_revision: i64,
    deleted_at: Option<DateTime<Utc>>,
}

/// Starts a retry-safe opaque attachment upload tied to an existing writable Cipher.
#[utoipa::path(
    post,
    path = "/api/v1/attachments",
    security(("bearer" = [])),
    request_body = AttachmentInitiateRequest,
    responses((status = 201, body = AttachmentResponse), (status = 409, body = hasilan_protocol::ApiErrorBody)),
    tag = "attachments"
)]
pub async fn initiate(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<AttachmentInitiateRequest>,
) -> Result<(StatusCode, Json<AttachmentResponse>), AppError> {
    validate_initiate(&request, state.config.attachment_max_bytes)?;
    let mut transaction = state.pool.begin().await?;
    cleanup_expired(&mut transaction).await?;
    authorize_object(
        &mut transaction,
        request.object_id,
        session.account_id,
        true,
        Some(request.object_revision),
    )
    .await?;
    if let Some(existing) = fetch_attachment_for_update(&mut transaction, request.id).await? {
        if existing.object_id != request.object_id
            || existing.uploader_account_id != session.account_id
            || existing.object_revision != request.object_revision
            || existing.format != request.format
            || existing.chunk_size != i32::try_from(request.chunk_size).unwrap_or(-1)
            || existing.chunk_count != i32::try_from(request.chunk_count).unwrap_or(-1)
            || existing.ciphertext_size != i64::try_from(request.ciphertext_size).unwrap_or(-1)
        {
            return Err(attachment_id_conflict());
        }
        let response = attachment_response(&mut transaction, existing).await?;
        transaction.commit().await?;
        return Ok((StatusCode::OK, Json(response)));
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM attachment_uploads WHERE object_id = $1",
    )
    .bind(request.object_id)
    .fetch_one(&mut *transaction)
    .await?;
    if count >= MAX_ATTACHMENTS_PER_OBJECT {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "attachment_limit",
            "The vault item has reached its attachment limit.",
        ));
    }
    sqlx::query(
        r"
        INSERT INTO attachment_uploads
            (id, object_id, uploader_account_id, object_revision, format,
             chunk_size, chunk_count, ciphertext_size)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(request.id)
    .bind(request.object_id)
    .bind(session.account_id)
    .bind(request.object_revision)
    .bind(&request.format)
    .bind(i32::try_from(request.chunk_size).map_err(|_| invalid_attachment())?)
    .bind(i32::try_from(request.chunk_count).map_err(|_| invalid_attachment())?)
    .bind(i64::try_from(request.ciphertext_size).map_err(|_| invalid_attachment())?)
    .execute(&mut *transaction)
    .await?;
    let row = fetch_attachment_for_update(&mut transaction, request.id)
        .await?
        .ok_or_else(AppError::internal)?;
    let response = attachment_response(&mut transaction, row).await?;
    transaction.commit().await?;
    tracing::info!(account.id = %session.account_id, object.id = %request.object_id, attachment.id = %request.id, "encrypted attachment upload initiated");
    Ok((StatusCode::CREATED, Json(response)))
}

/// Lists complete attachments and the caller's resumable uploads for one readable object.
#[utoipa::path(
    get,
    path = "/api/v1/vault/objects/{object_id}/attachments",
    params(("object_id" = Uuid, Path, description = "Parent vault object ID")),
    security(("bearer" = [])),
    responses((status = 200, body = [AttachmentResponse])),
    tag = "attachments"
)]
pub async fn list_for_object(
    State(state): State<AppState>,
    session: AuthSession,
    Path(object_id): Path<Uuid>,
) -> Result<Json<Vec<AttachmentResponse>>, AppError> {
    let mut transaction = state.pool.begin().await?;
    cleanup_expired(&mut transaction).await?;
    authorize_object(&mut transaction, object_id, session.account_id, false, None).await?;
    let rows = sqlx::query_as::<_, AttachmentRow>(
        r"
        SELECT id, object_id, uploader_account_id, object_revision, format, chunk_size,
               chunk_count, ciphertext_size, state, created_at, updated_at,
               completed_at, expires_at
        FROM attachment_uploads
        WHERE object_id = $1 AND (state = 1 OR uploader_account_id = $2)
        ORDER BY created_at, id
        ",
    )
    .bind(object_id)
    .bind(session.account_id)
    .fetch_all(&mut *transaction)
    .await?;
    let mut responses = Vec::with_capacity(rows.len());
    for row in rows {
        responses.push(attachment_response(&mut transaction, row).await?);
    }
    transaction.commit().await?;
    Ok(Json(responses))
}

/// Returns uploaded ranges so an interrupted client can resume at chunk boundaries.
#[utoipa::path(
    get,
    path = "/api/v1/attachments/{id}",
    params(("id" = Uuid, Path, description = "Attachment ID")),
    security(("bearer" = [])),
    responses((status = 200, body = AttachmentResponse), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "attachments"
)]
pub async fn status(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<Uuid>,
) -> Result<Json<AttachmentResponse>, AppError> {
    let mut transaction = state.pool.begin().await?;
    cleanup_expired(&mut transaction).await?;
    let row = fetch_attachment(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    authorize_object(
        &mut transaction,
        row.object_id,
        session.account_id,
        false,
        None,
    )
    .await?;
    if row.state == 0 && row.uploader_account_id != session.account_id {
        return Err(attachment_not_found());
    }
    let response = attachment_response(&mut transaction, row).await?;
    transaction.commit().await?;
    Ok(Json(response))
}

/// Stores one bounded ciphertext frame idempotently.
#[utoipa::path(
    put,
    path = "/api/v1/attachments/{id}/chunks/{index}",
    params(("id" = Uuid, Path, description = "Attachment ID"), ("index" = u32, Path, description = "Zero-based chunk index")),
    security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 204), (status = 409, body = hasilan_protocol::ApiErrorBody)),
    tag = "attachments"
)]
pub async fn put_chunk(
    State(state): State<AppState>,
    session: AuthSession,
    Path((id, index)): Path<(Uuid, u32)>,
    bytes: Bytes,
) -> Result<StatusCode, AppError> {
    let mut transaction = state.pool.begin().await?;
    let preliminary = fetch_attachment(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    authorize_object(
        &mut transaction,
        preliminary.object_id,
        session.account_id,
        true,
        None,
    )
    .await?;
    let row = fetch_attachment_for_update(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    require_active_uploader(&row, session.account_id)?;
    let expected = expected_ciphertext_len(&row, index)?;
    if bytes.len() != expected {
        return Err(invalid_attachment_chunk());
    }
    let digest = Sha256::digest(&bytes).to_vec();
    if let Some(existing_hash) = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT ciphertext_hash FROM attachment_chunks WHERE attachment_id = $1 AND chunk_index = $2",
    )
    .bind(id)
    .bind(i32::try_from(index).map_err(|_| invalid_attachment_chunk())?)
    .fetch_optional(&mut *transaction)
    .await?
    {
        if existing_hash.ct_eq(&digest).unwrap_u8() != 1 {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "attachment_chunk_conflict",
                "This chunk index already contains different ciphertext.",
            ));
        }
    } else {
        sqlx::query(
            r"
            INSERT INTO attachment_chunks
                (attachment_id, chunk_index, ciphertext, ciphertext_hash)
            VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(id)
        .bind(i32::try_from(index).map_err(|_| invalid_attachment_chunk())?)
        .bind(bytes.as_ref())
        .bind(digest)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "UPDATE attachment_uploads SET updated_at = now(), expires_at = now() + interval '24 hours' WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Atomically verifies completeness and publishes an attachment at the current parent revision.
#[utoipa::path(
    post,
    path = "/api/v1/attachments/{id}/complete",
    params(("id" = Uuid, Path, description = "Attachment ID")),
    security(("bearer" = [])),
    request_body = AttachmentCompleteRequest,
    responses((status = 200, body = AttachmentResponse), (status = 409, body = hasilan_protocol::ApiErrorBody)),
    tag = "attachments"
)]
pub async fn complete(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<Uuid>,
    Json(request): Json<AttachmentCompleteRequest>,
) -> Result<Json<AttachmentResponse>, AppError> {
    if request.object_revision <= 0 {
        return Err(invalid_attachment());
    }
    let mut transaction = state.pool.begin().await?;
    let preliminary = fetch_attachment(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    authorize_object(
        &mut transaction,
        preliminary.object_id,
        session.account_id,
        true,
        (preliminary.state == 0).then_some(request.object_revision),
    )
    .await?;
    let mut row = fetch_attachment_for_update(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    if row.uploader_account_id != session.account_id {
        return Err(attachment_not_found());
    }
    if row.state == 0 {
        require_active_uploader(&row, session.account_id)?;
        let dimensions = sqlx::query_as::<_, (i64, i64)>(
            "SELECT count(*), COALESCE(sum(octet_length(ciphertext)), 0) FROM attachment_chunks WHERE attachment_id = $1",
        )
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
        if dimensions.0 != i64::from(row.chunk_count) || dimensions.1 != row.ciphertext_size {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "attachment_incomplete",
                "All declared encrypted chunks must be uploaded before completion.",
            ));
        }
        sqlx::query(
            r"
            UPDATE attachment_uploads
            SET state = 1, object_revision = $2, updated_at = now(),
                completed_at = now(), expires_at = NULL
            WHERE id = $1
            ",
        )
        .bind(id)
        .bind(request.object_revision)
        .execute(&mut *transaction)
        .await?;
        row = fetch_attachment_for_update(&mut transaction, id)
            .await?
            .ok_or_else(AppError::internal)?;
    }
    let response = attachment_response(&mut transaction, row).await?;
    transaction.commit().await?;
    tracing::info!(account.id = %session.account_id, attachment.id = %id, "encrypted attachment upload completed");
    Ok(Json(response))
}

/// Downloads one independently authenticated ciphertext frame from a complete attachment.
#[utoipa::path(
    get,
    path = "/api/v1/attachments/{id}/chunks/{index}",
    params(("id" = Uuid, Path, description = "Attachment ID"), ("index" = u32, Path, description = "Zero-based chunk index")),
    security(("bearer" = [])),
    responses((status = 200, content_type = "application/octet-stream", body = Vec<u8>), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "attachments"
)]
pub async fn get_chunk(
    State(state): State<AppState>,
    session: AuthSession,
    Path((id, index)): Path<(Uuid, u32)>,
) -> Result<Response, AppError> {
    let mut transaction = state.pool.begin().await?;
    let row = fetch_attachment(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    if row.state != 1 {
        return Err(attachment_not_found());
    }
    authorize_object(
        &mut transaction,
        row.object_id,
        session.account_id,
        false,
        None,
    )
    .await?;
    let expected = expected_ciphertext_len(&row, index)?;
    let ciphertext = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT ciphertext FROM attachment_chunks WHERE attachment_id = $1 AND chunk_index = $2",
    )
    .bind(id)
    .bind(i32::try_from(index).map_err(|_| attachment_not_found())?)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(attachment_not_found)?;
    if ciphertext.len() != expected {
        return Err(AppError::internal());
    }
    transaction.commit().await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_LENGTH, &ciphertext.len().to_string()),
        ],
        ciphertext,
    )
        .into_response())
}

/// Removes opaque chunks after verifying current write access to the parent item.
#[utoipa::path(
    delete,
    path = "/api/v1/attachments/{id}",
    params(("id" = Uuid, Path, description = "Attachment ID")),
    security(("bearer" = [])),
    responses((status = 204), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "attachments"
)]
pub async fn delete_attachment(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut transaction = state.pool.begin().await?;
    let preliminary = fetch_attachment(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    authorize_object(
        &mut transaction,
        preliminary.object_id,
        session.account_id,
        true,
        None,
    )
    .await?;
    let row = fetch_attachment_for_update(&mut transaction, id)
        .await?
        .ok_or_else(attachment_not_found)?;
    if row.object_id != preliminary.object_id {
        return Err(AppError::internal());
    }
    sqlx::query("DELETE FROM attachment_uploads WHERE id = $1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    tracing::info!(account.id = %session.account_id, attachment.id = %id, "encrypted attachment removed");
    Ok(StatusCode::NO_CONTENT)
}

fn validate_initiate(request: &AttachmentInitiateRequest, maximum: u64) -> Result<(), AppError> {
    let full_chunk = u64::from(request.chunk_size)
        .checked_add(TAG_BYTES)
        .ok_or_else(invalid_attachment)?;
    let preceding = u64::from(request.chunk_count.saturating_sub(1))
        .checked_mul(full_chunk)
        .ok_or_else(invalid_attachment)?;
    let minimum = preceding
        .checked_add(TAG_BYTES)
        .ok_or_else(invalid_attachment)?;
    let declared_maximum = u64::from(request.chunk_count)
        .checked_mul(full_chunk)
        .ok_or_else(invalid_attachment)?;
    if request.id.is_nil()
        || request.object_id.is_nil()
        || request.object_revision <= 0
        || request.format != FORMAT
        || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&request.chunk_size)
        || !(1..=MAX_CHUNKS).contains(&request.chunk_count)
        || request.ciphertext_size < minimum
        || request.ciphertext_size > declared_maximum
        || request.ciphertext_size > maximum
    {
        return Err(invalid_attachment());
    }
    Ok(())
}

async fn authorize_object(
    transaction: &mut Transaction<'_, Postgres>,
    object_id: Uuid,
    account_id: Uuid,
    write: bool,
    expected_revision: Option<i64>,
) -> Result<ObjectAccessRow, AppError> {
    let preliminary = fetch_object_access(transaction, object_id, false)
        .await?
        .ok_or_else(attachment_not_found)?;
    if preliminary.owner_type == 1 {
        organizations::lock_organization(transaction, preliminary.owner_id)
            .await
            .map_err(|_| attachment_not_found())?;
    }
    let object = fetch_object_access(transaction, object_id, true)
        .await?
        .ok_or_else(attachment_not_found)?;
    if object.kind != 0 || object.deleted_at.is_some() {
        return Err(attachment_not_found());
    }
    if expected_revision.is_some_and(|revision| revision != object.object_revision) {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "attachment_parent_changed",
            "The parent vault item changed before this attachment operation.",
        ));
    }
    let allowed = match object.owner_type {
        0 => object.owner_id == account_id,
        1 => {
            let acl = organizations::member_acl(transaction, object.owner_id, account_id)
                .await
                .map_err(|_| attachment_not_found())?;
            if write {
                acl.can_write(&object.collection_ids)
            } else {
                acl.can_read(&object.collection_ids)
            }
        }
        _ => return Err(AppError::internal()),
    };
    if !allowed {
        return Err(if write {
            AppError::new(
                StatusCode::FORBIDDEN,
                "attachment_write_forbidden",
                "The attachment cannot be changed with the current item access.",
            )
        } else {
            attachment_not_found()
        });
    }
    Ok(object)
}

async fn fetch_object_access(
    transaction: &mut Transaction<'_, Postgres>,
    object_id: Uuid,
    locked: bool,
) -> Result<Option<ObjectAccessRow>, AppError> {
    let query = if locked {
        r"
        SELECT kind, owner_type, owner_id, collection_ids, object_revision, deleted_at
        FROM vault_objects WHERE id = $1 FOR UPDATE
        "
    } else {
        r"
        SELECT kind, owner_type, owner_id, collection_ids, object_revision, deleted_at
        FROM vault_objects WHERE id = $1
        "
    };
    sqlx::query_as::<_, ObjectAccessRow>(query)
        .bind(object_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(Into::into)
}

async fn fetch_attachment(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<AttachmentRow>, AppError> {
    sqlx::query_as::<_, AttachmentRow>(
        r"
        SELECT id, object_id, uploader_account_id, object_revision, format, chunk_size,
               chunk_count, ciphertext_size, state, created_at, updated_at,
               completed_at, expires_at
        FROM attachment_uploads WHERE id = $1
        ",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn fetch_attachment_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<AttachmentRow>, AppError> {
    sqlx::query_as::<_, AttachmentRow>(
        r"
        SELECT id, object_id, uploader_account_id, object_revision, format, chunk_size,
               chunk_count, ciphertext_size, state, created_at, updated_at,
               completed_at, expires_at
        FROM attachment_uploads WHERE id = $1 FOR UPDATE
        ",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn attachment_response(
    transaction: &mut Transaction<'_, Postgres>,
    row: AttachmentRow,
) -> Result<AttachmentResponse, AppError> {
    let indices = sqlx::query_scalar::<_, i32>(
        "SELECT chunk_index FROM attachment_chunks WHERE attachment_id = $1 ORDER BY chunk_index",
    )
    .bind(row.id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut uploaded_ranges: Vec<AttachmentChunkRange> = Vec::new();
    for index in indices {
        let index = u32::try_from(index).map_err(|_| AppError::internal())?;
        if let Some(last) = uploaded_ranges.last_mut()
            && last.end_exclusive == index
        {
            last.end_exclusive = index.checked_add(1).ok_or_else(AppError::internal)?;
        } else {
            uploaded_ranges.push(AttachmentChunkRange {
                start: index,
                end_exclusive: index.checked_add(1).ok_or_else(AppError::internal)?,
            });
        }
    }
    Ok(AttachmentResponse {
        id: row.id,
        object_id: row.object_id,
        object_revision: row.object_revision,
        format: row.format,
        chunk_size: u32::try_from(row.chunk_size).map_err(|_| AppError::internal())?,
        chunk_count: u32::try_from(row.chunk_count).map_err(|_| AppError::internal())?,
        ciphertext_size: u64::try_from(row.ciphertext_size).map_err(|_| AppError::internal())?,
        state: match row.state {
            0 => AttachmentState::Uploading,
            1 => AttachmentState::Complete,
            _ => return Err(AppError::internal()),
        },
        uploaded_ranges,
        created_at: row.created_at,
        updated_at: row.updated_at,
        completed_at: row.completed_at,
        expires_at: row.expires_at,
    })
}

fn expected_ciphertext_len(row: &AttachmentRow, index: u32) -> Result<usize, AppError> {
    let chunk_count = u32::try_from(row.chunk_count).map_err(|_| AppError::internal())?;
    if index >= chunk_count {
        return Err(invalid_attachment_chunk());
    }
    let full = i64::from(row.chunk_size)
        .checked_add(i64::try_from(TAG_BYTES).unwrap_or(16))
        .ok_or_else(AppError::internal)?;
    let length = if index + 1 < chunk_count {
        full
    } else {
        row.ciphertext_size
            .checked_sub(
                i64::from(chunk_count - 1)
                    .checked_mul(full)
                    .ok_or_else(AppError::internal)?,
            )
            .ok_or_else(AppError::internal)?
    };
    usize::try_from(length).map_err(|_| AppError::internal())
}

fn require_active_uploader(row: &AttachmentRow, account_id: Uuid) -> Result<(), AppError> {
    if row.state != 0 || row.uploader_account_id != account_id {
        return Err(attachment_not_found());
    }
    if row.expires_at.is_none_or(|expires| expires <= Utc::now()) {
        return Err(AppError::new(
            StatusCode::GONE,
            "attachment_upload_expired",
            "The interrupted attachment upload expired.",
        ));
    }
    Ok(())
}

async fn cleanup_expired(transaction: &mut Transaction<'_, Postgres>) -> Result<(), AppError> {
    sqlx::query("DELETE FROM attachment_uploads WHERE state = 0 AND expires_at <= now()")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn invalid_attachment() -> AppError {
    AppError::invalid(
        "invalid_attachment",
        "Encrypted attachment dimensions are invalid.",
    )
}

fn invalid_attachment_chunk() -> AppError {
    AppError::invalid(
        "invalid_attachment_chunk",
        "The encrypted attachment chunk has an invalid index or length.",
    )
}

fn attachment_not_found() -> AppError {
    AppError::new(
        StatusCode::NOT_FOUND,
        "attachment_not_found",
        "Attachment not found.",
    )
}

fn attachment_id_conflict() -> AppError {
    AppError::new(
        StatusCode::CONFLICT,
        "attachment_id_conflict",
        "The attachment ID is already bound to different upload metadata.",
    )
}
