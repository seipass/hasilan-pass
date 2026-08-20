use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use hasilan_protocol::{
    DeleteObjectRequest, EncryptedObject, ObjectKind, OwnerType, PutObjectRequest,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{auth::AuthSession, error::AppError, organizations, state::AppState};

const MAX_WRAPPED_KEY_BYTES: usize = 16 * 1024;
const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_COLLECTIONS: usize = 100;

#[derive(FromRow)]
struct ObjectRow {
    account_id: Uuid,
    id: Uuid,
    kind: i16,
    owner_type: i16,
    owner_id: Uuid,
    collection_ids: Vec<Uuid>,
    format: String,
    wrapped_key: String,
    payload: String,
    object_revision: i64,
    account_revision: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
}

impl TryFrom<ObjectRow> for EncryptedObject {
    type Error = AppError;

    fn try_from(row: ObjectRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            kind: kind_from_db(row.kind)?,
            owner_type: owner_from_db(row.owner_type)?,
            owner_id: row.owner_id,
            collection_ids: row.collection_ids,
            format: row.format,
            wrapped_key: row.wrapped_key,
            payload: row.payload,
            object_revision: row.object_revision,
            account_revision: row.account_revision,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        })
    }
}

/// Fetches one encrypted object owned by the authenticated account.
#[utoipa::path(
    get,
    path = "/api/v1/vault/objects/{id}",
    params(("id" = Uuid, Path, description = "Object ID")),
    security(("bearer" = [])),
    responses((status = 200, body = EncryptedObject), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "vault"
)]
pub async fn get_object(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<Uuid>,
) -> Result<Json<EncryptedObject>, AppError> {
    let row = fetch_object_global(&state.pool, id)
        .await?
        .ok_or_else(not_found)?;
    let mut object: EncryptedObject = row.try_into()?;
    match object.owner_type {
        OwnerType::User => {
            if object.owner_id != session.account_id {
                return Err(not_found());
            }
        }
        OwnerType::Organization => {
            let mut transaction = state.pool.begin().await?;
            let acl =
                organizations::member_acl(&mut transaction, object.owner_id, session.account_id)
                    .await
                    .map_err(|_| not_found())?;
            if !acl.can_read(&object.collection_ids) {
                return Err(not_found());
            }
            if let Some(revision) = sqlx::query_scalar::<_, i64>(
                r"
                SELECT revision FROM vault_changes
                WHERE account_id = $1 AND object_id = $2
                ORDER BY revision DESC LIMIT 1
                ",
            )
            .bind(session.account_id)
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await?
            {
                object.account_revision = revision;
            }
            transaction.commit().await?;
        }
    }
    Ok(Json(object))
}

/// Creates or updates an opaque client-encrypted object.
#[utoipa::path(
    put,
    path = "/api/v1/vault/objects/{id}",
    params(("id" = Uuid, Path, description = "Client-generated object ID")),
    security(("bearer" = [])),
    request_body = PutObjectRequest,
    responses((status = 200, body = EncryptedObject), (status = 409, body = hasilan_protocol::ConflictResponse)),
    tag = "vault"
)]
pub async fn put_object(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<Uuid>,
    Json(request): Json<PutObjectRequest>,
) -> Result<Json<EncryptedObject>, AppError> {
    validate_put(&request, session.account_id)?;
    let request_hash = request_hash(b"put", id, &request)?;
    let mut transaction = state.pool.begin().await?;
    lock_object_id(&mut transaction, id).await?;
    if let Some(cached) = cached_idempotent_response(
        &mut transaction,
        session.account_id,
        request.idempotency_key,
        &request_hash,
    )
    .await?
    {
        transaction.commit().await?;
        return Ok(Json(cached));
    }
    let object = match request.owner_type {
        OwnerType::User => {
            put_personal_object(&mut transaction, session.account_id, id, &request).await?
        }
        OwnerType::Organization => {
            put_organization_object(&mut transaction, session.account_id, id, &request).await?
        }
    };
    cache_idempotent_response(
        &mut transaction,
        session.account_id,
        request.idempotency_key,
        &request_hash,
        &object,
    )
    .await?;
    transaction.commit().await?;
    tracing::info!(account.id = %session.account_id, object.id = %id, revision = object.account_revision, "encrypted vault object committed");
    Ok(Json(object))
}

/// Creates a revisioned tombstone while retaining encrypted trash content.
#[utoipa::path(
    delete,
    path = "/api/v1/vault/objects/{id}",
    params(("id" = Uuid, Path, description = "Object ID")),
    security(("bearer" = [])),
    request_body = DeleteObjectRequest,
    responses((status = 200, body = EncryptedObject), (status = 409, body = hasilan_protocol::ConflictResponse)),
    tag = "vault"
)]
pub async fn delete_object(
    State(state): State<AppState>,
    session: AuthSession,
    Path(id): Path<Uuid>,
    Json(request): Json<DeleteObjectRequest>,
) -> Result<Json<EncryptedObject>, AppError> {
    if request.base_revision <= 0 {
        return Err(AppError::invalid(
            "invalid_revision",
            "A positive base revision is required.",
        ));
    }
    let request_hash = request_hash(b"delete", id, &request)?;
    let mut transaction = state.pool.begin().await?;
    lock_object_id(&mut transaction, id).await?;
    if let Some(cached) = cached_idempotent_response(
        &mut transaction,
        session.account_id,
        request.idempotency_key,
        &request_hash,
    )
    .await?
    {
        transaction.commit().await?;
        return Ok(Json(cached));
    }
    let row = fetch_object_global_for_update(&mut transaction, id)
        .await?
        .ok_or_else(not_found)?;
    let storage_account_id = row.account_id;
    let current: EncryptedObject = row.try_into()?;
    let object = match current.owner_type {
        OwnerType::User => {
            delete_personal_object(
                &mut transaction,
                session.account_id,
                storage_account_id,
                current,
                &request,
            )
            .await?
        }
        OwnerType::Organization => {
            delete_organization_object(
                &mut transaction,
                session.account_id,
                storage_account_id,
                current,
                &request,
            )
            .await?
        }
    };
    cache_idempotent_response(
        &mut transaction,
        session.account_id,
        request.idempotency_key,
        &request_hash,
        &object,
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(object))
}

async fn put_personal_object(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    id: Uuid,
    request: &PutObjectRequest,
) -> Result<EncryptedObject, AppError> {
    let current_revision = lock_account_revision(transaction, account_id).await?;
    let row = fetch_object_global_for_update(transaction, id).await?;
    let current = if let Some(row) = row {
        if row.account_id != account_id {
            return Err(object_id_unavailable());
        }
        let object: EncryptedObject = row.try_into()?;
        if object.owner_type != OwnerType::User || object.owner_id != account_id {
            return Err(object_id_unavailable());
        }
        Some(object)
    } else {
        None
    };
    let account_revision = current_revision
        .checked_add(1)
        .ok_or_else(AppError::internal)?;
    let object = build_put_object(id, request, current.as_ref(), account_revision)?;
    persist_object(transaction, account_id, &object).await?;
    update_account_revision(transaction, account_id, account_revision).await?;
    append_change(transaction, account_id, &object, 0).await?;
    Ok(object)
}

async fn put_organization_object(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    id: Uuid,
    request: &PutObjectRequest,
) -> Result<EncryptedObject, AppError> {
    organizations::lock_organization(transaction, request.owner_id).await?;
    organizations::validate_collection_ids(transaction, request.owner_id, &request.collection_ids)
        .await?;
    let actor = organizations::member_acl(transaction, request.owner_id, account_id).await?;
    let row = fetch_object_global_for_update(transaction, id).await?;
    let (storage_account_id, current) = if let Some(row) = row {
        let storage_account_id = row.account_id;
        let object: EncryptedObject = row.try_into()?;
        if object.owner_type != OwnerType::Organization || object.owner_id != request.owner_id {
            return Err(object_id_unavailable());
        }
        (storage_account_id, Some(object))
    } else {
        (account_id, None)
    };
    if !actor.can_write(&request.collection_ids)
        || current
            .as_ref()
            .is_some_and(|object| !actor.can_write(&object.collection_ids))
        || (request.kind == ObjectKind::OrganizationKey
            && !matches!(
                actor.role,
                hasilan_protocol::OrganizationRole::Owner
                    | hasilan_protocol::OrganizationRole::Admin
            ))
    {
        return Err(organization_write_forbidden());
    }
    let members = organizations::confirmed_member_acls(transaction, request.owner_id).await?;
    let affected: Vec<_> = members
        .iter()
        .filter(|member| {
            member.can_read(&request.collection_ids)
                || current.as_ref().is_some_and(|object| {
                    object.deleted_at.is_none() && member.can_read(&object.collection_ids)
                })
        })
        .collect();
    let account_ids: Vec<_> = affected.iter().map(|member| member.account_id).collect();
    let revisions = allocate_account_revisions(transaction, &account_ids).await?;
    let account_revision = revisions
        .get(&account_id)
        .copied()
        .ok_or_else(AppError::internal)?;
    let object = build_put_object(id, request, current.as_ref(), account_revision)?;
    persist_object(transaction, storage_account_id, &object).await?;
    for member in affected {
        let revision = revisions
            .get(&member.account_id)
            .copied()
            .ok_or_else(AppError::internal)?;
        if member.can_read(&object.collection_ids) {
            let mut snapshot = object.clone();
            snapshot.account_revision = revision;
            append_change(transaction, member.account_id, &snapshot, 0).await?;
        } else {
            append_delete_change(transaction, member.account_id, id, revision).await?;
        }
        update_account_revision(transaction, member.account_id, revision).await?;
    }
    Ok(object)
}

fn build_put_object(
    id: Uuid,
    request: &PutObjectRequest,
    current: Option<&EncryptedObject>,
    account_revision: i64,
) -> Result<EncryptedObject, AppError> {
    let now = Utc::now();
    match (request.base_revision, current) {
        (None, None) => Ok(EncryptedObject {
            id,
            kind: request.kind,
            owner_type: request.owner_type,
            owner_id: request.owner_id,
            collection_ids: request.collection_ids.clone(),
            format: request.format.clone(),
            wrapped_key: request.wrapped_key.clone(),
            payload: request.payload.clone(),
            object_revision: 1,
            account_revision,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }),
        (Some(base), Some(current)) => {
            if current.object_revision != base
                || current.deleted_at.is_some()
                || current.kind != request.kind
                || current.owner_type != request.owner_type
                || current.owner_id != request.owner_id
            {
                return Err(conflict(current)?);
            }
            Ok(EncryptedObject {
                id,
                kind: request.kind,
                owner_type: request.owner_type,
                owner_id: request.owner_id,
                collection_ids: request.collection_ids.clone(),
                format: request.format.clone(),
                wrapped_key: request.wrapped_key.clone(),
                payload: request.payload.clone(),
                object_revision: current
                    .object_revision
                    .checked_add(1)
                    .ok_or_else(AppError::internal)?,
                account_revision,
                created_at: current.created_at,
                updated_at: now,
                deleted_at: None,
            })
        }
        (_, Some(current)) => Err(conflict(current)?),
        (Some(_), None) => Err(not_found()),
    }
}

async fn delete_personal_object(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    storage_account_id: Uuid,
    mut object: EncryptedObject,
    request: &DeleteObjectRequest,
) -> Result<EncryptedObject, AppError> {
    if storage_account_id != account_id
        || object.owner_type != OwnerType::User
        || object.owner_id != account_id
    {
        return Err(not_found());
    }
    validate_delete_revision(&object, request.base_revision)?;
    let current_revision = lock_account_revision(transaction, account_id).await?;
    object.object_revision = object
        .object_revision
        .checked_add(1)
        .ok_or_else(AppError::internal)?;
    object.account_revision = current_revision
        .checked_add(1)
        .ok_or_else(AppError::internal)?;
    object.updated_at = Utc::now();
    object.deleted_at = Some(object.updated_at);
    persist_object(transaction, storage_account_id, &object).await?;
    update_account_revision(transaction, account_id, object.account_revision).await?;
    append_change(transaction, account_id, &object, 1).await?;
    Ok(object)
}

async fn delete_organization_object(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    storage_account_id: Uuid,
    mut object: EncryptedObject,
    request: &DeleteObjectRequest,
) -> Result<EncryptedObject, AppError> {
    organizations::lock_organization(transaction, object.owner_id).await?;
    let actor = organizations::member_acl(transaction, object.owner_id, account_id).await?;
    if !actor.can_write(&object.collection_ids) {
        return Err(organization_write_forbidden());
    }
    validate_delete_revision(&object, request.base_revision)?;
    let members = organizations::confirmed_member_acls(transaction, object.owner_id).await?;
    let readers: Vec<_> = members
        .iter()
        .filter(|member| member.can_read(&object.collection_ids))
        .collect();
    let account_ids: Vec<_> = readers.iter().map(|member| member.account_id).collect();
    let revisions = allocate_account_revisions(transaction, &account_ids).await?;
    object.object_revision = object
        .object_revision
        .checked_add(1)
        .ok_or_else(AppError::internal)?;
    object.account_revision = revisions
        .get(&account_id)
        .copied()
        .ok_or_else(AppError::internal)?;
    object.updated_at = Utc::now();
    object.deleted_at = Some(object.updated_at);
    persist_object(transaction, storage_account_id, &object).await?;
    for member in readers {
        let revision = revisions
            .get(&member.account_id)
            .copied()
            .ok_or_else(AppError::internal)?;
        let mut snapshot = object.clone();
        snapshot.account_revision = revision;
        append_change(transaction, member.account_id, &snapshot, 1).await?;
        update_account_revision(transaction, member.account_id, revision).await?;
    }
    Ok(object)
}

fn validate_delete_revision(object: &EncryptedObject, base_revision: i64) -> Result<(), AppError> {
    if object.object_revision != base_revision || object.deleted_at.is_some() {
        return Err(conflict(object)?);
    }
    Ok(())
}

fn validate_put(request: &PutObjectRequest, account_id: Uuid) -> Result<(), AppError> {
    if request.owner_id.is_nil()
        || (request.owner_type == OwnerType::User && request.owner_id != account_id)
    {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "invalid_owner",
            "The requested object owner is not available.",
        ));
    }
    if request.owner_type == OwnerType::User && !request.collection_ids.is_empty() {
        return Err(AppError::invalid(
            "invalid_collections",
            "Personal objects cannot have collection membership.",
        ));
    }
    if request.collection_ids.len() > MAX_COLLECTIONS
        || request.format != "hp.v1"
        || request.base_revision.is_some_and(|revision| revision <= 0)
    {
        return Err(AppError::invalid(
            "invalid_object",
            "Encrypted object metadata is invalid.",
        ));
    }
    validate_enc_string(&request.wrapped_key, MAX_WRAPPED_KEY_BYTES)?;
    validate_enc_string(&request.payload, MAX_PAYLOAD_BYTES)?;
    Ok(())
}

fn validate_enc_string(value: &str, maximum: usize) -> Result<(), AppError> {
    if value.len() > maximum || !value.starts_with("2.") {
        return Err(invalid_encrypted());
    }
    let parts: Vec<&str> = value[2..].split('|').collect();
    if parts.len() != 3 {
        return Err(invalid_encrypted());
    }
    let iv = STANDARD.decode(parts[0]).map_err(|_| invalid_encrypted())?;
    let ciphertext = STANDARD.decode(parts[1]).map_err(|_| invalid_encrypted())?;
    let mac = STANDARD.decode(parts[2]).map_err(|_| invalid_encrypted())?;
    if iv.len() != 16
        || mac.len() != 32
        || ciphertext.is_empty()
        || !ciphertext.len().is_multiple_of(16)
    {
        return Err(invalid_encrypted());
    }
    Ok(())
}

fn invalid_encrypted() -> AppError {
    AppError::invalid("invalid_encrypted_value", "Encrypted value is malformed.")
}

async fn lock_account_revision(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT current_revision FROM account_revisions WHERE account_id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn allocate_account_revisions(
    transaction: &mut Transaction<'_, Postgres>,
    account_ids: &[Uuid],
) -> Result<HashMap<Uuid, i64>, AppError> {
    let unique: std::collections::HashSet<_> = account_ids.iter().copied().collect();
    if unique.len() != account_ids.len() || account_ids.is_empty() {
        return Err(AppError::internal());
    }
    let rows = sqlx::query_as::<_, (Uuid, i64)>(
        r"
        SELECT account_id, current_revision
        FROM account_revisions
        WHERE account_id = ANY($1)
        ORDER BY account_id
        FOR UPDATE
        ",
    )
    .bind(account_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != account_ids.len() {
        return Err(AppError::internal());
    }
    rows.into_iter()
        .map(|(account_id, revision)| {
            revision
                .checked_add(1)
                .map(|next| (account_id, next))
                .ok_or_else(AppError::internal)
        })
        .collect()
}

async fn lock_object_id(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(id.to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn update_account_revision(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    revision: i64,
) -> Result<(), AppError> {
    sqlx::query("UPDATE account_revisions SET current_revision = $1 WHERE account_id = $2")
        .bind(revision)
        .bind(account_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn fetch_object_global(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<ObjectRow>, AppError> {
    sqlx::query_as::<_, ObjectRow>(
        r"
        SELECT account_id, id, kind, owner_type, owner_id, collection_ids, format, wrapped_key,
               payload, object_revision, account_revision, created_at, updated_at, deleted_at
        FROM vault_objects WHERE id = $1
        ",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

async fn fetch_object_global_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<ObjectRow>, AppError> {
    sqlx::query_as::<_, ObjectRow>(
        r"
        SELECT account_id, id, kind, owner_type, owner_id, collection_ids, format, wrapped_key,
               payload, object_revision, account_revision, created_at, updated_at, deleted_at
        FROM vault_objects WHERE id = $1 FOR UPDATE
        ",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn persist_object(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    object: &EncryptedObject,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        INSERT INTO vault_objects
            (id, account_id, kind, owner_type, owner_id, collection_ids, format,
             wrapped_key, payload, object_revision, account_revision,
             created_at, updated_at, deleted_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (account_id, id) DO UPDATE SET
            kind = EXCLUDED.kind,
            owner_type = EXCLUDED.owner_type,
            owner_id = EXCLUDED.owner_id,
            collection_ids = EXCLUDED.collection_ids,
            format = EXCLUDED.format,
            wrapped_key = EXCLUDED.wrapped_key,
            payload = EXCLUDED.payload,
            object_revision = EXCLUDED.object_revision,
            account_revision = EXCLUDED.account_revision,
            updated_at = EXCLUDED.updated_at,
            deleted_at = EXCLUDED.deleted_at
        ",
    )
    .bind(object.id)
    .bind(account_id)
    .bind(kind_to_db(object.kind))
    .bind(owner_to_db(object.owner_type))
    .bind(object.owner_id)
    .bind(&object.collection_ids)
    .bind(&object.format)
    .bind(&object.wrapped_key)
    .bind(&object.payload)
    .bind(object.object_revision)
    .bind(object.account_revision)
    .bind(object.created_at)
    .bind(object.updated_at)
    .bind(object.deleted_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn append_change(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    object: &EncryptedObject,
    operation: i16,
) -> Result<(), AppError> {
    let snapshot = serde_json::to_value(object).map_err(|_| AppError::internal())?;
    sqlx::query(
        "INSERT INTO vault_changes (account_id, revision, object_id, operation, snapshot) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(account_id)
    .bind(object.account_revision)
    .bind(object.id)
    .bind(operation)
    .bind(snapshot)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Re-emits the current organization view for one member after an ACL transition.
/// Inaccessible objects become deletion records so an offline cache cannot retain them.
pub(crate) async fn reconcile_organization_member(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    member_id: Uuid,
    account_id: Uuid,
) -> Result<(), AppError> {
    let acl = organizations::member_acl(transaction, organization_id, account_id).await?;
    if acl.member_id != member_id || acl.account_id != account_id {
        return Err(AppError::internal());
    }
    let rows = sqlx::query_as::<_, ObjectRow>(
        r"
        SELECT account_id, id, kind, owner_type, owner_id, collection_ids, format,
               wrapped_key, payload, object_revision, account_revision, created_at,
               updated_at, deleted_at
        FROM vault_objects
        WHERE owner_type = 1 AND owner_id = $1
        ORDER BY id
        ",
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let latest = sqlx::query_as::<_, (Uuid, i16)>(
        r"
        SELECT DISTINCT ON (c.object_id) c.object_id, c.operation
        FROM vault_changes c
        JOIN vault_objects o ON o.id = c.object_id
        WHERE c.account_id = $1 AND o.owner_type = 1 AND o.owner_id = $2
        ORDER BY c.object_id, c.revision DESC
        ",
    )
    .bind(account_id)
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .collect::<HashMap<_, _>>();
    let mut transitions = Vec::new();
    for row in rows {
        let object: EncryptedObject = row.try_into()?;
        let was_visible = latest
            .get(&object.id)
            .is_some_and(|operation| *operation == 0);
        let is_visible = object.deleted_at.is_none() && acl.can_read(&object.collection_ids);
        if was_visible != is_visible {
            transitions.push((object, is_visible));
        }
    }
    if transitions.is_empty() {
        return Ok(());
    }
    let mut revision = lock_account_revision(transaction, account_id).await?;
    for (mut object, is_visible) in transitions {
        revision = revision.checked_add(1).ok_or_else(AppError::internal)?;
        if is_visible {
            object.account_revision = revision;
            append_change(transaction, account_id, &object, 0).await?;
        } else {
            append_delete_change(transaction, account_id, object.id, revision).await?;
        }
    }
    update_account_revision(transaction, account_id, revision).await
}

async fn append_delete_change(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    object_id: Uuid,
    revision: i64,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO vault_changes (account_id, revision, object_id, operation, snapshot) VALUES ($1, $2, $3, 1, NULL)",
    )
    .bind(account_id)
    .bind(revision)
    .bind(object_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn cached_idempotent_response(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    key: Uuid,
    request_hash: &[u8],
) -> Result<Option<EncryptedObject>, AppError> {
    let row = sqlx::query_as::<_, (Vec<u8>, Value)>(
        "SELECT request_hash, response FROM idempotency_requests WHERE account_id = $1 AND idempotency_key = $2",
    )
    .bind(account_id)
    .bind(key)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((stored_hash, response)) = row else {
        return Ok(None);
    };
    if stored_hash.as_slice().ct_eq(request_hash).unwrap_u8() != 1 {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "idempotency_key_reused",
            "The idempotency key was used for a different request.",
        ));
    }
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| AppError::internal())
}

async fn cache_idempotent_response(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    key: Uuid,
    request_hash: &[u8],
    object: &EncryptedObject,
) -> Result<(), AppError> {
    let response = serde_json::to_value(object).map_err(|_| AppError::internal())?;
    sqlx::query(
        "INSERT INTO idempotency_requests (account_id, idempotency_key, request_hash, response) VALUES ($1, $2, $3, $4)",
    )
    .bind(account_id)
    .bind(key)
    .bind(request_hash)
    .bind(response)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn request_hash<T: Serialize>(method: &[u8], id: Uuid, request: &T) -> Result<Vec<u8>, AppError> {
    let mut encoded =
        Zeroizing::new(serde_json::to_vec(request).map_err(|_| AppError::internal())?);
    let mut digest = Sha256::new();
    digest.update(method);
    digest.update(id.as_bytes());
    digest.update(encoded.as_slice());
    encoded.zeroize();
    Ok(digest.finalize().to_vec())
}

fn conflict(object: &EncryptedObject) -> Result<AppError, AppError> {
    let value = serde_json::to_value(object).map_err(|_| AppError::internal())?;
    Ok(AppError::conflict(&value))
}

fn not_found() -> AppError {
    AppError::new(
        StatusCode::NOT_FOUND,
        "object_not_found",
        "Vault object not found.",
    )
}

fn object_id_unavailable() -> AppError {
    AppError::new(
        StatusCode::CONFLICT,
        "object_id_unavailable",
        "The vault object ID is unavailable.",
    )
}

fn organization_write_forbidden() -> AppError {
    AppError::new(
        StatusCode::FORBIDDEN,
        "organization_write_forbidden",
        "The organization object cannot be changed with the current collection access.",
    )
}

fn kind_to_db(kind: ObjectKind) -> i16 {
    match kind {
        ObjectKind::Cipher => 0,
        ObjectKind::Folder => 1,
        ObjectKind::OrganizationKey => 2,
    }
}

fn kind_from_db(value: i16) -> Result<ObjectKind, AppError> {
    match value {
        0 => Ok(ObjectKind::Cipher),
        1 => Ok(ObjectKind::Folder),
        2 => Ok(ObjectKind::OrganizationKey),
        _ => Err(AppError::internal()),
    }
}

fn owner_to_db(owner: OwnerType) -> i16 {
    match owner {
        OwnerType::User => 0,
        OwnerType::Organization => 1,
    }
}

fn owner_from_db(value: i16) -> Result<OwnerType, AppError> {
    match value {
        0 => Ok(OwnerType::User),
        1 => Ok(OwnerType::Organization),
        _ => Err(AppError::internal()),
    }
}
