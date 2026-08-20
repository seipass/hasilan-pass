use axum::{
    Json,
    extract::{Query, State},
};
use hasilan_protocol::{ChangeOperation, EncryptedObject, SyncChange, SyncResponse};
use serde::Deserialize;
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthSession,
    error::AppError,
    state::AppState,
    token::{decode_cursor, encode_cursor},
};

const DEFAULT_PAGE_SIZE: u32 = 200;
const MAX_PAGE_SIZE: u32 = 500;

/// Sync query string.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct SyncQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(FromRow)]
struct ChangeRow {
    revision: i64,
    object_id: Uuid,
    operation: i16,
    snapshot: Option<Value>,
}

/// Returns an ordered page of opaque encrypted changes.
#[utoipa::path(
    get,
    path = "/api/v1/sync",
    params(SyncQuery),
    security(("bearer" = [])),
    responses((status = 200, body = SyncResponse), (status = 400, body = hasilan_protocol::ApiErrorBody)),
    tag = "synchronization"
)]
pub async fn sync(
    State(state): State<AppState>,
    session: AuthSession,
    Query(query): Query<SyncQuery>,
) -> Result<Json<SyncResponse>, AppError> {
    let after_revision = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor(cursor, session.account_id, &state.config.token_pepper))
        .transpose()?
        .unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(AppError::invalid(
            "invalid_page_size",
            "Sync page size is outside the supported range.",
        ));
    }
    let fetch_limit = i64::from(limit) + 1;
    let rows = sqlx::query_as::<_, ChangeRow>(
        r"
        SELECT revision, object_id, operation, snapshot
        FROM vault_changes
        WHERE account_id = $1 AND revision > $2
        ORDER BY revision ASC
        LIMIT $3
        ",
    )
    .bind(session.account_id)
    .bind(after_revision)
    .bind(fetch_limit)
    .fetch_all(&state.pool)
    .await?;
    let has_more = rows.len() > limit as usize;
    let mut changes = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows.into_iter().take(limit as usize) {
        let operation = match row.operation {
            0 => ChangeOperation::Upsert,
            1 => ChangeOperation::Delete,
            _ => return Err(AppError::internal()),
        };
        let object = row
            .snapshot
            .map(serde_json::from_value::<EncryptedObject>)
            .transpose()
            .map_err(|_| AppError::internal())?;
        if object.as_ref().is_some_and(|object| {
            object.id != row.object_id || object.account_revision != row.revision
        }) {
            return Err(AppError::internal());
        }
        changes.push(SyncChange {
            revision: row.revision,
            operation,
            object_id: row.object_id,
            object,
        });
    }
    let next_revision = if let Some(last) = changes.last() {
        last.revision
    } else {
        sqlx::query_scalar::<_, i64>(
            "SELECT current_revision FROM account_revisions WHERE account_id = $1",
        )
        .bind(session.account_id)
        .fetch_one(&state.pool)
        .await?
        .max(after_revision)
    };
    Ok(Json(SyncResponse {
        changes,
        next_cursor: encode_cursor(
            session.account_id,
            next_revision,
            &state.config.token_pepper,
        ),
        has_more,
    }))
}
