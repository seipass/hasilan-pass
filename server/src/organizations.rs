use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hasilan_protocol::{
    CollectionAccessRequest, CollectionCreateRequest, CollectionResponse, CollectionUpdateRequest,
    InvitationDeliveryKind, MembershipStatus, OrganizationAcceptRequest, OrganizationCreateRequest,
    OrganizationInviteRequest, OrganizationInviteResponse, OrganizationMemberResponse,
    OrganizationMemberRoleRequest, OrganizationResponse, OrganizationRole, SharingKeyRequest,
    SharingKeyResponse,
};
use serde::Deserialize;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    auth::{AuthSession, insert_event, is_unique_violation, normalize_email},
    error::AppError,
    invitation_delivery::Invitation,
    state::AppState,
    token::{generate_token, hash_token},
    vault,
};

const MAX_PROTECTED_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const MAX_ORGANIZATION_KEY_WRAPPER_BYTES: usize = 16 * 1024;
const INVITATION_TTL: ChronoDuration = ChronoDuration::days(7);

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct SharingKeyLookupQuery {
    email: String,
}

#[derive(FromRow)]
struct OrganizationRow {
    id: Uuid,
    member_id: Uuid,
    name: String,
    role: i16,
    status: i16,
    encrypted_organization_key: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct MemberRow {
    id: Uuid,
    account_id: Option<Uuid>,
    email: String,
    role: i16,
    status: i16,
    encrypted_organization_key: Option<String>,
    invited_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, FromRow)]
struct ActorRow {
    id: Uuid,
    role: i16,
    status: i16,
}

#[derive(FromRow)]
struct CollectionRow {
    id: Uuid,
    organization_id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
    read_only: Option<bool>,
    hide_passwords: Option<bool>,
    manage: Option<bool>,
}

/// Stores the account's public sharing key and user-key-encrypted private key.
#[utoipa::path(
    put,
    path = "/api/v1/account/sharing-key",
    security(("bearer" = [])),
    request_body = SharingKeyRequest,
    responses((status = 200, body = SharingKeyResponse), (status = 409, body = hasilan_protocol::ApiErrorBody)),
    tag = "organizations"
)]
pub async fn put_sharing_key(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<SharingKeyRequest>,
) -> Result<Json<SharingKeyResponse>, AppError> {
    validate_public_key(&request.public_key)?;
    validate_enc_string(
        &request.protected_private_key,
        MAX_PROTECTED_PRIVATE_KEY_BYTES,
    )?;
    let updated = sqlx::query_as::<_, (String, String)>(
        r"
        UPDATE accounts
        SET sharing_public_key = $1,
            protected_sharing_private_key = $2,
            updated_at = now()
        WHERE id = $3
          AND (
              sharing_public_key IS NULL
              OR (sharing_public_key = $1 AND protected_sharing_private_key = $2)
              OR NOT EXISTS (
                  SELECT 1 FROM organization_members
                  WHERE account_id = $3 AND status IN (0, 1, 2)
              )
          )
        RETURNING sharing_public_key, protected_sharing_private_key
        ",
    )
    .bind(&request.public_key)
    .bind(&request.protected_private_key)
    .bind(session.account_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((public_key, protected_private_key)) = updated else {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "sharing_key_exists",
            "The sharing key is already installed and cannot be replaced while memberships exist.",
        ));
    };
    Ok(Json(SharingKeyResponse {
        account_id: session.account_id,
        public_key,
        protected_private_key: Some(protected_private_key),
    }))
}

/// Returns the caller's sharing key material; the private key remains encrypted.
#[utoipa::path(
    get,
    path = "/api/v1/account/sharing-key",
    security(("bearer" = [])),
    responses((status = 200, body = SharingKeyResponse), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "organizations"
)]
pub async fn get_sharing_key(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<SharingKeyResponse>, AppError> {
    let row = sqlx::query_as::<_, (String, String)>(
        r"
        SELECT sharing_public_key, protected_sharing_private_key
        FROM accounts
        WHERE id = $1
          AND sharing_public_key IS NOT NULL
          AND protected_sharing_private_key IS NOT NULL
        ",
    )
    .bind(session.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(sharing_key_not_found)?;
    Ok(Json(SharingKeyResponse {
        account_id: session.account_id,
        public_key: row.0,
        protected_private_key: Some(row.1),
    }))
}

/// Resolves an existing recipient's public sharing key without exposing private material.
#[utoipa::path(
    get,
    path = "/api/v1/directory/sharing-key",
    params(SharingKeyLookupQuery),
    security(("bearer" = [])),
    responses((status = 200, body = SharingKeyResponse), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "organizations"
)]
pub async fn lookup_sharing_key(
    State(state): State<AppState>,
    _session: AuthSession,
    Query(query): Query<SharingKeyLookupQuery>,
) -> Result<Json<SharingKeyResponse>, AppError> {
    let email = normalize_email(&query.email)?;
    let row = sqlx::query_as::<_, (Uuid, String)>(
        r"
        SELECT id, sharing_public_key
        FROM accounts
        WHERE email = $1 AND disabled_at IS NULL AND sharing_public_key IS NOT NULL
        ",
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(sharing_key_not_found)?;
    Ok(Json(SharingKeyResponse {
        account_id: row.0,
        public_key: row.1,
        protected_private_key: None,
    }))
}

/// Creates a zero-knowledge organization with a client-generated symmetric key wrapper.
#[utoipa::path(
    post,
    path = "/api/v1/organizations",
    security(("bearer" = [])),
    request_body = OrganizationCreateRequest,
    responses((status = 201, body = OrganizationResponse), (status = 409, body = hasilan_protocol::ApiErrorBody)),
    tag = "organizations"
)]
pub async fn create_organization(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<OrganizationCreateRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), AppError> {
    validate_name(&request.name)?;
    validate_organization_key_wrapper(&request.encrypted_organization_key)?;
    if request.id.is_nil() {
        return Err(AppError::invalid(
            "invalid_organization_id",
            "The organization ID is invalid.",
        ));
    }
    let sharing_key_exists = sqlx::query_scalar::<_, bool>(
        "SELECT sharing_public_key IS NOT NULL FROM accounts WHERE id = $1",
    )
    .bind(session.account_id)
    .fetch_one(&state.pool)
    .await?;
    if !sharing_key_exists {
        return Err(sharing_key_not_found());
    }

    let member_id = Uuid::new_v4();
    let now = Utc::now();
    let mut transaction = state.pool.begin().await?;
    let inserted =
        sqlx::query("INSERT INTO organizations (id, name, created_by) VALUES ($1, $2, $3)")
            .bind(request.id)
            .bind(&request.name)
            .bind(session.account_id)
            .execute(&mut *transaction)
            .await;
    if let Err(error) = inserted {
        if is_unique_violation(&error) {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "organization_exists",
                "The organization ID is already in use.",
            ));
        }
        return Err(error.into());
    }
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM accounts WHERE id = $1")
        .bind(session.account_id)
        .fetch_one(&mut *transaction)
        .await?;
    sqlx::query(
        r"
        INSERT INTO organization_members
            (id, organization_id, account_id, email, role, status,
             encrypted_organization_key, invited_by, accepted_at, confirmed_at)
        VALUES ($1, $2, $3, $4, 0, 2, $5, $3, $6, $6)
        ",
    )
    .bind(member_id)
    .bind(request.id)
    .bind(session.account_id)
    .bind(email)
    .bind(&request.encrypted_organization_key)
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "organization_created",
    )
    .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(OrganizationResponse {
            id: request.id,
            member_id,
            name: request.name,
            role: OrganizationRole::Owner,
            status: MembershipStatus::Confirmed,
            encrypted_organization_key: Some(request.encrypted_organization_key),
            created_at: now,
        }),
    ))
}

/// Lists organizations visible to the authenticated account.
#[utoipa::path(
    get,
    path = "/api/v1/organizations",
    security(("bearer" = [])),
    responses((status = 200, body = Vec<OrganizationResponse>)),
    tag = "organizations"
)]
pub async fn list_organizations(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Vec<OrganizationResponse>>, AppError> {
    let rows = sqlx::query_as::<_, OrganizationRow>(
        r"
        SELECT o.id, m.id AS member_id, o.name, m.role, m.status,
               m.encrypted_organization_key, o.created_at
        FROM organization_members m
        JOIN organizations o ON o.id = m.organization_id
        WHERE m.account_id = $1 AND m.status <> 3
        ORDER BY lower(o.name), o.id
        ",
    )
    .bind(session.account_id)
    .fetch_all(&state.pool)
    .await?;
    rows.into_iter()
        .map(organization_response)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

/// Returns one organization visible to the caller.
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}",
    params(("organization_id" = Uuid, Path)),
    security(("bearer" = [])),
    responses((status = 200, body = OrganizationResponse), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "organizations"
)]
pub async fn get_organization(
    State(state): State<AppState>,
    session: AuthSession,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationResponse>, AppError> {
    let row = sqlx::query_as::<_, OrganizationRow>(
        r"
        SELECT o.id, m.id AS member_id, o.name, m.role, m.status,
               m.encrypted_organization_key, o.created_at
        FROM organization_members m
        JOIN organizations o ON o.id = m.organization_id
        WHERE m.organization_id = $1 AND m.account_id = $2 AND m.status <> 3
        ",
    )
    .bind(organization_id)
    .bind(session.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(organization_not_found)?;
    Ok(Json(organization_response(row)?))
}

/// Invites an existing account using a recipient-specific opaque key wrapper.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/invitations",
    params(("organization_id" = Uuid, Path)),
    security(("bearer" = [])),
    request_body = OrganizationInviteRequest,
    responses((status = 201, body = OrganizationInviteResponse), (status = 403, body = hasilan_protocol::ApiErrorBody)),
    tag = "organizations"
)]
#[allow(
    clippy::too_many_lines,
    reason = "authorization, token persistence, adapter delivery, and commit stay visibly inside one transaction"
)]
pub async fn invite_member(
    State(state): State<AppState>,
    session: AuthSession,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<OrganizationInviteRequest>,
) -> Result<(StatusCode, Json<OrganizationInviteResponse>), AppError> {
    if matches!(request.role, OrganizationRole::Owner) {
        return Err(AppError::invalid(
            "invalid_invitation_role",
            "Owners must be promoted after confirming membership.",
        ));
    }
    validate_organization_key_wrapper(&request.encrypted_organization_key)?;
    let email = normalize_email(&request.email)?;
    let invitation_token = generate_token()?;
    let invitation_hash = hash_token(&invitation_token, &state.config.token_pepper);
    let expires_at = Utc::now() + INVITATION_TTL;
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_admin(actor)?;
    let organization_name =
        sqlx::query_scalar::<_, String>("SELECT name FROM organizations WHERE id = $1")
            .bind(organization_id)
            .fetch_one(&mut *transaction)
            .await?;
    let recipient = sqlx::query_as::<_, (Uuid, String)>(
        r"
        SELECT id, sharing_public_key
        FROM accounts
        WHERE email = $1 AND disabled_at IS NULL AND sharing_public_key IS NOT NULL
        ",
    )
    .bind(&email)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(recipient_unavailable)?;
    if recipient.0 == session.account_id {
        return Err(AppError::invalid(
            "cannot_invite_self",
            "The current account is already a member.",
        ));
    }
    let existing = sqlx::query_as::<_, (Uuid, i16)>(
        r"
        SELECT id, status FROM organization_members
        WHERE organization_id = $1 AND email = $2
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(&email)
    .fetch_optional(&mut *transaction)
    .await?;
    let member_id = existing.map_or_else(Uuid::new_v4, |row| row.0);
    if existing.is_some_and(|row| matches!(row.1, 1 | 2)) {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "member_exists",
            "The account already has an active membership.",
        ));
    }
    sqlx::query(
        r"
        INSERT INTO organization_members
            (id, organization_id, account_id, email, role, status,
             encrypted_organization_key, invited_by, invitation_token_hash,
             invitation_expires_at)
        VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9)
        ON CONFLICT (organization_id, email) DO UPDATE SET
            account_id = EXCLUDED.account_id,
            role = EXCLUDED.role,
            status = 0,
            encrypted_organization_key = EXCLUDED.encrypted_organization_key,
            invited_by = EXCLUDED.invited_by,
            invitation_token_hash = EXCLUDED.invitation_token_hash,
            invitation_expires_at = EXCLUDED.invitation_expires_at,
            invited_at = now(),
            accepted_at = NULL,
            confirmed_at = NULL,
            removed_at = NULL
        ",
    )
    .bind(member_id)
    .bind(organization_id)
    .bind(recipient.0)
    .bind(&email)
    .bind(role_to_db(request.role))
    .bind(&request.encrypted_organization_key)
    .bind(session.account_id)
    .bind(invitation_hash)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "organization_member_invited",
    )
    .await?;
    let delivery = state.invitation_delivery.kind();
    if let Err(error) = state
        .invitation_delivery
        .deliver(&Invitation {
            recipient: &email,
            organization_name: &organization_name,
            token: &invitation_token,
            expires_at,
            public_url: &state.config.public_url,
        })
        .await
    {
        tracing::warn!(
            organization.id = %organization_id,
            delivery.error = ?error,
            "organization invitation delivery failed"
        );
        return Err(AppError::new(
            StatusCode::BAD_GATEWAY,
            "invitation_delivery_failed",
            "The invitation could not be delivered; no invitation was created.",
        ));
    }
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(OrganizationInviteResponse {
            member_id,
            invitation_token: matches!(delivery, InvitationDeliveryKind::Manual)
                .then_some(invitation_token),
            expires_at,
            delivery,
        }),
    ))
}

/// Accepts an unexpired invitation for the authenticated account.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/invitations/accept",
    security(("bearer" = [])),
    request_body = OrganizationAcceptRequest,
    responses((status = 200, body = OrganizationMemberResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "organizations"
)]
pub async fn accept_invitation(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<OrganizationAcceptRequest>,
) -> Result<Json<OrganizationMemberResponse>, AppError> {
    if request.invitation_token.len() > 256 {
        return Err(invalid_invitation());
    }
    let token_hash = hash_token(&request.invitation_token, &state.config.token_pepper);
    let mut transaction = state.pool.begin().await?;
    let invitation = sqlx::query_as::<_, (Uuid, i16, DateTime<Utc>)>(
        r"
        SELECT id, status, invitation_expires_at
        FROM organization_members
        WHERE invitation_token_hash = $1 AND account_id = $2
        FOR UPDATE
        ",
    )
    .bind(token_hash)
    .bind(session.account_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((member_id, status, expires_at)) = invitation else {
        return Err(invalid_invitation());
    };
    if status != 0 || expires_at <= Utc::now() {
        return Err(invalid_invitation());
    }
    sqlx::query(
        r"
        UPDATE organization_members
        SET status = 1, invitation_token_hash = NULL, invitation_expires_at = NULL,
            accepted_at = now()
        WHERE id = $1
        ",
    )
    .bind(member_id)
    .execute(&mut *transaction)
    .await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "organization_invitation_accepted",
    )
    .await?;
    let response = fetch_member(&mut transaction, member_id).await?;
    transaction.commit().await?;
    Ok(Json(response))
}

/// Lists organization members for a confirmed member.
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/members",
    params(("organization_id" = Uuid, Path)),
    security(("bearer" = [])),
    responses((status = 200, body = Vec<OrganizationMemberResponse>)),
    tag = "organizations"
)]
pub async fn list_members(
    State(state): State<AppState>,
    session: AuthSession,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMemberResponse>>, AppError> {
    require_confirmed_membership(&state.pool, organization_id, session.account_id).await?;
    let rows = sqlx::query_as::<_, MemberRow>(
        r"
        SELECT id, account_id, email, role, status, encrypted_organization_key,
               invited_at, accepted_at, confirmed_at
        FROM organization_members
        WHERE organization_id = $1 AND status <> 3
        ORDER BY lower(email), id
        ",
    )
    .bind(organization_id)
    .fetch_all(&state.pool)
    .await?;
    rows.into_iter()
        .map(member_response)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

/// Confirms an accepted member and emits their currently authorized sync snapshots.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/members/{member_id}/confirm",
    params(("organization_id" = Uuid, Path), ("member_id" = Uuid, Path)),
    security(("bearer" = [])),
    responses((status = 200, body = OrganizationMemberResponse)),
    tag = "organizations"
)]
pub async fn confirm_member(
    State(state): State<AppState>,
    session: AuthSession,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<OrganizationMemberResponse>, AppError> {
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_admin(actor)?;
    let target = lock_member(&mut transaction, organization_id, member_id).await?;
    if target.status != 1 || target.account_id.is_none() {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "member_not_accepted",
            "The member must accept the invitation before confirmation.",
        ));
    }
    sqlx::query("UPDATE organization_members SET status = 2, confirmed_at = now() WHERE id = $1")
        .bind(member_id)
        .execute(&mut *transaction)
        .await?;
    vault::reconcile_organization_member(
        &mut transaction,
        organization_id,
        member_id,
        target.account_id.ok_or_else(AppError::internal)?,
    )
    .await?;
    insert_event(
        &mut transaction,
        target.account_id,
        Some(session.device_id),
        "organization_membership_confirmed",
    )
    .await?;
    let response = fetch_member(&mut transaction, member_id).await?;
    transaction.commit().await?;
    Ok(Json(response))
}

/// Changes a confirmed member's role and reconciles their encrypted feed.
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{organization_id}/members/{member_id}/role",
    params(("organization_id" = Uuid, Path), ("member_id" = Uuid, Path)),
    security(("bearer" = [])),
    request_body = OrganizationMemberRoleRequest,
    responses((status = 200, body = OrganizationMemberResponse)),
    tag = "organizations"
)]
pub async fn change_member_role(
    State(state): State<AppState>,
    session: AuthSession,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<OrganizationMemberRoleRequest>,
) -> Result<Json<OrganizationMemberResponse>, AppError> {
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_admin(actor)?;
    let target = lock_member(&mut transaction, organization_id, member_id).await?;
    if target.status != 2 || target.account_id.is_none() {
        return Err(member_not_found());
    }
    let current_role = role_from_db(target.role)?;
    let actor_role = role_from_db(actor.role)?;
    if actor_role != OrganizationRole::Owner
        && (current_role == OrganizationRole::Owner
            || request.role == OrganizationRole::Owner
            || current_role == OrganizationRole::Admin)
    {
        return Err(forbidden());
    }
    if current_role == OrganizationRole::Owner && request.role != OrganizationRole::Owner {
        ensure_another_owner(&mut transaction, organization_id, member_id).await?;
    }
    sqlx::query("UPDATE organization_members SET role = $1 WHERE id = $2")
        .bind(role_to_db(request.role))
        .bind(member_id)
        .execute(&mut *transaction)
        .await?;
    vault::reconcile_organization_member(
        &mut transaction,
        organization_id,
        member_id,
        target.account_id.ok_or_else(AppError::internal)?,
    )
    .await?;
    let response = fetch_member(&mut transaction, member_id).await?;
    transaction.commit().await?;
    Ok(Json(response))
}

/// Removes a member and emits deletion changes for all organization objects.
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/members/{member_id}",
    params(("organization_id" = Uuid, Path), ("member_id" = Uuid, Path)),
    security(("bearer" = [])),
    responses((status = 204)),
    tag = "organizations"
)]
pub async fn remove_member(
    State(state): State<AppState>,
    session: AuthSession,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_admin(actor)?;
    if actor.id == member_id {
        return Err(AppError::invalid(
            "cannot_remove_self",
            "Use a dedicated leave flow to remove your own membership.",
        ));
    }
    let target = lock_member(&mut transaction, organization_id, member_id).await?;
    if target.status == 3 {
        return Err(member_not_found());
    }
    let target_role = role_from_db(target.role)?;
    if role_from_db(actor.role)? != OrganizationRole::Owner
        && matches!(
            target_role,
            OrganizationRole::Owner | OrganizationRole::Admin
        )
    {
        return Err(forbidden());
    }
    if target_role == OrganizationRole::Owner {
        ensure_another_owner(&mut transaction, organization_id, member_id).await?;
    }
    sqlx::query(
        r"
        UPDATE organization_members
        SET status = 3, encrypted_organization_key = NULL,
            invitation_token_hash = NULL, invitation_expires_at = NULL,
            removed_at = now()
        WHERE id = $1
        ",
    )
    .bind(member_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM collection_access WHERE member_id = $1")
        .bind(member_id)
        .execute(&mut *transaction)
        .await?;
    if let Some(account_id) = target.account_id {
        vault::reconcile_organization_member(
            &mut transaction,
            organization_id,
            member_id,
            account_id,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Creates a collection visible to administrators or an explicitly granted manager.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/collections",
    params(("organization_id" = Uuid, Path)),
    security(("bearer" = [])),
    request_body = CollectionCreateRequest,
    responses((status = 201, body = CollectionResponse)),
    tag = "organizations"
)]
pub async fn create_collection(
    State(state): State<AppState>,
    session: AuthSession,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CollectionCreateRequest>,
) -> Result<(StatusCode, Json<CollectionResponse>), AppError> {
    validate_name(&request.name)?;
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    let actor_role = role_from_db(actor.role)?;
    if !matches!(
        actor_role,
        OrganizationRole::Owner | OrganizationRole::Admin | OrganizationRole::Manager
    ) {
        return Err(forbidden());
    }
    let collection_id = Uuid::new_v4();
    let created_at = Utc::now();
    let inserted = sqlx::query(
        r"
        INSERT INTO collections (id, organization_id, name, created_by, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $5)
        ",
    )
    .bind(collection_id)
    .bind(organization_id)
    .bind(&request.name)
    .bind(session.account_id)
    .bind(created_at)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = inserted {
        if is_unique_violation(&error) {
            return Err(collection_name_conflict());
        }
        return Err(error.into());
    }
    if actor_role == OrganizationRole::Manager {
        sqlx::query(
            r"
            INSERT INTO collection_access
                (collection_id, member_id, read_only, hide_passwords, manage)
            VALUES ($1, $2, false, false, true)
            ",
        )
        .bind(collection_id)
        .bind(actor.id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CollectionResponse {
            id: collection_id,
            organization_id,
            name: request.name,
            read_only: false,
            hide_passwords: false,
            manage: true,
            created_at,
        }),
    ))
}

/// Lists collections the caller may read.
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/collections",
    params(("organization_id" = Uuid, Path)),
    security(("bearer" = [])),
    responses((status = 200, body = Vec<CollectionResponse>)),
    tag = "organizations"
)]
pub async fn list_collections(
    State(state): State<AppState>,
    session: AuthSession,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<CollectionResponse>>, AppError> {
    let actor =
        require_confirmed_membership(&state.pool, organization_id, session.account_id).await?;
    let role = role_from_db(actor.role)?;
    let rows = sqlx::query_as::<_, CollectionRow>(
        r"
        SELECT c.id, c.organization_id, c.name, c.created_at,
               a.read_only, a.hide_passwords, a.manage
        FROM collections c
        LEFT JOIN collection_access a
          ON a.collection_id = c.id AND a.member_id = $2
        WHERE c.organization_id = $1
        ORDER BY lower(c.name), c.id
        ",
    )
    .bind(organization_id)
    .bind(actor.id)
    .fetch_all(&state.pool)
    .await?;
    let elevated = matches!(role, OrganizationRole::Owner | OrganizationRole::Admin);
    Ok(Json(
        rows.into_iter()
            .filter_map(|row| collection_response(row, elevated))
            .collect(),
    ))
}

/// Renames a collection when the caller has collection-management rights.
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{organization_id}/collections/{collection_id}",
    params(("organization_id" = Uuid, Path), ("collection_id" = Uuid, Path)),
    security(("bearer" = [])),
    request_body = CollectionUpdateRequest,
    responses((status = 200, body = CollectionResponse)),
    tag = "organizations"
)]
pub async fn update_collection(
    State(state): State<AppState>,
    session: AuthSession,
    Path((organization_id, collection_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<CollectionUpdateRequest>,
) -> Result<Json<CollectionResponse>, AppError> {
    validate_name(&request.name)?;
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_collection_manager(&mut transaction, actor, collection_id).await?;
    let updated = sqlx::query_as::<_, (DateTime<Utc>,)>(
        r"
        UPDATE collections SET name = $1, updated_at = now()
        WHERE id = $2 AND organization_id = $3
        RETURNING created_at
        ",
    )
    .bind(&request.name)
    .bind(collection_id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await;
    let created_at = match updated {
        Ok(Some(row)) => row.0,
        Ok(None) => return Err(collection_not_found()),
        Err(error) if is_unique_violation(&error) => return Err(collection_name_conflict()),
        Err(error) => return Err(error.into()),
    };
    let permissions =
        effective_collection_permissions(&mut transaction, actor, collection_id).await?;
    transaction.commit().await?;
    Ok(Json(CollectionResponse {
        id: collection_id,
        organization_id,
        name: request.name,
        read_only: permissions.0,
        hide_passwords: permissions.1,
        manage: permissions.2,
        created_at,
    }))
}

/// Deletes an empty collection.
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/collections/{collection_id}",
    params(("organization_id" = Uuid, Path), ("collection_id" = Uuid, Path)),
    security(("bearer" = [])),
    responses((status = 204)),
    tag = "organizations"
)]
pub async fn delete_collection(
    State(state): State<AppState>,
    session: AuthSession,
    Path((organization_id, collection_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_collection_manager(&mut transaction, actor, collection_id).await?;
    let object_count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*) FROM vault_objects
        WHERE owner_type = 1 AND owner_id = $1 AND deleted_at IS NULL
          AND $2 = ANY(collection_ids)
        ",
    )
    .bind(organization_id)
    .bind(collection_id)
    .fetch_one(&mut *transaction)
    .await?;
    if object_count != 0 {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "collection_not_empty",
            "Move or delete every vault item before deleting the collection.",
        ));
    }
    let changed = sqlx::query("DELETE FROM collections WHERE id = $1 AND organization_id = $2")
        .bind(collection_id)
        .bind(organization_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(collection_not_found());
    }
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Grants or replaces a confirmed member's collection permissions.
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{organization_id}/collections/{collection_id}/access/{member_id}",
    params(("organization_id" = Uuid, Path), ("collection_id" = Uuid, Path), ("member_id" = Uuid, Path)),
    security(("bearer" = [])),
    request_body = CollectionAccessRequest,
    responses((status = 204)),
    tag = "organizations"
)]
pub async fn put_collection_access(
    State(state): State<AppState>,
    session: AuthSession,
    Path((organization_id, collection_id, member_id)): Path<(Uuid, Uuid, Uuid)>,
    Json(request): Json<CollectionAccessRequest>,
) -> Result<StatusCode, AppError> {
    if request.member_id != member_id {
        return Err(AppError::invalid(
            "member_id_mismatch",
            "The collection-access member ID does not match the route.",
        ));
    }
    if request.manage && (request.read_only || request.hide_passwords) {
        return Err(AppError::invalid(
            "invalid_collection_access",
            "Collection managers must have writable, visible-secret access.",
        ));
    }
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_admin(actor)?;
    ensure_collection(&mut transaction, organization_id, collection_id).await?;
    let target = lock_member(&mut transaction, organization_id, member_id).await?;
    if target.status != 2 || target.account_id.is_none() {
        return Err(member_not_found());
    }
    sqlx::query(
        r"
        INSERT INTO collection_access
            (collection_id, member_id, read_only, hide_passwords, manage)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (collection_id, member_id) DO UPDATE SET
            read_only = EXCLUDED.read_only,
            hide_passwords = EXCLUDED.hide_passwords,
            manage = EXCLUDED.manage
        ",
    )
    .bind(collection_id)
    .bind(member_id)
    .bind(request.read_only)
    .bind(request.hide_passwords)
    .bind(request.manage)
    .execute(&mut *transaction)
    .await?;
    vault::reconcile_organization_member(
        &mut transaction,
        organization_id,
        member_id,
        target.account_id.ok_or_else(AppError::internal)?,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revokes one member's collection access and removes no-longer-visible items from sync.
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/collections/{collection_id}/access/{member_id}",
    params(("organization_id" = Uuid, Path), ("collection_id" = Uuid, Path), ("member_id" = Uuid, Path)),
    security(("bearer" = [])),
    responses((status = 204)),
    tag = "organizations"
)]
pub async fn delete_collection_access(
    State(state): State<AppState>,
    session: AuthSession,
    Path((organization_id, collection_id, member_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut transaction = state.pool.begin().await?;
    let actor = lock_actor(&mut transaction, organization_id, session.account_id).await?;
    require_admin(actor)?;
    ensure_collection(&mut transaction, organization_id, collection_id).await?;
    let target = lock_member(&mut transaction, organization_id, member_id).await?;
    if target.status != 2 || target.account_id.is_none() {
        return Err(member_not_found());
    }
    sqlx::query("DELETE FROM collection_access WHERE collection_id = $1 AND member_id = $2")
        .bind(collection_id)
        .bind(member_id)
        .execute(&mut *transaction)
        .await?;
    vault::reconcile_organization_member(
        &mut transaction,
        organization_id,
        member_id,
        target.account_id.ok_or_else(AppError::internal)?,
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn member_acl(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    account_id: Uuid,
) -> Result<MemberAcl, AppError> {
    let row = sqlx::query_as::<_, (Uuid, i16, i16)>(
        r"
        SELECT id, role, status FROM organization_members
        WHERE organization_id = $1 AND account_id = $2
        ",
    )
    .bind(organization_id)
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(forbidden)?;
    let access = sqlx::query_as::<_, (Uuid, bool, bool)>(
        r"
        SELECT collection_id, read_only, manage FROM collection_access
        WHERE member_id = $1
        ",
    )
    .bind(row.0)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(MemberAcl {
        member_id: row.0,
        account_id,
        role: role_from_db(row.1)?,
        confirmed: row.2 == 2,
        collection_access: access
            .into_iter()
            .map(|(id, read_only, manage)| (id, (read_only, manage)))
            .collect(),
    })
}

pub(crate) async fn confirmed_member_acls(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<Vec<MemberAcl>, AppError> {
    let members = sqlx::query_as::<_, (Uuid, Uuid, i16)>(
        r"
        SELECT id, account_id, role FROM organization_members
        WHERE organization_id = $1 AND status = 2 AND account_id IS NOT NULL
        ORDER BY account_id
        ",
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut result = Vec::with_capacity(members.len());
    for (member_id, account_id, role) in members {
        let access = sqlx::query_as::<_, (Uuid, bool, bool)>(
            "SELECT collection_id, read_only, manage FROM collection_access WHERE member_id = $1",
        )
        .bind(member_id)
        .fetch_all(&mut **transaction)
        .await?;
        result.push(MemberAcl {
            member_id,
            account_id,
            role: role_from_db(role)?,
            confirmed: true,
            collection_access: access
                .into_iter()
                .map(|(id, read_only, manage)| (id, (read_only, manage)))
                .collect(),
        });
    }
    Ok(result)
}

pub(crate) async fn validate_collection_ids(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    collection_ids: &[Uuid],
) -> Result<(), AppError> {
    let unique: HashSet<_> = collection_ids.iter().copied().collect();
    if unique.len() != collection_ids.len() {
        return Err(AppError::invalid(
            "invalid_collections",
            "Collection IDs must be unique.",
        ));
    }
    if unique.is_empty() {
        return Ok(());
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM collections WHERE organization_id = $1 AND id = ANY($2)",
    )
    .bind(organization_id)
    .bind(collection_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(count).ok() != Some(unique.len()) {
        return Err(AppError::invalid(
            "invalid_collections",
            "One or more collections do not belong to the organization.",
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct MemberAcl {
    pub member_id: Uuid,
    pub account_id: Uuid,
    pub role: OrganizationRole,
    pub confirmed: bool,
    /// collection -> (`read_only`, `manage`)
    pub collection_access: std::collections::HashMap<Uuid, (bool, bool)>,
}

impl MemberAcl {
    pub(crate) fn can_read(&self, collection_ids: &[Uuid]) -> bool {
        self.confirmed
            && (matches!(self.role, OrganizationRole::Owner | OrganizationRole::Admin)
                || collection_ids
                    .iter()
                    .any(|id| self.collection_access.contains_key(id)))
    }

    pub(crate) fn can_write(&self, collection_ids: &[Uuid]) -> bool {
        if !self.confirmed {
            return false;
        }
        if matches!(self.role, OrganizationRole::Owner | OrganizationRole::Admin) {
            return true;
        }
        !collection_ids.is_empty()
            && collection_ids.iter().all(|id| {
                self.collection_access
                    .get(id)
                    .is_some_and(|(read_only, _)| !read_only)
            })
    }
}

async fn lock_actor(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    account_id: Uuid,
) -> Result<ActorRow, AppError> {
    lock_organization(transaction, organization_id).await?;
    let actor = sqlx::query_as::<_, ActorRow>(
        r"
        SELECT id, role, status FROM organization_members
        WHERE organization_id = $1 AND account_id = $2
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(organization_not_found)?;
    if actor.status != 2 {
        return Err(forbidden());
    }
    Ok(actor)
}

pub(crate) async fn lock_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<(), AppError> {
    let exists =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(organization_id)
            .fetch_optional(&mut **transaction)
            .await?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(organization_not_found())
    }
}

async fn require_confirmed_membership(
    pool: &sqlx::PgPool,
    organization_id: Uuid,
    account_id: Uuid,
) -> Result<ActorRow, AppError> {
    sqlx::query_as::<_, ActorRow>(
        r"
        SELECT id, role, status FROM organization_members
        WHERE organization_id = $1 AND account_id = $2 AND status = 2
        ",
    )
    .bind(organization_id)
    .bind(account_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(organization_not_found)
}

fn require_admin(actor: ActorRow) -> Result<(), AppError> {
    if matches!(
        role_from_db(actor.role)?,
        OrganizationRole::Owner | OrganizationRole::Admin
    ) {
        Ok(())
    } else {
        Err(forbidden())
    }
}

async fn lock_member(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    member_id: Uuid,
) -> Result<MemberRow, AppError> {
    sqlx::query_as::<_, MemberRow>(
        r"
        SELECT id, account_id, email, role, status, encrypted_organization_key,
               invited_at, accepted_at, confirmed_at
        FROM organization_members
        WHERE organization_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(member_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(member_not_found)
}

async fn fetch_member(
    transaction: &mut Transaction<'_, Postgres>,
    member_id: Uuid,
) -> Result<OrganizationMemberResponse, AppError> {
    let row = sqlx::query_as::<_, MemberRow>(
        r"
        SELECT id, account_id, email, role, status, encrypted_organization_key,
               invited_at, accepted_at, confirmed_at
        FROM organization_members WHERE id = $1
        ",
    )
    .bind(member_id)
    .fetch_one(&mut **transaction)
    .await?;
    member_response(row)
}

async fn ensure_another_owner(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    excluded_member: Uuid,
) -> Result<(), AppError> {
    let another_owner = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS(
            SELECT 1 FROM organization_members
            WHERE organization_id = $1 AND id <> $2 AND role = 0 AND status = 2
        )
        ",
    )
    .bind(organization_id)
    .bind(excluded_member)
    .fetch_one(&mut **transaction)
    .await?;
    if another_owner {
        Ok(())
    } else {
        Err(AppError::new(
            StatusCode::CONFLICT,
            "last_owner",
            "An organization must retain at least one confirmed owner.",
        ))
    }
}

async fn require_collection_manager(
    transaction: &mut Transaction<'_, Postgres>,
    actor: ActorRow,
    collection_id: Uuid,
) -> Result<(), AppError> {
    if matches!(
        role_from_db(actor.role)?,
        OrganizationRole::Owner | OrganizationRole::Admin
    ) {
        return Ok(());
    }
    let manage = sqlx::query_scalar::<_, bool>(
        "SELECT manage FROM collection_access WHERE collection_id = $1 AND member_id = $2",
    )
    .bind(collection_id)
    .bind(actor.id)
    .fetch_optional(&mut **transaction)
    .await?
    .unwrap_or(false);
    if manage { Ok(()) } else { Err(forbidden()) }
}

async fn effective_collection_permissions(
    transaction: &mut Transaction<'_, Postgres>,
    actor: ActorRow,
    collection_id: Uuid,
) -> Result<(bool, bool, bool), AppError> {
    if matches!(
        role_from_db(actor.role)?,
        OrganizationRole::Owner | OrganizationRole::Admin
    ) {
        return Ok((false, false, true));
    }
    sqlx::query_as::<_, (bool, bool, bool)>(
        r"
        SELECT read_only, hide_passwords, manage FROM collection_access
        WHERE collection_id = $1 AND member_id = $2
        ",
    )
    .bind(collection_id)
    .bind(actor.id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(forbidden)
}

async fn ensure_collection(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    collection_id: Uuid,
) -> Result<(), AppError> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM collections WHERE organization_id = $1 AND id = $2)",
    )
    .bind(organization_id)
    .bind(collection_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(collection_not_found())
    }
}

fn organization_response(row: OrganizationRow) -> Result<OrganizationResponse, AppError> {
    let status = status_from_db(row.status)?;
    Ok(OrganizationResponse {
        id: row.id,
        member_id: row.member_id,
        name: row.name,
        role: role_from_db(row.role)?,
        status,
        encrypted_organization_key: matches!(
            status,
            MembershipStatus::Accepted | MembershipStatus::Confirmed
        )
        .then_some(row.encrypted_organization_key)
        .flatten(),
        created_at: row.created_at,
    })
}

fn member_response(row: MemberRow) -> Result<OrganizationMemberResponse, AppError> {
    let status = status_from_db(row.status)?;
    Ok(OrganizationMemberResponse {
        id: row.id,
        account_id: row.account_id,
        email: row.email,
        role: role_from_db(row.role)?,
        status,
        encrypted_organization_key: matches!(
            status,
            MembershipStatus::Accepted | MembershipStatus::Confirmed
        )
        .then_some(row.encrypted_organization_key)
        .flatten(),
        invited_at: row.invited_at,
        accepted_at: row.accepted_at,
        confirmed_at: row.confirmed_at,
    })
}

fn collection_response(row: CollectionRow, elevated: bool) -> Option<CollectionResponse> {
    if !elevated && row.manage.is_none() {
        return None;
    }
    Some(CollectionResponse {
        id: row.id,
        organization_id: row.organization_id,
        name: row.name,
        read_only: if elevated {
            false
        } else {
            row.read_only.unwrap_or(true)
        },
        hide_passwords: if elevated {
            false
        } else {
            row.hide_passwords.unwrap_or(true)
        },
        manage: elevated || row.manage.unwrap_or(false),
        created_at: row.created_at,
    })
}

fn validate_name(value: &str) -> Result<(), AppError> {
    let characters = value.chars().count();
    if value.trim() != value
        || !(1..=128).contains(&characters)
        || value.chars().any(char::is_control)
    {
        return Err(AppError::invalid(
            "invalid_name",
            "Names must contain between 1 and 128 visible characters.",
        ));
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), AppError> {
    let decoded = decode_urlsafe(value, "invalid_sharing_key")?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(AppError::invalid(
            "invalid_sharing_key",
            "The sharing public key is malformed.",
        ));
    }
    Ok(())
}

fn validate_organization_key_wrapper(value: &str) -> Result<(), AppError> {
    if value.len() > MAX_ORGANIZATION_KEY_WRAPPER_BYTES {
        return Err(invalid_organization_key());
    }
    let mut parts = value.split('.');
    if parts.next() != Some("hp-share") || parts.next() != Some("v1") {
        return Err(invalid_organization_key());
    }
    let ephemeral = parts.next().ok_or_else(invalid_organization_key)?;
    let nonce = parts.next().ok_or_else(invalid_organization_key)?;
    let ciphertext = parts.next().ok_or_else(invalid_organization_key)?;
    if parts.next().is_some()
        || decode_urlsafe(ephemeral, "invalid_organization_key")?.len() != 32
        || decode_urlsafe(nonce, "invalid_organization_key")?.len() != 24
        || decode_urlsafe(ciphertext, "invalid_organization_key")?.len() < 48
    {
        return Err(invalid_organization_key());
    }
    Ok(())
}

fn validate_enc_string(value: &str, maximum: usize) -> Result<(), AppError> {
    if value.len() > maximum || !value.starts_with("2.") {
        return Err(AppError::invalid(
            "invalid_encrypted_value",
            "Encrypted value is malformed.",
        ));
    }
    let parts: Vec<&str> = value[2..].split('|').collect();
    if parts.len() != 3 {
        return Err(AppError::invalid(
            "invalid_encrypted_value",
            "Encrypted value is malformed.",
        ));
    }
    let standard = base64::engine::general_purpose::STANDARD;
    let iv = standard.decode(parts[0]);
    let ciphertext = standard.decode(parts[1]);
    let mac = standard.decode(parts[2]);
    if !matches!(iv, Ok(ref bytes) if bytes.len() == 16)
        || !matches!(ciphertext, Ok(ref bytes) if !bytes.is_empty() && bytes.len().is_multiple_of(16))
        || !matches!(mac, Ok(ref bytes) if bytes.len() == 32)
    {
        return Err(AppError::invalid(
            "invalid_encrypted_value",
            "Encrypted value is malformed.",
        ));
    }
    Ok(())
}

fn decode_urlsafe(value: &str, code: &'static str) -> Result<Vec<u8>, AppError> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        AppError::invalid(
            code,
            "The encrypted organization key material is malformed.",
        )
    })
}

fn role_to_db(role: OrganizationRole) -> i16 {
    match role {
        OrganizationRole::Owner => 0,
        OrganizationRole::Admin => 1,
        OrganizationRole::Manager => 2,
        OrganizationRole::User => 3,
    }
}

fn role_from_db(value: i16) -> Result<OrganizationRole, AppError> {
    match value {
        0 => Ok(OrganizationRole::Owner),
        1 => Ok(OrganizationRole::Admin),
        2 => Ok(OrganizationRole::Manager),
        3 => Ok(OrganizationRole::User),
        _ => Err(AppError::internal()),
    }
}

fn status_from_db(value: i16) -> Result<MembershipStatus, AppError> {
    match value {
        0 => Ok(MembershipStatus::Invited),
        1 => Ok(MembershipStatus::Accepted),
        2 => Ok(MembershipStatus::Confirmed),
        3 => Ok(MembershipStatus::Removed),
        _ => Err(AppError::internal()),
    }
}

fn organization_not_found() -> AppError {
    AppError::new(
        StatusCode::NOT_FOUND,
        "organization_not_found",
        "Organization not found.",
    )
}

fn member_not_found() -> AppError {
    AppError::new(
        StatusCode::NOT_FOUND,
        "member_not_found",
        "Organization member not found.",
    )
}

fn collection_not_found() -> AppError {
    AppError::new(
        StatusCode::NOT_FOUND,
        "collection_not_found",
        "Collection not found.",
    )
}

fn collection_name_conflict() -> AppError {
    AppError::new(
        StatusCode::CONFLICT,
        "collection_exists",
        "A collection with that name already exists.",
    )
}

fn sharing_key_not_found() -> AppError {
    AppError::new(
        StatusCode::NOT_FOUND,
        "sharing_key_not_found",
        "The account has not installed a sharing key.",
    )
}

fn recipient_unavailable() -> AppError {
    AppError::new(
        StatusCode::NOT_FOUND,
        "recipient_unavailable",
        "The recipient is unavailable or has not installed a sharing key.",
    )
}

fn invalid_invitation() -> AppError {
    AppError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_invitation",
        "The invitation is invalid or expired.",
    )
}

fn invalid_organization_key() -> AppError {
    AppError::invalid(
        "invalid_organization_key",
        "The encrypted organization key is malformed.",
    )
}

fn forbidden() -> AppError {
    AppError::new(
        StatusCode::FORBIDDEN,
        "organization_forbidden",
        "The organization operation is not permitted.",
    )
}
