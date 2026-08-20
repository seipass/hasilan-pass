use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json,
    extract::{FromRequestParts, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hasilan_protocol::{
    DeviceResponse, KdfSettings, KdfType, LoginRequest, LogoutRequest, PreloginRequest,
    PreloginResponse, RefreshRequest, RegisterRequest, RegisterResponse, SessionResponse,
    TokenResponse,
};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    account_security::{maybe_issue_login_trust, verify_login_second_factor},
    config::TokenPepper,
    error::AppError,
    state::AppState,
    token::{generate_token, hash_token},
};

const MAX_EMAIL_BYTES: usize = 254;
const MAX_PROTECTED_KEY_BYTES: usize = 16 * 1024;
const MAX_COOKIE_HEADER_BYTES: usize = 4096;
const REFRESH_COOKIE: &str = "hp_refresh";
const CSRF_COOKIE: &str = "hp_csrf";
pub(crate) const WEB_SESSION_HEADER: &str = "x-hasilan-web-session";
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";

#[derive(FromRow)]
struct AccountAuthRow {
    id: Uuid,
    auth_verifier: String,
    protected_user_key: String,
    kdf_type: i16,
    kdf_iterations: i32,
    kdf_memory_mib: Option<i32>,
    kdf_parallelism: Option<i32>,
}

#[derive(FromRow)]
struct SessionAccountRow {
    session_id: Uuid,
    account_id: Uuid,
    device_id: Uuid,
    protected_user_key: String,
    kdf_type: i16,
    kdf_iterations: i32,
    kdf_memory_mib: Option<i32>,
    kdf_parallelism: Option<i32>,
}

/// Authenticated request identity resolved from a hashed opaque access token.
#[allow(
    clippy::struct_field_names,
    reason = "explicit ID suffixes make the three security principals unambiguous"
)]
#[derive(Clone, Copy, Debug)]
pub struct AuthSession {
    /// Current revocable session.
    pub session_id: Uuid,
    /// Authenticated account boundary.
    pub account_id: Uuid,
    /// Device bound to the current session.
    pub device_id: Uuid,
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let authorization = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| !token.is_empty() && token.len() <= 256)
            .ok_or_else(AppError::unauthorized)?;
        let token_hash = hash_token(authorization, &state.config.token_pepper);
        let session = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
            r"
            UPDATE sessions
            SET last_seen_at = now()
            WHERE access_token_hash = $1
              AND access_expires_at > now()
              AND refresh_expires_at > now()
              AND revoked_at IS NULL
            RETURNING id, account_id, device_id
            ",
        )
        .bind(token_hash)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(AppError::unauthorized)?;
        Ok(Self {
            session_id: session.0,
            account_id: session.1,
            device_id: session.2,
        })
    }
}

/// Returns KDF settings without accepting a password.
#[utoipa::path(
    post,
    path = "/api/v1/auth/prelogin",
    request_body = PreloginRequest,
    responses((status = 200, body = PreloginResponse), (status = 400, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
pub async fn prelogin(
    State(state): State<AppState>,
    Json(request): Json<PreloginRequest>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = normalize_email(&request.email)?;
    let row = sqlx::query_as::<_, (i16, i32, Option<i32>, Option<i32>)>(
        "SELECT kdf_type, kdf_iterations, kdf_memory_mib, kdf_parallelism FROM accounts WHERE email = $1 AND disabled_at IS NULL",
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await?;
    let kdf = row
        .map(|row| kdf_from_db(row.0, row.1, row.2, row.3))
        .transpose()?
        .unwrap_or_default();
    Ok(Json(PreloginResponse { kdf }))
}

/// Registers a new account while storing only a wrapped user key and a hardened proof verifier.
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    request_body = RegisterRequest,
    responses((status = 201, body = RegisterResponse), (status = 400, body = hasilan_protocol::ApiErrorBody), (status = 409, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let email = normalize_email(&request.email)?;
    validate_kdf(&request.kdf)?;
    validate_device(&request.device.name, &request.device.device_type)?;
    validate_enc_string(&request.protected_user_key, MAX_PROTECTED_KEY_BYTES)?;
    let proof = decode_auth_proof(&request.auth_proof)?;
    let verifier = hash_auth_proof(proof, Arc::clone(&state.config.token_pepper)).await?;

    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let (kdf_type, iterations, memory, parallelism) = kdf_to_db(&request.kdf)?;
    let mut transaction = state.pool.begin().await?;
    let insert = sqlx::query(
        r"
        INSERT INTO accounts
            (id, email, auth_verifier, protected_user_key, kdf_type, kdf_iterations,
             kdf_memory_mib, kdf_parallelism)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(account_id)
    .bind(&email)
    .bind(verifier)
    .bind(&request.protected_user_key)
    .bind(kdf_type)
    .bind(iterations)
    .bind(memory)
    .bind(parallelism)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = insert {
        if is_unique_violation(&error) {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "account_exists",
                "An account with this email already exists.",
            ));
        }
        return Err(error.into());
    }
    sqlx::query("INSERT INTO account_revisions (account_id) VALUES ($1)")
        .bind(account_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO devices (id, account_id, identifier, name, device_type) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(request.device.identifier)
    .bind(&request.device.name)
    .bind(&request.device.device_type)
    .execute(&mut *transaction)
    .await?;
    insert_event(
        &mut transaction,
        Some(account_id),
        Some(device_id),
        "account_registered",
    )
    .await?;
    transaction.commit().await?;
    tracing::info!(account.id = %account_id, "account registered");
    Ok((StatusCode::CREATED, Json(RegisterResponse { account_id })))
}

/// Authenticates a client-derived proof and creates a new rotating session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses((status = 200, body = TokenResponse), (status = 401, body = hasilan_protocol::ApiErrorBody), (status = 429, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, AppError> {
    let web_session = web_session_requested(&headers);
    if web_session {
        verify_web_origin(&headers, &state)?;
    }
    let email = normalize_email(&request.email)?;
    validate_device(&request.device.name, &request.device.device_type)?;
    state.login_limiter.check(&email)?;
    let proof = decode_auth_proof(&request.auth_proof)?;
    let account = sqlx::query_as::<_, AccountAuthRow>(
        r"
        SELECT id, auth_verifier, protected_user_key, kdf_type, kdf_iterations,
               kdf_memory_mib, kdf_parallelism
        FROM accounts WHERE email = $1 AND disabled_at IS NULL
        ",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some(account) = account else {
        // Perform a comparable verifier operation for unknown accounts.
        let _ = hash_auth_proof(proof, Arc::clone(&state.config.token_pepper)).await;
        return Err(AppError::unauthorized());
    };
    let valid = verify_auth_proof(
        proof,
        account.auth_verifier.clone(),
        Arc::clone(&state.config.token_pepper),
    )
    .await?;
    if !valid {
        insert_standalone_event(&state, Some(account.id), None, "login_failed").await;
        return Err(AppError::unauthorized());
    }

    let mut transaction = state.pool.begin().await?;
    let factor_outcome =
        match verify_login_second_factor(&mut transaction, &state, account.id, &request).await {
            Ok(outcome) => outcome,
            Err(error) => {
                drop(transaction);
                let event_type = if error.code == "mfa_required" {
                    "login_mfa_required"
                } else {
                    "login_second_factor_failed"
                };
                insert_standalone_event(&state, Some(account.id), None, event_type).await;
                return Err(error);
            }
        };
    let device_id = upsert_device(
        &mut transaction,
        account.id,
        request.device.identifier,
        &request.device.name,
        &request.device.device_type,
    )
    .await?;
    let mut tokens = create_session(
        &mut transaction,
        &state,
        account.id,
        device_id,
        account.protected_user_key,
        kdf_from_db(
            account.kdf_type,
            account.kdf_iterations,
            account.kdf_memory_mib,
            account.kdf_parallelism,
        )?,
    )
    .await?;
    tokens.trusted_device_token = maybe_issue_login_trust(
        &mut transaction,
        &state,
        device_id,
        factor_outcome,
        request.remember_device,
    )
    .await?;
    insert_event(
        &mut transaction,
        Some(account.id),
        Some(device_id),
        factor_outcome.event_type(),
    )
    .await?;
    transaction.commit().await?;
    state.login_limiter.clear(&email);
    tracing::info!(account.id = %account.id, device.id = %device_id, "login succeeded");
    token_response(tokens, &state, web_session)
}

/// Rotates access and refresh tokens. Reusing an old refresh token revokes the session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    request_body = RefreshRequest,
    responses((status = 200, body = TokenResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
#[allow(
    clippy::too_many_lines,
    reason = "refresh rotation and reuse revocation intentionally remain one auditable transaction"
)]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> Result<Response, AppError> {
    let web_session = web_session_requested(&headers);
    let refresh_token = if web_session {
        verify_web_origin(&headers, &state)?;
        verify_web_csrf(&headers)?;
        if !request.refresh_token.is_empty() {
            return Err(AppError::invalid(
                "ambiguous_refresh_transport",
                "Web refresh must use its HttpOnly cookie.",
            ));
        }
        required_cookie(&headers, REFRESH_COOKIE).map_err(|()| AppError::unauthorized())?
    } else {
        request.refresh_token
    };
    if refresh_token.len() > 256 || refresh_token.is_empty() {
        return Err(AppError::unauthorized());
    }
    let old_hash = hash_token(&refresh_token, &state.config.token_pepper);
    let mut transaction = state.pool.begin().await?;
    let session = sqlx::query_as::<_, SessionAccountRow>(
        r"
        SELECT s.id AS session_id, s.account_id, s.device_id,
               a.protected_user_key, a.kdf_type, a.kdf_iterations,
               a.kdf_memory_mib, a.kdf_parallelism
        FROM sessions s
        JOIN accounts a ON a.id = s.account_id
        WHERE s.refresh_token_hash = $1
          AND s.refresh_expires_at > now()
          AND s.revoked_at IS NULL
          AND a.disabled_at IS NULL
        FOR UPDATE OF s
        ",
    )
    .bind(&old_hash)
    .fetch_optional(&mut *transaction)
    .await?;

    let Some(session) = session else {
        let reused_session = sqlx::query_scalar::<_, Uuid>(
            "SELECT session_id FROM used_refresh_tokens WHERE token_hash = $1",
        )
        .bind(&old_hash)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(session_id) = reused_session {
            let revoked = sqlx::query_as::<_, (Uuid, Uuid)>(
                r"
                UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'refresh_reuse'
                WHERE id = $1 RETURNING account_id, device_id
                ",
            )
            .bind(session_id)
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some((account_id, device_id)) = revoked {
                insert_event(
                    &mut transaction,
                    Some(account_id),
                    Some(device_id),
                    "refresh_token_reuse_detected",
                )
                .await?;
            }
            transaction.commit().await?;
            return Err(AppError::new(
                StatusCode::UNAUTHORIZED,
                "refresh_reuse_detected",
                "The session was revoked.",
            ));
        }
        return Err(AppError::unauthorized());
    };

    let access_token = generate_token()?;
    let refresh_token = generate_token()?;
    let access_hash = hash_token(&access_token, &state.config.token_pepper);
    let refresh_hash = hash_token(&refresh_token, &state.config.token_pepper);
    let access_expiry = Utc::now() + chrono_duration(state.config.access_token_ttl)?;
    sqlx::query("INSERT INTO used_refresh_tokens (token_hash, session_id) VALUES ($1, $2)")
        .bind(&old_hash)
        .bind(session.session_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        r"
        UPDATE sessions
        SET access_token_hash = $1, refresh_token_hash = $2,
            access_expires_at = $3, last_seen_at = now()
        WHERE id = $4
        ",
    )
    .bind(access_hash)
    .bind(refresh_hash)
    .bind(access_expiry)
    .bind(session.session_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
        .bind(session.device_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    token_response(
        TokenResponse {
            account_id: session.account_id,
            access_token,
            refresh_token,
            token_type: "Bearer".to_owned(),
            expires_in: state.config.access_token_ttl.as_secs(),
            protected_user_key: session.protected_user_key,
            kdf: kdf_from_db(
                session.kdf_type,
                session.kdf_iterations,
                session.kdf_memory_mib,
                session.kdf_parallelism,
            )?,
            session_id: session.session_id,
            device_id: session.device_id,
            trusted_device_token: None,
        },
        &state,
        web_session,
    )
}

/// Revokes the current session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    security(("bearer" = [])),
    request_body = LogoutRequest,
    responses((status = 204), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
pub async fn logout(
    State(state): State<AppState>,
    session: AuthSession,
    headers: HeaderMap,
    Json(_request): Json<LogoutRequest>,
) -> Result<Response, AppError> {
    let web_session = web_session_requested(&headers);
    if web_session {
        verify_web_origin(&headers, &state)?;
        verify_web_csrf(&headers)?;
    }
    let mut transaction = state.pool.begin().await?;
    sqlx::query(
        "UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'logout' WHERE id = $1",
    )
    .bind(session.session_id)
    .execute(&mut *transaction)
    .await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "logout",
    )
    .await?;
    transaction.commit().await?;
    if web_session {
        clear_web_session_response(state.config.production)
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

/// Lists account sessions without returning tokens.
pub async fn list_sessions(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Vec<SessionResponse>>, AppError> {
    let rows = sqlx::query_as::<_, SessionListRow>(
        r"
        SELECT id, device_id, created_at, last_seen_at, refresh_expires_at, revoked_at
        FROM sessions WHERE account_id = $1 ORDER BY last_seen_at DESC
        ",
    )
    .bind(session.account_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| SessionResponse {
                id: row.id,
                device_id: row.device_id,
                created_at: row.created_at,
                last_seen_at: row.last_seen_at,
                expires_at: row.refresh_expires_at,
                revoked_at: row.revoked_at,
                current: row.id == session.session_id,
            })
            .collect(),
    ))
}

#[derive(FromRow)]
struct SessionListRow {
    id: Uuid,
    device_id: Uuid,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    refresh_expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

/// Revokes an arbitrary session belonging to the authenticated account.
pub async fn revoke_session(
    State(state): State<AppState>,
    session: AuthSession,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let changed = sqlx::query(
        r"
        UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'user_revoked'
        WHERE id = $1 AND account_id = $2
        ",
    )
    .bind(session_id)
    .bind(session.account_id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::new(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "Session not found.",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Lists registered devices.
pub async fn list_devices(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Vec<DeviceResponse>>, AppError> {
    let rows = sqlx::query_as::<_, DeviceRow>(
        r"
        SELECT id, identifier, name, device_type, trusted, trusted_until, created_at, last_seen_at
        FROM devices WHERE account_id = $1 ORDER BY last_seen_at DESC
        ",
    )
    .bind(session.account_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| DeviceResponse {
                id: row.id,
                identifier: row.identifier,
                name: row.name,
                device_type: row.device_type,
                trusted: row.trusted,
                trusted_until: row.trusted_until,
                created_at: row.created_at,
                last_seen_at: row.last_seen_at,
            })
            .collect(),
    ))
}

#[derive(FromRow)]
struct DeviceRow {
    id: Uuid,
    identifier: Uuid,
    name: String,
    device_type: String,
    trusted: bool,
    trusted_until: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

pub(crate) fn web_session_requested(headers: &HeaderMap) -> bool {
    headers
        .get(WEB_SESSION_HEADER)
        .is_some_and(|value| value.as_bytes() == b"1")
}

pub(crate) fn verify_web_origin(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 2048)
        .ok_or_else(csrf_failed)?;
    if !state
        .config
        .allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        return Err(csrf_failed());
    }
    Ok(())
}

/// Converts a token result to the Web cookie transport or the native JSON transport.
///
/// Web responses keep the access token and unlock material in JSON, move the refresh
/// token into an `HttpOnly` cookie, and issue an independent double-submit CSRF value.
pub(crate) fn token_response(
    mut tokens: TokenResponse,
    state: &AppState,
    web_session: bool,
) -> Result<Response, AppError> {
    if !web_session {
        return Ok(Json(tokens).into_response());
    }
    let refresh_token = std::mem::take(&mut tokens.refresh_token);
    let csrf_token = generate_token()?;
    let max_age = state.config.refresh_token_ttl.as_secs();
    let mut response = Json(tokens).into_response();
    append_cookie(
        &mut response,
        session_cookie(
            REFRESH_COOKIE,
            &refresh_token,
            max_age,
            state.config.production,
        )?,
    );
    append_cookie(
        &mut response,
        session_cookie(CSRF_COOKIE, &csrf_token, max_age, state.config.production)?,
    );
    response.headers_mut().insert(
        CSRF_HEADER,
        HeaderValue::from_str(&csrf_token).map_err(|_| AppError::internal())?,
    );
    Ok(response)
}

fn verify_web_csrf(headers: &HeaderMap) -> Result<(), AppError> {
    let supplied = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(csrf_failed)?;
    let cookie = required_cookie(headers, CSRF_COOKIE).map_err(|()| csrf_failed())?;
    if cookie.len() != supplied.len()
        || cookie.as_bytes().ct_eq(supplied.as_bytes()).unwrap_u8() != 1
    {
        return Err(csrf_failed());
    }
    Ok(())
}

fn csrf_failed() -> AppError {
    AppError::new(
        StatusCode::FORBIDDEN,
        "csrf_failed",
        "The Web session request could not be verified.",
    )
}

fn required_cookie(headers: &HeaderMap, name: &str) -> Result<String, ()> {
    let mut found = None;
    let mut total = 0_usize;
    for header_value in headers.get_all(header::COOKIE) {
        let value = header_value.to_str().map_err(|_| ())?;
        total = total.checked_add(value.len()).ok_or(())?;
        if total > MAX_COOKIE_HEADER_BYTES {
            return Err(());
        }
        for pair in value.split(';').map(str::trim) {
            let Some((candidate, cookie_value)) = pair.split_once('=') else {
                continue;
            };
            if candidate == name {
                if found.is_some()
                    || cookie_value.is_empty()
                    || cookie_value.len() > 256
                    || !cookie_value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(());
                }
                found = Some(cookie_value.to_owned());
            }
        }
    }
    found.ok_or(())
}

fn session_cookie(
    name: &str,
    value: &str,
    max_age: u64,
    secure: bool,
) -> Result<HeaderValue, AppError> {
    let secure_attribute = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/api/v1/auth; Max-Age={max_age}; SameSite=Strict; HttpOnly{secure_attribute}"
    ))
    .map_err(|_| AppError::internal())
}

fn expired_cookie(name: &str, secure: bool) -> Result<HeaderValue, AppError> {
    session_cookie(name, "deleted", 0, secure)
}

fn append_cookie(response: &mut Response, value: HeaderValue) {
    response.headers_mut().append(header::SET_COOKIE, value);
}

fn clear_web_session_response(secure: bool) -> Result<Response, AppError> {
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_cookie(&mut response, expired_cookie(REFRESH_COOKIE, secure)?);
    append_cookie(&mut response, expired_cookie(CSRF_COOKIE, secure)?);
    Ok(response)
}

pub(crate) async fn create_session(
    transaction: &mut Transaction<'_, Postgres>,
    state: &AppState,
    account_id: Uuid,
    device_id: Uuid,
    protected_user_key: String,
    kdf: KdfSettings,
) -> Result<TokenResponse, AppError> {
    let session_id = Uuid::new_v4();
    let access_token = generate_token()?;
    let refresh_token = generate_token()?;
    let access_hash = hash_token(&access_token, &state.config.token_pepper);
    let refresh_hash = hash_token(&refresh_token, &state.config.token_pepper);
    let now = Utc::now();
    let access_expiry = now + chrono_duration(state.config.access_token_ttl)?;
    let refresh_expiry = now + chrono_duration(state.config.refresh_token_ttl)?;
    sqlx::query(
        r"
        INSERT INTO sessions
            (id, account_id, device_id, token_family_id, access_token_hash,
             refresh_token_hash, access_expires_at, refresh_expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(session_id)
    .bind(account_id)
    .bind(device_id)
    .bind(Uuid::new_v4())
    .bind(access_hash)
    .bind(refresh_hash)
    .bind(access_expiry)
    .bind(refresh_expiry)
    .execute(&mut **transaction)
    .await?;
    Ok(TokenResponse {
        account_id,
        access_token,
        refresh_token,
        token_type: "Bearer".to_owned(),
        expires_in: state.config.access_token_ttl.as_secs(),
        protected_user_key,
        kdf,
        session_id,
        device_id,
        trusted_device_token: None,
    })
}

pub(crate) async fn upsert_device(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    identifier: Uuid,
    name: &str,
    device_type: &str,
) -> Result<Uuid, AppError> {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO devices (id, account_id, identifier, name, device_type)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (account_id, identifier) DO UPDATE
        SET name = EXCLUDED.name, device_type = EXCLUDED.device_type, last_seen_at = now()
        RETURNING id
        ",
    )
    .bind(id)
    .bind(account_id)
    .bind(identifier)
    .bind(name)
    .bind(device_type)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

pub(crate) async fn insert_event(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Option<Uuid>,
    device_id: Option<Uuid>,
    event_type: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO security_events (id, account_id, device_id, event_type, details) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(device_id)
    .bind(event_type)
    .bind(json!({}))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_standalone_event(
    state: &AppState,
    account_id: Option<Uuid>,
    device_id: Option<Uuid>,
    event_type: &str,
) {
    let result = sqlx::query(
        "INSERT INTO security_events (id, account_id, device_id, event_type, details) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(device_id)
    .bind(event_type)
    .bind(json!({}))
    .execute(&state.pool)
    .await;
    if let Err(error) = result {
        tracing::warn!(
            error.category = "security_event_write",
            "failed to persist security event"
        );
        tracing::debug!(error.kind = ?error.as_database_error().and_then(sqlx::error::DatabaseError::code), "security event database category");
    }
}

pub(crate) fn normalize_email(email: &str) -> Result<String, AppError> {
    let normalized = email.trim().to_lowercase();
    if normalized.is_empty()
        || normalized.len() > MAX_EMAIL_BYTES
        || normalized.chars().any(char::is_whitespace)
        || normalized.matches('@').count() != 1
        || normalized.starts_with('@')
        || normalized.ends_with('@')
    {
        return Err(AppError::invalid(
            "invalid_email",
            "Email address is invalid.",
        ));
    }
    Ok(normalized)
}

pub(crate) fn validate_device(name: &str, device_type: &str) -> Result<(), AppError> {
    if name.trim().is_empty()
        || name.len() > 128
        || device_type.trim().is_empty()
        || device_type.len() > 64
        || name.chars().any(char::is_control)
        || device_type.chars().any(char::is_control)
    {
        return Err(AppError::invalid(
            "invalid_device",
            "Device metadata is invalid.",
        ));
    }
    Ok(())
}

fn validate_kdf(kdf: &KdfSettings) -> Result<(), AppError> {
    let valid = match kdf.kdf_type {
        KdfType::Pbkdf2 => {
            (600_000..=5_000_000).contains(&kdf.iterations)
                && kdf.memory_mib.is_none()
                && kdf.parallelism.is_none()
        }
        KdfType::Argon2id => {
            (2..=20).contains(&kdf.iterations)
                && kdf
                    .memory_mib
                    .is_some_and(|value| (16..=256).contains(&value))
                && kdf
                    .parallelism
                    .is_some_and(|value| (1..=16).contains(&value))
        }
    };
    if valid {
        Ok(())
    } else {
        Err(AppError::invalid(
            "invalid_kdf",
            "KDF settings are outside the supported security policy.",
        ))
    }
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
    let iv = STANDARD.decode(parts[0]).map_err(|_| {
        AppError::invalid("invalid_encrypted_value", "Encrypted value is malformed.")
    })?;
    let ciphertext = STANDARD.decode(parts[1]).map_err(|_| {
        AppError::invalid("invalid_encrypted_value", "Encrypted value is malformed.")
    })?;
    let mac = STANDARD.decode(parts[2]).map_err(|_| {
        AppError::invalid("invalid_encrypted_value", "Encrypted value is malformed.")
    })?;
    if iv.len() != 16
        || mac.len() != 32
        || ciphertext.is_empty()
        || !ciphertext.len().is_multiple_of(16)
    {
        return Err(AppError::invalid(
            "invalid_encrypted_value",
            "Encrypted value is malformed.",
        ));
    }
    Ok(())
}

pub(crate) fn decode_auth_proof(value: &str) -> Result<[u8; 32], AppError> {
    let mut decoded = STANDARD
        .decode(value)
        .map_err(|_| AppError::unauthorized())?;
    let proof = decoded
        .as_slice()
        .try_into()
        .map_err(|_| AppError::unauthorized())?;
    decoded.zeroize();
    Ok(proof)
}

pub(crate) async fn hash_auth_proof(
    proof: [u8; 32],
    pepper: Arc<TokenPepper>,
) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || {
        let secret = peppered_proof(&proof, &pepper);
        let mut salt_bytes = [0_u8; 16];
        getrandom::fill(&mut salt_bytes).map_err(|_| AppError::internal())?;
        let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AppError::internal())?;
        Argon2::default()
            .hash_password(&secret, &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AppError::internal())
    })
    .await
    .map_err(|_| AppError::internal())?
}

pub(crate) async fn verify_auth_proof(
    proof: [u8; 32],
    verifier: String,
    pepper: Arc<TokenPepper>,
) -> Result<bool, AppError> {
    tokio::task::spawn_blocking(move || {
        let secret = peppered_proof(&proof, &pepper);
        let parsed = PasswordHash::new(&verifier).map_err(|_| AppError::internal())?;
        Ok(Argon2::default().verify_password(&secret, &parsed).is_ok())
    })
    .await
    .map_err(|_| AppError::internal())?
}

fn peppered_proof(proof: &[u8; 32], pepper: &TokenPepper) -> Zeroizing<Vec<u8>> {
    let mut secret = Zeroizing::new(Vec::with_capacity(64));
    secret.extend_from_slice(proof);
    secret.extend_from_slice(pepper.bytes());
    secret
}

fn kdf_to_db(kdf: &KdfSettings) -> Result<(i16, i32, Option<i32>, Option<i32>), AppError> {
    let iterations = i32::try_from(kdf.iterations)
        .map_err(|_| AppError::invalid("invalid_kdf", "KDF settings are invalid."))?;
    let memory = kdf
        .memory_mib
        .map(i32::try_from)
        .transpose()
        .map_err(|_| AppError::invalid("invalid_kdf", "KDF settings are invalid."))?;
    let parallelism = kdf
        .parallelism
        .map(i32::try_from)
        .transpose()
        .map_err(|_| AppError::invalid("invalid_kdf", "KDF settings are invalid."))?;
    Ok((
        match kdf.kdf_type {
            KdfType::Pbkdf2 => 0,
            KdfType::Argon2id => 1,
        },
        iterations,
        memory,
        parallelism,
    ))
}

pub(crate) fn kdf_from_db(
    kdf_type: i16,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> Result<KdfSettings, AppError> {
    Ok(KdfSettings {
        kdf_type: match kdf_type {
            0 => KdfType::Pbkdf2,
            1 => KdfType::Argon2id,
            _ => return Err(AppError::internal()),
        },
        iterations: u32::try_from(iterations).map_err(|_| AppError::internal())?,
        memory_mib: memory
            .map(u32::try_from)
            .transpose()
            .map_err(|_| AppError::internal())?,
        parallelism: parallelism
            .map(u32::try_from)
            .transpose()
            .map_err(|_| AppError::internal())?,
    })
}

pub(crate) fn chrono_duration(duration: std::time::Duration) -> Result<ChronoDuration, AppError> {
    ChronoDuration::from_std(duration).map_err(|_| AppError::internal())
}

pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "23505")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test assertions intentionally fail fast"
)]
mod tests {
    use super::*;

    #[test]
    fn production_session_cookies_are_strict_secure_and_path_scoped() {
        let cookie = session_cookie(REFRESH_COOKIE, "abc_DEF-123", 3600, true).unwrap();
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with("hp_refresh=abc_DEF-123;"));
        assert!(cookie.contains("Path=/api/v1/auth"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.ends_with("; Secure"));
    }

    #[test]
    fn csrf_requires_one_canonical_cookie_and_constant_time_equal_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("unrelated=x; hp_csrf=valid_token-123"),
        );
        headers.insert(CSRF_HEADER, HeaderValue::from_static("valid_token-123"));
        assert!(verify_web_csrf(&headers).is_ok());

        headers.insert(CSRF_HEADER, HeaderValue::from_static("wrong_token-123"));
        assert!(verify_web_csrf(&headers).is_err());
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("hp_csrf=valid_token-123; hp_csrf=valid_token-123"),
        );
        assert!(verify_web_csrf(&headers).is_err());
    }
}
