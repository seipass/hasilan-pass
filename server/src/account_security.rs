//! Account second factors, passkey authentication, recovery codes, and device trust.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use data_encoding::BASE32_NOPAD;
use hasilan_protocol::{
    DeviceRequest, LoginRequest, MfaEnableResponse, MfaStatusResponse, PasskeyLoginStartRequest,
    ReauthenticationRequest, RecoveryCodesResponse, TokenResponse, TotpSetupFinishRequest,
    TotpSetupStartRequest, TotpSetupStartResponse, WebauthnChallengeResponse,
    WebauthnCredentialResponse, WebauthnLoginFinishRequest, WebauthnMfaLoginStartRequest,
    WebauthnRegistrationFinishRequest, WebauthnRegistrationStartRequest,
};
use hasilan_vault::TotpConfig;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use sqlx::{FromRow, Postgres, Transaction};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::{
        AuthSession, chrono_duration, create_session, decode_auth_proof, hash_auth_proof,
        insert_event, kdf_from_db, normalize_email, token_response, upsert_device, validate_device,
        verify_auth_proof, verify_web_origin, web_session_requested,
    },
    config::TokenPepper,
    error::AppError,
    server_secret::{decrypt_mfa_secret, encrypt_mfa_secret},
    state::AppState,
    token::{generate_token, hash_token},
};

type HmacSha256 = Hmac<Sha256>;

const CEREMONY_TTL: ChronoDuration = ChronoDuration::minutes(5);
const TOTP_SETUP_TTL: ChronoDuration = ChronoDuration::minutes(10);
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_BYTES: usize = 10;
const RECOVERY_HASH_DOMAIN: &[u8] = b"hasilan-pass:recovery-code:v1";

const CEREMONY_REGISTRATION: i16 = 0;
const CEREMONY_MFA_LOGIN: i16 = 1;
const CEREMONY_PASSKEY_LOGIN: i16 = 2;

/// Outcome of password-login second-factor evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecondFactorOutcome {
    NotRequired,
    Totp,
    RecoveryCode,
    TrustedDevice,
}

impl SecondFactorOutcome {
    pub(crate) const fn event_type(self) -> &'static str {
        match self {
            Self::NotRequired => "login_succeeded",
            Self::Totp => "login_succeeded_totp",
            Self::RecoveryCode => "login_succeeded_recovery_code",
            Self::TrustedDevice => "login_succeeded_trusted_device",
        }
    }

    pub(crate) const fn is_full_mfa(self) -> bool {
        matches!(self, Self::Totp | Self::RecoveryCode)
    }
}

/// Lists account MFA state without returning any authenticator secret.
#[utoipa::path(
    get,
    path = "/api/v1/account/security",
    security(("bearer" = [])),
    responses((status = 200, body = MfaStatusResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn status(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<MfaStatusResponse>, AppError> {
    let totp_enabled = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM account_totp WHERE account_id = $1)",
    )
    .bind(session.account_id)
    .fetch_one(&state.pool)
    .await?;
    let recovery_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM account_recovery_codes WHERE account_id = $1 AND used_at IS NULL",
    )
    .bind(session.account_id)
    .fetch_one(&state.pool)
    .await?;
    let credentials = sqlx::query_as::<_, WebauthnCredentialRow>(
        r"
        SELECT id, name, created_at, last_used_at
        FROM account_webauthn_credentials
        WHERE account_id = $1 ORDER BY created_at
        ",
    )
    .bind(session.account_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(MfaStatusResponse {
        totp_enabled,
        recovery_codes_remaining: u32::try_from(recovery_count)
            .map_err(|_| AppError::internal())?,
        webauthn_credentials: credentials
            .into_iter()
            .map(WebauthnCredentialRow::into_response)
            .collect(),
    }))
}

/// Creates an expiring authenticator-app seed after master-password reauthentication.
#[utoipa::path(
    post,
    path = "/api/v1/account/security/totp/start",
    security(("bearer" = [])),
    request_body = TotpSetupStartRequest,
    responses((status = 200, body = TotpSetupStartResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn start_totp_setup(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<TotpSetupStartRequest>,
) -> Result<Json<TotpSetupStartResponse>, AppError> {
    verify_reauthentication(&state, session.account_id, &request.auth_proof).await?;
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM accounts WHERE id = $1")
        .bind(session.account_id)
        .fetch_one(&state.pool)
        .await?;
    let mut secret_bytes = Zeroizing::new([0_u8; 20]);
    getrandom::fill(secret_bytes.as_mut()).map_err(|_| AppError::internal())?;
    let mut secret = Zeroizing::new(BASE32_NOPAD.encode(secret_bytes.as_ref()));
    let encrypted = encrypt_mfa_secret(
        secret.as_bytes(),
        session.account_id,
        &state.config.mfa_encryption_key,
    )?;
    let setup_id = Uuid::new_v4();
    let expires_at = Utc::now() + TOTP_SETUP_TTL;
    let mut transaction = state.pool.begin().await?;
    sqlx::query("DELETE FROM account_totp_setups WHERE account_id = $1")
        .bind(session.account_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        r"
        INSERT INTO account_totp_setups
            (id, account_id, session_id, encrypted_secret, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(setup_id)
    .bind(session.account_id)
    .bind(session.session_id)
    .bind(encrypted)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "totp_setup_started",
    )
    .await?;
    transaction.commit().await?;
    let otpauth_uri = build_totp_uri(&email, &secret)?;
    let response = TotpSetupStartResponse {
        setup_id,
        secret: secret.to_string(),
        otpauth_uri,
        expires_at,
    };
    secret.zeroize();
    Ok(Json(response))
}

/// Verifies a pending seed, enables TOTP, and returns new recovery codes once.
#[utoipa::path(
    post,
    path = "/api/v1/account/security/totp/finish",
    security(("bearer" = [])),
    request_body = TotpSetupFinishRequest,
    responses((status = 200, body = MfaEnableResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn finish_totp_setup(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<TotpSetupFinishRequest>,
) -> Result<Json<MfaEnableResponse>, AppError> {
    let mut transaction = state.pool.begin().await?;
    let setup = sqlx::query_as::<_, TotpSetupRow>(
        r"
        SELECT encrypted_secret, expires_at
        FROM account_totp_setups
        WHERE id = $1 AND account_id = $2 AND session_id = $3
        FOR UPDATE
        ",
    )
    .bind(request.setup_id)
    .bind(session.account_id)
    .bind(session.session_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| {
        AppError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_totp_setup",
            "The TOTP setup is invalid or expired.",
        )
    })?;
    if setup.expires_at <= Utc::now() {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_totp_setup",
            "The TOTP setup is invalid or expired.",
        ));
    }
    let secret = decrypt_mfa_secret(
        &setup.encrypted_secret,
        session.account_id,
        &state.config.mfa_encryption_key,
    )?;
    let secret_text = std::str::from_utf8(&secret).map_err(|_| AppError::internal())?;
    if verify_totp(secret_text, &request.code, Utc::now()).is_none() {
        return Err(AppError::unauthorized());
    }
    sqlx::query(
        r"
        INSERT INTO account_totp (account_id, encrypted_secret, last_used_step)
        VALUES ($1, $2, -1)
        ON CONFLICT (account_id) DO UPDATE
        SET encrypted_secret = EXCLUDED.encrypted_secret,
            last_used_step = -1,
            updated_at = now()
        ",
    )
    .bind(session.account_id)
    .bind(setup.encrypted_secret)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM account_totp_setups WHERE id = $1")
        .bind(request.setup_id)
        .execute(&mut *transaction)
        .await?;
    revoke_all_device_trust(&mut transaction, session.account_id).await?;
    let recovery_codes = ensure_recovery_codes(
        &mut transaction,
        session.account_id,
        &state.config.token_pepper,
    )
    .await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "totp_enabled",
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(MfaEnableResponse { recovery_codes }))
}

/// Disables TOTP after master-password reauthentication.
#[utoipa::path(
    delete,
    path = "/api/v1/account/security/totp",
    security(("bearer" = [])),
    request_body = ReauthenticationRequest,
    responses((status = 204), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn disable_totp(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<ReauthenticationRequest>,
) -> Result<StatusCode, AppError> {
    verify_reauthentication(&state, session.account_id, &request.auth_proof).await?;
    let mut transaction = state.pool.begin().await?;
    let changed = sqlx::query("DELETE FROM account_totp WHERE account_id = $1")
        .bind(session.account_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(AppError::new(
            StatusCode::NOT_FOUND,
            "totp_not_enabled",
            "TOTP is not enabled.",
        ));
    }
    revoke_all_device_trust(&mut transaction, session.account_id).await?;
    remove_recovery_codes_without_factors(&mut transaction, session.account_id).await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "totp_disabled",
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Invalidates all previous recovery codes and returns a fresh one-time set.
#[utoipa::path(
    post,
    path = "/api/v1/account/security/recovery-codes/rotate",
    security(("bearer" = [])),
    request_body = ReauthenticationRequest,
    responses((status = 200, body = RecoveryCodesResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn rotate_recovery_codes(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<ReauthenticationRequest>,
) -> Result<Json<RecoveryCodesResponse>, AppError> {
    verify_reauthentication(&state, session.account_id, &request.auth_proof).await?;
    if !account_has_mfa(&state, session.account_id).await? {
        return Err(AppError::invalid(
            "mfa_not_enabled",
            "Enable a second factor before creating recovery codes.",
        ));
    }
    let mut transaction = state.pool.begin().await?;
    sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = $1")
        .bind(session.account_id)
        .execute(&mut *transaction)
        .await?;
    let codes = insert_recovery_codes(
        &mut transaction,
        session.account_id,
        &state.config.token_pepper,
    )
    .await?;
    revoke_all_device_trust(&mut transaction, session.account_id).await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "recovery_codes_rotated",
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(RecoveryCodesResponse { codes }))
}

/// Starts server-bound `WebAuthn` registration after password reauthentication.
#[utoipa::path(
    post,
    path = "/api/v1/account/security/webauthn/start",
    security(("bearer" = [])),
    request_body = WebauthnRegistrationStartRequest,
    responses((status = 200, body = WebauthnChallengeResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn start_webauthn_registration(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<WebauthnRegistrationStartRequest>,
) -> Result<Json<WebauthnChallengeResponse>, AppError> {
    verify_credential_name(&request.name)?;
    verify_reauthentication(&state, session.account_id, &request.auth_proof).await?;
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM accounts WHERE id = $1")
        .bind(session.account_id)
        .fetch_one(&state.pool)
        .await?;
    let passkeys = load_passkeys(&state, session.account_id).await?;
    let exclude = (!passkeys.is_empty()).then(|| {
        passkeys
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect()
    });
    let (options, registration) = state
        .webauthn
        .start_passkey_registration(session.account_id, &email, &email, exclude)
        .map_err(|_| AppError::internal())?;
    let ceremony_id = Uuid::new_v4();
    let expires_at = Utc::now() + CEREMONY_TTL;
    let state_json = serde_json::to_value(registration).map_err(|_| AppError::internal())?;
    sqlx::query(
        r"
        INSERT INTO webauthn_ceremonies
            (id, account_id, session_id, purpose, state, credential_name, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(ceremony_id)
    .bind(session.account_id)
    .bind(session.session_id)
    .bind(CEREMONY_REGISTRATION)
    .bind(state_json)
    .bind(request.name.trim())
    .bind(expires_at)
    .execute(&state.pool)
    .await?;
    Ok(Json(WebauthnChallengeResponse {
        ceremony_id,
        options: serde_json::to_value(options).map_err(|_| AppError::internal())?,
        expires_at,
    }))
}

/// Finishes a `WebAuthn` registration exactly once and persists only public material.
#[utoipa::path(
    post,
    path = "/api/v1/account/security/webauthn/finish",
    security(("bearer" = [])),
    request_body = WebauthnRegistrationFinishRequest,
    responses((status = 200, body = MfaEnableResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn finish_webauthn_registration(
    State(state): State<AppState>,
    session: AuthSession,
    Json(request): Json<WebauthnRegistrationFinishRequest>,
) -> Result<Json<MfaEnableResponse>, AppError> {
    let credential: RegisterPublicKeyCredential = serde_json::from_value(request.credential)
        .map_err(|_| {
            AppError::invalid(
                "invalid_webauthn_credential",
                "The WebAuthn response is malformed.",
            )
        })?;
    let mut transaction = state.pool.begin().await?;
    let ceremony = sqlx::query_as::<_, RegistrationCeremonyRow>(
        r"
        SELECT state, credential_name, expires_at, consumed_at
        FROM webauthn_ceremonies
        WHERE id = $1 AND account_id = $2 AND session_id = $3 AND purpose = $4
        FOR UPDATE
        ",
    )
    .bind(request.ceremony_id)
    .bind(session.account_id)
    .bind(session.session_id)
    .bind(CEREMONY_REGISTRATION)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(invalid_webauthn_ceremony)?;
    if ceremony.consumed_at.is_some() || ceremony.expires_at <= Utc::now() {
        return Err(invalid_webauthn_ceremony());
    }
    let registration: PasskeyRegistration =
        serde_json::from_value(ceremony.state).map_err(|_| AppError::internal())?;
    let passkey = state
        .webauthn
        .finish_passkey_registration(&credential, &registration)
        .map_err(|_| AppError::unauthorized())?;
    let credential_id = passkey.cred_id().to_vec();
    let passkey_json = serde_json::to_value(&passkey).map_err(|_| AppError::internal())?;
    let insert = sqlx::query(
        r"
        INSERT INTO account_webauthn_credentials
            (id, account_id, credential_id, name, passkey)
        VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(Uuid::new_v4())
    .bind(session.account_id)
    .bind(credential_id)
    .bind(ceremony.credential_name)
    .bind(passkey_json)
    .execute(&mut *transaction)
    .await;
    if let Err(error) = insert {
        if crate::auth::is_unique_violation(&error) {
            return Err(AppError::new(
                StatusCode::CONFLICT,
                "webauthn_credential_exists",
                "This WebAuthn credential is already registered.",
            ));
        }
        return Err(error.into());
    }
    consume_ceremony(&mut transaction, request.ceremony_id).await?;
    revoke_all_device_trust(&mut transaction, session.account_id).await?;
    let recovery_codes = ensure_recovery_codes(
        &mut transaction,
        session.account_id,
        &state.config.token_pepper,
    )
    .await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "webauthn_credential_registered",
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(MfaEnableResponse { recovery_codes }))
}

/// Removes one account `WebAuthn` credential and revokes all trusted-device grants.
#[utoipa::path(
    delete,
    path = "/api/v1/account/security/webauthn/{credential_id}",
    security(("bearer" = [])),
    params(("credential_id" = Uuid, Path, description = "Account WebAuthn credential ID")),
    responses((status = 204), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn delete_webauthn_credential(
    State(state): State<AppState>,
    session: AuthSession,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut transaction = state.pool.begin().await?;
    let changed =
        sqlx::query("DELETE FROM account_webauthn_credentials WHERE id = $1 AND account_id = $2")
            .bind(credential_id)
            .bind(session.account_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    if changed == 0 {
        return Err(AppError::new(
            StatusCode::NOT_FOUND,
            "webauthn_credential_not_found",
            "WebAuthn credential not found.",
        ));
    }
    revoke_all_device_trust(&mut transaction, session.account_id).await?;
    remove_recovery_codes_without_factors(&mut transaction, session.account_id).await?;
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(session.device_id),
        "webauthn_credential_removed",
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Verifies the password proof and starts a `WebAuthn` second-factor ceremony.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login/webauthn/start",
    request_body = WebauthnMfaLoginStartRequest,
    responses((status = 200, body = WebauthnChallengeResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
pub async fn start_webauthn_mfa_login(
    State(state): State<AppState>,
    Json(request): Json<WebauthnMfaLoginStartRequest>,
) -> Result<Json<WebauthnChallengeResponse>, AppError> {
    let email = normalize_email(&request.email)?;
    validate_device(&request.device.name, &request.device.device_type)?;
    state.login_limiter.check(&email)?;
    let account = authenticate_password(&state, &email, &request.auth_proof).await?;
    start_login_ceremony(&state, account.id, CEREMONY_MFA_LOGIN, request.device).await
}

/// Starts passwordless account authentication for an email-associated passkey.
#[utoipa::path(
    post,
    path = "/api/v1/auth/passkey/start",
    request_body = PasskeyLoginStartRequest,
    responses((status = 200, body = WebauthnChallengeResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
pub async fn start_passkey_login(
    State(state): State<AppState>,
    Json(request): Json<PasskeyLoginStartRequest>,
) -> Result<Json<WebauthnChallengeResponse>, AppError> {
    let email = normalize_email(&request.email)?;
    validate_device(&request.device.name, &request.device.device_type)?;
    state.login_limiter.check(&email)?;
    let account_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM accounts WHERE email = $1 AND disabled_at IS NULL",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(AppError::unauthorized)?;
    start_login_ceremony(&state, account_id, CEREMONY_PASSKEY_LOGIN, request.device).await
}

/// Verifies origin, RP ID, challenge, UV, signature, and counter before issuing a session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/finish",
    request_body = WebauthnLoginFinishRequest,
    responses((status = 200, body = TokenResponse), (status = 401, body = hasilan_protocol::ApiErrorBody)),
    tag = "authentication"
)]
#[allow(
    clippy::too_many_lines,
    reason = "signature verification, one-use consumption, counter update, and session issuance remain one auditable transaction"
)]
pub async fn finish_webauthn_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WebauthnLoginFinishRequest>,
) -> Result<Response, AppError> {
    let web_session = web_session_requested(&headers);
    if web_session {
        verify_web_origin(&headers, &state)?;
    }
    let credential: PublicKeyCredential =
        serde_json::from_value(request.credential).map_err(|_| {
            AppError::invalid(
                "invalid_webauthn_credential",
                "The WebAuthn response is malformed.",
            )
        })?;
    let mut transaction = state.pool.begin().await?;
    let ceremony = sqlx::query_as::<_, LoginCeremonyRow>(
        r"
        SELECT account_id, purpose, state, device_identifier, device_name, device_type,
               expires_at, consumed_at
        FROM webauthn_ceremonies
        WHERE id = $1 AND purpose IN ($2, $3)
        FOR UPDATE
        ",
    )
    .bind(request.ceremony_id)
    .bind(CEREMONY_MFA_LOGIN)
    .bind(CEREMONY_PASSKEY_LOGIN)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(invalid_webauthn_ceremony)?;
    if ceremony.consumed_at.is_some() || ceremony.expires_at <= Utc::now() {
        return Err(invalid_webauthn_ceremony());
    }
    let authentication: PasskeyAuthentication =
        serde_json::from_value(ceremony.state).map_err(|_| AppError::internal())?;
    let authentication_result = state
        .webauthn
        .finish_passkey_authentication(&credential, &authentication)
        .map_err(|_| AppError::unauthorized())?;
    let credential_id = authentication_result.cred_id().to_vec();
    let stored = sqlx::query_as::<_, StoredPasskeyRow>(
        r"
        SELECT id, passkey
        FROM account_webauthn_credentials
        WHERE account_id = $1 AND credential_id = $2
        FOR UPDATE
        ",
    )
    .bind(ceremony.account_id)
    .bind(&credential_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(AppError::unauthorized)?;
    let mut passkey: Passkey =
        serde_json::from_value(stored.passkey).map_err(|_| AppError::internal())?;
    passkey
        .update_credential(&authentication_result)
        .ok_or_else(AppError::unauthorized)?;
    sqlx::query(
        "UPDATE account_webauthn_credentials SET passkey = $1, last_used_at = now() WHERE id = $2",
    )
    .bind(serde_json::to_value(passkey).map_err(|_| AppError::internal())?)
    .bind(stored.id)
    .execute(&mut *transaction)
    .await?;
    consume_ceremony(&mut transaction, request.ceremony_id).await?;

    let material = load_session_material(&mut transaction, ceremony.account_id).await?;
    let device_identifier = ceremony.device_identifier.ok_or_else(AppError::internal)?;
    let device_name = ceremony.device_name.ok_or_else(AppError::internal)?;
    let device_type = ceremony.device_type.ok_or_else(AppError::internal)?;
    let device_id = upsert_device(
        &mut transaction,
        ceremony.account_id,
        device_identifier,
        &device_name,
        &device_type,
    )
    .await?;
    let mut tokens = create_session(
        &mut transaction,
        &state,
        ceremony.account_id,
        device_id,
        material.protected_user_key,
        kdf_from_db(
            material.kdf_type,
            material.kdf_iterations,
            material.kdf_memory_mib,
            material.kdf_parallelism,
        )?,
    )
    .await?;
    if request.remember_device {
        tokens.trusted_device_token =
            Some(issue_trusted_device(&mut transaction, &state, device_id).await?);
    }
    let event_type = if ceremony.purpose == CEREMONY_PASSKEY_LOGIN {
        "login_succeeded_passkey"
    } else {
        "login_succeeded_webauthn_mfa"
    };
    insert_event(
        &mut transaction,
        Some(ceremony.account_id),
        Some(device_id),
        event_type,
    )
    .await?;
    transaction.commit().await?;
    state.login_limiter.clear(&material.email);
    token_response(tokens, &state, web_session)
}

/// Revokes a device's persistent MFA bypass grant without deleting device history.
#[utoipa::path(
    delete,
    path = "/api/v1/account/devices/{device_id}/trust",
    security(("bearer" = [])),
    params(("device_id" = Uuid, Path, description = "Account device ID")),
    responses((status = 204), (status = 404, body = hasilan_protocol::ApiErrorBody)),
    tag = "account security"
)]
pub async fn revoke_device_trust(
    State(state): State<AppState>,
    session: AuthSession,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut transaction = state.pool.begin().await?;
    let changed = sqlx::query(
        r"
        UPDATE devices
        SET trusted = false, trusted_token_hash = NULL, trusted_until = NULL
        WHERE id = $1 AND account_id = $2 AND trusted = true
        ",
    )
    .bind(device_id)
    .bind(session.account_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::new(
            StatusCode::NOT_FOUND,
            "trusted_device_not_found",
            "Trusted device not found.",
        ));
    }
    insert_event(
        &mut transaction,
        Some(session.account_id),
        Some(device_id),
        "device_trust_revoked",
    )
    .await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Enforces account second factors inside the password-login transaction.
pub(crate) async fn verify_login_second_factor(
    transaction: &mut Transaction<'_, Postgres>,
    state: &AppState,
    account_id: Uuid,
    request: &LoginRequest,
) -> Result<SecondFactorOutcome, AppError> {
    let factor_count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT
            (SELECT count(*) FROM account_totp WHERE account_id = $1)
          + (SELECT count(*) FROM account_webauthn_credentials WHERE account_id = $1)
        ",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if factor_count == 0 {
        return Ok(SecondFactorOutcome::NotRequired);
    }

    if let Some(token) = request.trusted_device_token.as_deref()
        && verify_trusted_device(
            transaction,
            state,
            account_id,
            request.device.identifier,
            token,
        )
        .await?
    {
        return Ok(SecondFactorOutcome::TrustedDevice);
    }

    if request.totp_code.is_some() && request.recovery_code.is_some() {
        return Err(AppError::invalid(
            "ambiguous_second_factor",
            "Provide exactly one second-factor response.",
        ));
    }
    if let Some(code) = request.totp_code.as_deref() {
        if consume_totp(transaction, state, account_id, code).await? {
            return Ok(SecondFactorOutcome::Totp);
        }
        return Err(AppError::unauthorized());
    }
    if let Some(code) = request.recovery_code.as_deref() {
        if consume_recovery_code(transaction, account_id, code, &state.config.token_pepper).await? {
            return Ok(SecondFactorOutcome::RecoveryCode);
        }
        return Err(AppError::unauthorized());
    }
    Err(AppError::new(
        StatusCode::UNAUTHORIZED,
        "mfa_required",
        "A second factor is required.",
    ))
}

/// Issues trust only after an explicit full factor; ordinary or trusted logins cannot extend it.
pub(crate) async fn maybe_issue_login_trust(
    transaction: &mut Transaction<'_, Postgres>,
    state: &AppState,
    device_id: Uuid,
    outcome: SecondFactorOutcome,
    remember_device: bool,
) -> Result<Option<String>, AppError> {
    if remember_device && outcome.is_full_mfa() {
        return issue_trusted_device(transaction, state, device_id)
            .await
            .map(Some);
    }
    Ok(None)
}

async fn verify_reauthentication(
    state: &AppState,
    account_id: Uuid,
    encoded_proof: &str,
) -> Result<(), AppError> {
    let proof = decode_auth_proof(encoded_proof)?;
    let verifier = sqlx::query_scalar::<_, String>(
        "SELECT auth_verifier FROM accounts WHERE id = $1 AND disabled_at IS NULL",
    )
    .bind(account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(AppError::unauthorized)?;
    if !verify_auth_proof(proof, verifier, Arc::clone(&state.config.token_pepper)).await? {
        return Err(AppError::unauthorized());
    }
    Ok(())
}

async fn authenticate_password(
    state: &AppState,
    email: &str,
    encoded_proof: &str,
) -> Result<PasswordAccountRow, AppError> {
    let proof = decode_auth_proof(encoded_proof)?;
    let account = sqlx::query_as::<_, PasswordAccountRow>(
        "SELECT id, auth_verifier FROM accounts WHERE email = $1 AND disabled_at IS NULL",
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await?;
    let Some(account) = account else {
        let _ = hash_auth_proof(proof, Arc::clone(&state.config.token_pepper)).await;
        return Err(AppError::unauthorized());
    };
    if !verify_auth_proof(
        proof,
        account.auth_verifier.clone(),
        Arc::clone(&state.config.token_pepper),
    )
    .await?
    {
        return Err(AppError::unauthorized());
    }
    Ok(account)
}

async fn start_login_ceremony(
    state: &AppState,
    account_id: Uuid,
    purpose: i16,
    device: DeviceRequest,
) -> Result<Json<WebauthnChallengeResponse>, AppError> {
    let passkeys = load_passkeys(state, account_id).await?;
    if passkeys.is_empty() {
        return Err(AppError::unauthorized());
    }
    let (options, authentication) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| AppError::internal())?;
    let ceremony_id = Uuid::new_v4();
    let expires_at = Utc::now() + CEREMONY_TTL;
    sqlx::query(
        r"
        INSERT INTO webauthn_ceremonies
            (id, account_id, purpose, state, device_identifier, device_name, device_type, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(ceremony_id)
    .bind(account_id)
    .bind(purpose)
    .bind(serde_json::to_value(authentication).map_err(|_| AppError::internal())?)
    .bind(device.identifier)
    .bind(device.name)
    .bind(device.device_type)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;
    Ok(Json(WebauthnChallengeResponse {
        ceremony_id,
        options: serde_json::to_value(options).map_err(|_| AppError::internal())?,
        expires_at,
    }))
}

async fn load_passkeys(state: &AppState, account_id: Uuid) -> Result<Vec<Passkey>, AppError> {
    let values = sqlx::query_scalar::<_, Value>(
        "SELECT passkey FROM account_webauthn_credentials WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;
    values
        .into_iter()
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::internal()))
        .collect()
}

async fn consume_ceremony(
    transaction: &mut Transaction<'_, Postgres>,
    ceremony_id: Uuid,
) -> Result<(), AppError> {
    let changed = sqlx::query(
        "UPDATE webauthn_ceremonies SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(ceremony_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(invalid_webauthn_ceremony());
    }
    Ok(())
}

async fn load_session_material(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
) -> Result<SessionMaterialRow, AppError> {
    sqlx::query_as::<_, SessionMaterialRow>(
        r"
        SELECT email, protected_user_key, kdf_type, kdf_iterations,
               kdf_memory_mib, kdf_parallelism
        FROM accounts WHERE id = $1 AND disabled_at IS NULL
        ",
    )
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(AppError::unauthorized)
}

async fn account_has_mfa(state: &AppState, account_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS(SELECT 1 FROM account_totp WHERE account_id = $1)
            OR EXISTS(SELECT 1 FROM account_webauthn_credentials WHERE account_id = $1)
        ",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await
    .map_err(Into::into)
}

async fn consume_totp(
    transaction: &mut Transaction<'_, Postgres>,
    state: &AppState,
    account_id: Uuid,
    code: &str,
) -> Result<bool, AppError> {
    let row = sqlx::query_as::<_, TotpLoginRow>(
        "SELECT encrypted_secret, last_used_step FROM account_totp WHERE account_id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let secret = decrypt_mfa_secret(
        &row.encrypted_secret,
        account_id,
        &state.config.mfa_encryption_key,
    )?;
    let secret = std::str::from_utf8(&secret).map_err(|_| AppError::internal())?;
    let Some(step) = verify_totp(secret, code, Utc::now()) else {
        return Ok(false);
    };
    if step <= row.last_used_step {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE account_totp SET last_used_step = $1, updated_at = now() WHERE account_id = $2",
    )
    .bind(step)
    .bind(account_id)
    .execute(&mut **transaction)
    .await?;
    Ok(true)
}

fn verify_totp(secret: &str, supplied: &str, now: DateTime<Utc>) -> Option<i64> {
    let supplied = normalize_totp(supplied)?;
    let config = TotpConfig::parse(secret).ok()?;
    let current_step = now.timestamp().checked_div(i64::from(config.period))?;
    for offset in [-1_i64, 0, 1] {
        let step = current_step.checked_add(offset)?;
        let timestamp = u64::try_from(step.checked_mul(i64::from(config.period))?).ok()?;
        let expected = config.generate_at(timestamp).ok()?.code;
        if expected.as_bytes().ct_eq(supplied.as_bytes()).into() {
            return Some(step);
        }
    }
    None
}

fn normalize_totp(value: &str) -> Option<String> {
    let normalized: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .collect();
    (normalized.len() == 6 && normalized.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(normalized)
}

async fn consume_recovery_code(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    supplied: &str,
    pepper: &TokenPepper,
) -> Result<bool, AppError> {
    let Some(normalized) = normalize_recovery_code(supplied) else {
        return Ok(false);
    };
    let hash = recovery_code_hash(account_id, normalized.as_bytes(), pepper);
    let changed = sqlx::query(
        r"
        UPDATE account_recovery_codes SET used_at = now()
        WHERE account_id = $1 AND code_hash = $2 AND used_at IS NULL
        ",
    )
    .bind(account_id)
    .bind(hash)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    Ok(changed == 1)
}

async fn ensure_recovery_codes(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    pepper: &TokenPepper,
) -> Result<Vec<String>, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM account_recovery_codes WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if count == 0 {
        insert_recovery_codes(transaction, account_id, pepper).await
    } else {
        Ok(Vec::new())
    }
}

async fn insert_recovery_codes(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    pepper: &TokenPepper,
) -> Result<Vec<String>, AppError> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = Zeroizing::new([0_u8; RECOVERY_CODE_BYTES]);
        getrandom::fill(bytes.as_mut()).map_err(|_| AppError::internal())?;
        let raw = Zeroizing::new(BASE32_NOPAD.encode(bytes.as_ref()));
        let displayed = format!(
            "HP-{}-{}-{}-{}",
            &raw[0..4],
            &raw[4..8],
            &raw[8..12],
            &raw[12..16]
        );
        let hash = recovery_code_hash(account_id, raw.as_bytes(), pepper);
        sqlx::query(
            "INSERT INTO account_recovery_codes (id, account_id, code_hash) VALUES ($1, $2, $3)",
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(hash)
        .execute(&mut **transaction)
        .await?;
        codes.push(displayed);
    }
    Ok(codes)
}

fn normalize_recovery_code(value: &str) -> Option<Zeroizing<String>> {
    let mut normalized = Zeroizing::new(
        value
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_uppercase(),
    );
    if normalized.starts_with("HP") {
        normalized.drain(..2);
    }
    let valid = normalized.len() == 16
        && normalized
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte));
    valid.then_some(normalized)
}

fn recovery_code_hash(account_id: Uuid, normalized: &[u8], pepper: &TokenPepper) -> [u8; 32] {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(pepper.bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts a 32-byte key"));
    hmac.update(RECOVERY_HASH_DOMAIN);
    hmac.update(account_id.as_bytes());
    hmac.update(normalized);
    hmac.finalize().into_bytes().into()
}

async fn verify_trusted_device(
    transaction: &mut Transaction<'_, Postgres>,
    state: &AppState,
    account_id: Uuid,
    identifier: Uuid,
    token: &str,
) -> Result<bool, AppError> {
    if token.is_empty() || token.len() > 256 {
        return Ok(false);
    }
    let hash = hash_token(token, &state.config.token_pepper);
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS(
            SELECT 1 FROM devices
            WHERE account_id = $1 AND identifier = $2 AND trusted = true
              AND trusted_until > now() AND trusted_token_hash = $3
        )
        ",
    )
    .bind(account_id)
    .bind(identifier)
    .bind(hash)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn issue_trusted_device(
    transaction: &mut Transaction<'_, Postgres>,
    state: &AppState,
    device_id: Uuid,
) -> Result<String, AppError> {
    let token = generate_token()?;
    let hash = hash_token(&token, &state.config.token_pepper);
    let trusted_until = Utc::now() + chrono_duration(state.config.trusted_device_ttl)?;
    sqlx::query(
        r"
        UPDATE devices
        SET trusted = true, trusted_token_hash = $1, trusted_until = $2
        WHERE id = $3
        ",
    )
    .bind(hash)
    .bind(trusted_until)
    .bind(device_id)
    .execute(&mut **transaction)
    .await?;
    Ok(token)
}

async fn revoke_all_device_trust(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE devices
        SET trusted = false, trusted_token_hash = NULL, trusted_until = NULL
        WHERE account_id = $1 AND trusted = true
        ",
    )
    .bind(account_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn remove_recovery_codes_without_factors(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
) -> Result<(), AppError> {
    let has_factor = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS(SELECT 1 FROM account_totp WHERE account_id = $1)
            OR EXISTS(SELECT 1 FROM account_webauthn_credentials WHERE account_id = $1)
        ",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !has_factor {
        sqlx::query("DELETE FROM account_recovery_codes WHERE account_id = $1")
            .bind(account_id)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn build_totp_uri(email: &str, secret: &str) -> Result<String, AppError> {
    let mut uri = Url::parse("otpauth://totp/").map_err(|_| AppError::internal())?;
    uri.set_path(&format!("/Hasilan Pass:{email}"));
    uri.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", "Hasilan Pass")
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", "30");
    Ok(uri.to_string())
}

fn verify_credential_name(name: &str) -> Result<(), AppError> {
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(AppError::invalid(
            "invalid_credential_name",
            "Credential name is invalid.",
        ));
    }
    Ok(())
}

fn invalid_webauthn_ceremony() -> AppError {
    AppError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_webauthn_ceremony",
        "The WebAuthn ceremony is invalid or expired.",
    )
}

#[derive(FromRow)]
struct WebauthnCredentialRow {
    id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl WebauthnCredentialRow {
    fn into_response(self) -> WebauthnCredentialResponse {
        WebauthnCredentialResponse {
            id: self.id,
            name: self.name,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        }
    }
}

#[derive(FromRow)]
struct TotpSetupRow {
    encrypted_secret: String,
    expires_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct TotpLoginRow {
    encrypted_secret: String,
    last_used_step: i64,
}

#[derive(FromRow)]
struct PasswordAccountRow {
    id: Uuid,
    auth_verifier: String,
}

#[derive(FromRow)]
struct RegistrationCeremonyRow {
    state: Value,
    credential_name: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct LoginCeremonyRow {
    account_id: Uuid,
    purpose: i16,
    state: Value,
    device_identifier: Option<Uuid>,
    device_name: Option<String>,
    device_type: Option<String>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct StoredPasskeyRow {
    id: Uuid,
    passkey: Value,
}

#[derive(FromRow)]
struct SessionMaterialRow {
    email: String,
    protected_user_key: String,
    kdf_type: i16,
    kdf_iterations: i32,
    kdf_memory_mib: Option<i32>,
    kdf_parallelism: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_normalization_and_hash_are_scoped() {
        let pepper = TokenPepper::from_bytes([7; 32]);
        let account = Uuid::new_v4();
        let normalized = normalize_recovery_code("hp-abcd-efgh-jk23-mn45")
            .unwrap_or_else(|| panic!("normalization failed"));
        assert_eq!(normalized.as_str(), "ABCDEFGHJK23MN45");
        assert_ne!(
            recovery_code_hash(account, normalized.as_bytes(), &pepper),
            recovery_code_hash(Uuid::new_v4(), normalized.as_bytes(), &pepper)
        );
        assert!(normalize_recovery_code("not-a-code").is_none());
    }

    #[test]
    fn totp_accepts_window_but_normalizes_only_six_digits() {
        let now =
            DateTime::from_timestamp(1_234_567_890, 0).unwrap_or_else(|| panic!("valid timestamp"));
        let secret = "JBSWY3DPEHPK3PXP";
        let current = TotpConfig::parse(secret)
            .and_then(|config| config.generate_at(1_234_567_890))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(verify_totp(secret, &current.code, now).is_some());
        assert!(verify_totp(secret, "12ab56", now).is_none());
    }
}
