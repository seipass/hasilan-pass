//! Axum synchronization server. Vault ciphertext remains opaque to this crate.

mod account_security;
mod attachments;
mod auth;
mod config;
mod error;
mod invitation_delivery;
mod organizations;
mod server_secret;
mod state;
mod sync_api;
mod token;
mod vault;

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware,
    routing::{delete, get, post, put},
};
use hasilan_protocol::HealthResponse;
use invitation_delivery::InvitationDelivery;
use sqlx::{PgPool, postgres::PgPoolOptions};
use state::{AppState, LoginLimiter};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use webauthn_rs::prelude::WebauthnBuilder;

pub use config::{
    Config, InvitationDeliveryConfig, MfaEncryptionKey, SmtpConfig, SmtpPassword, SmtpTls,
    TokenPepper,
};
pub use error::AppError;

const MAX_API_BODY_BYTES: usize = 3 * 1024 * 1024;

#[derive(OpenApi)]
#[openapi(
    paths(
        health_live,
        health_ready,
        auth::prelogin,
        auth::register,
        auth::login,
        auth::refresh,
        auth::logout,
        account_security::status,
        account_security::start_totp_setup,
        account_security::finish_totp_setup,
        account_security::disable_totp,
        account_security::rotate_recovery_codes,
        account_security::start_webauthn_registration,
        account_security::finish_webauthn_registration,
        account_security::delete_webauthn_credential,
        account_security::start_webauthn_mfa_login,
        account_security::start_passkey_login,
        account_security::finish_webauthn_login,
        account_security::revoke_device_trust,
        attachments::initiate,
        attachments::list_for_object,
        attachments::status,
        attachments::put_chunk,
        attachments::complete,
        attachments::get_chunk,
        attachments::delete_attachment,
        organizations::put_sharing_key,
        organizations::get_sharing_key,
        organizations::lookup_sharing_key,
        organizations::create_organization,
        organizations::list_organizations,
        organizations::get_organization,
        organizations::invite_member,
        organizations::accept_invitation,
        organizations::list_members,
        organizations::confirm_member,
        organizations::change_member_role,
        organizations::remove_member,
        organizations::create_collection,
        organizations::list_collections,
        organizations::update_collection,
        organizations::delete_collection,
        organizations::put_collection_access,
        organizations::delete_collection_access,
        vault::get_object,
        vault::put_object,
        vault::delete_object,
        sync_api::sync,
    ),
    tags(
        (name = "health", description = "Container health"),
        (name = "authentication", description = "Zero-knowledge authentication and sessions"),
        (name = "account security", description = "MFA, recovery, passkeys, and trusted devices"),
        (name = "attachments", description = "Opaque resumable encrypted attachment chunks"),
        (name = "organizations", description = "Zero-knowledge organizations, membership, and collections"),
        (name = "vault", description = "Opaque encrypted vault objects"),
        (name = "synchronization", description = "Cursor-based encrypted change feed"),
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .build(),
                ),
            );
        }
    }
}

/// Connects `PostgreSQL` and applies embedded migrations.
///
/// # Errors
///
/// Returns an error if the pool cannot connect or a migration fails.
pub async fn connect_database(config: &Config) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("../migrations").run(&pool).await?;
    Ok(pool)
}

/// Constructs the complete HTTP application for production or integration tests.
///
/// # Errors
///
/// Returns an error if a configured CORS origin cannot be encoded as a header.
pub fn build_router(config: Arc<Config>, pool: PgPool) -> anyhow::Result<Router> {
    let origins = config
        .allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin))
        .collect::<Result<Vec<_>, _>>()?;
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static(auth::CSRF_HEADER),
            HeaderName::from_static(auth::WEB_SESSION_HEADER),
        ])
        .expose_headers([HeaderName::from_static(auth::CSRF_HEADER)])
        .allow_credentials(true)
        .max_age(Duration::from_mins(10));
    let mut webauthn_builder =
        WebauthnBuilder::new(&config.webauthn_rp_id, &config.webauthn_origin)?;
    for origin in config.webauthn_additional_origins.iter() {
        webauthn_builder = webauthn_builder.append_allowed_origin(origin);
    }
    let webauthn = webauthn_builder.rp_name(&config.webauthn_rp_name).build()?;
    let invitation_delivery = InvitationDelivery::from_config(&config.invitation_delivery)?;
    let state = AppState {
        pool,
        config,
        login_limiter: LoginLimiter::default(),
        webauthn: Arc::new(webauthn),
        invitation_delivery,
    };
    let router = Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/api/openapi.json", get(openapi))
        .nest("/api/v1", api_routes());
    let request_id_header = HeaderName::from_static("x-request-id");
    Ok(router
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .layer(middleware::from_fn(security_headers))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors))
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/prelogin", post(auth::prelogin))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route(
            "/auth/login/webauthn/start",
            post(account_security::start_webauthn_mfa_login),
        )
        .route(
            "/auth/passkey/start",
            post(account_security::start_passkey_login),
        )
        .route(
            "/auth/webauthn/finish",
            post(account_security::finish_webauthn_login),
        )
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/logout", post(auth::logout))
        .route("/account/sessions", get(auth::list_sessions))
        .route(
            "/account/sessions/{session_id}",
            delete(auth::revoke_session),
        )
        .route("/account/devices", get(auth::list_devices))
        .route(
            "/account/devices/{device_id}/trust",
            delete(account_security::revoke_device_trust),
        )
        .route("/account/security", get(account_security::status))
        .route(
            "/account/security/totp/start",
            post(account_security::start_totp_setup),
        )
        .route(
            "/account/security/totp/finish",
            post(account_security::finish_totp_setup),
        )
        .route(
            "/account/security/totp",
            delete(account_security::disable_totp),
        )
        .route(
            "/account/security/recovery-codes/rotate",
            post(account_security::rotate_recovery_codes),
        )
        .route(
            "/account/security/webauthn/start",
            post(account_security::start_webauthn_registration),
        )
        .route(
            "/account/security/webauthn/finish",
            post(account_security::finish_webauthn_registration),
        )
        .route(
            "/account/security/webauthn/{credential_id}",
            delete(account_security::delete_webauthn_credential),
        )
        .route("/vault/objects/{id}", get(vault::get_object))
        .route("/vault/objects/{id}", put(vault::put_object))
        .route("/vault/objects/{id}", delete(vault::delete_object))
        .route(
            "/vault/objects/{object_id}/attachments",
            get(attachments::list_for_object),
        )
        .route("/attachments", post(attachments::initiate))
        .route(
            "/attachments/{id}",
            get(attachments::status).delete(attachments::delete_attachment),
        )
        .route(
            "/attachments/{id}/chunks/{index}",
            get(attachments::get_chunk).put(attachments::put_chunk),
        )
        .route("/attachments/{id}/complete", post(attachments::complete))
        .route("/sync", get(sync_api::sync))
        .merge(organization_routes())
}

fn organization_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/account/sharing-key",
            get(organizations::get_sharing_key).put(organizations::put_sharing_key),
        )
        .route(
            "/directory/sharing-key",
            get(organizations::lookup_sharing_key),
        )
        .route(
            "/organizations",
            get(organizations::list_organizations).post(organizations::create_organization),
        )
        .route(
            "/organizations/invitations/accept",
            post(organizations::accept_invitation),
        )
        .route(
            "/organizations/{organization_id}",
            get(organizations::get_organization),
        )
        .route(
            "/organizations/{organization_id}/invitations",
            post(organizations::invite_member),
        )
        .route(
            "/organizations/{organization_id}/members",
            get(organizations::list_members),
        )
        .route(
            "/organizations/{organization_id}/members/{member_id}/confirm",
            post(organizations::confirm_member),
        )
        .route(
            "/organizations/{organization_id}/members/{member_id}/role",
            put(organizations::change_member_role),
        )
        .route(
            "/organizations/{organization_id}/members/{member_id}",
            delete(organizations::remove_member),
        )
        .route(
            "/organizations/{organization_id}/collections",
            get(organizations::list_collections).post(organizations::create_collection),
        )
        .route(
            "/organizations/{organization_id}/collections/{collection_id}",
            put(organizations::update_collection).delete(organizations::delete_collection),
        )
        .route(
            "/organizations/{organization_id}/collections/{collection_id}/access/{member_id}",
            put(organizations::put_collection_access)
                .delete(organizations::delete_collection_access),
        )
}

async fn security_headers(
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    response
}

#[utoipa::path(
    get,
    path = "/health/live",
    responses((status = 200, body = HealthResponse)),
    tag = "health"
)]
async fn health_live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        database: None,
    })
}

#[utoipa::path(
    get,
    path = "/health/ready",
    responses((status = 200, body = HealthResponse), (status = 503, body = HealthResponse)),
    tag = "health"
)]
async fn health_ready(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let ready = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(HealthResponse {
            status: if ready { "ok" } else { "unavailable" }.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            database: Some(if ready { "ok" } else { "unavailable" }.to_owned()),
        }),
    )
}

async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
