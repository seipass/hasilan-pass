use axum::{Json, http::StatusCode, response::IntoResponse};
use hasilan_protocol::ApiErrorBody;
use serde_json::{Value, json};
use thiserror::Error;

/// Deliberately non-sensitive application error.
#[derive(Debug, Error)]
#[error("{code}")]
pub struct AppError {
    /// HTTP status returned to the caller.
    pub status: StatusCode,
    /// Stable non-secret machine code.
    pub code: &'static str,
    /// Non-sensitive user-facing summary.
    pub message: &'static str,
    /// Optional safe structured details.
    pub details: Option<Value>,
}

impl AppError {
    /// Creates a non-sensitive application error.
    #[must_use]
    pub const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            details: None,
        }
    }

    /// Creates an optimistic concurrency error containing only ciphertext metadata.
    #[must_use]
    pub fn conflict(current: &Value) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "revision_conflict",
            message: "The object changed on another client.",
            details: Some(json!({ "current": current })),
        }
    }

    /// Creates the deliberately indistinguishable authentication failure.
    #[must_use]
    pub const fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "Authentication failed.",
        )
    }

    /// Creates a request validation error.
    #[must_use]
    pub const fn invalid(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// Creates the generic internal failure returned for unexpected conditions.
    #[must_use]
    pub const fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "The request could not be completed.",
        )
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        if let Some(details) = self.details {
            return (
                self.status,
                Json(json!({
                    "code": self.code,
                    "message": self.message,
                    "requestId": Value::Null,
                    "details": details,
                })),
            )
                .into_response();
        }
        (
            self.status,
            Json(ApiErrorBody {
                code: self.code.to_owned(),
                message: self.message.to_owned(),
                request_id: None,
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(
            error.category = database_error_category(&error),
            "database operation failed"
        );
        Self::internal()
    }
}

fn database_error_category(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::RowNotFound => "row_not_found",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::Io(_) => "io",
        _ => "other",
    }
}
