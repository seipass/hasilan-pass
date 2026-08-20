use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use sqlx::PgPool;
use webauthn_rs::prelude::Webauthn;

use crate::{config::Config, error::AppError, invitation_delivery::InvitationDelivery};

/// Shared application dependencies.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub login_limiter: LoginLimiter,
    pub webauthn: Arc<Webauthn>,
    pub invitation_delivery: InvitationDelivery,
}

/// Small in-process per-account login limiter. Reverse proxies should add an IP limiter too.
#[derive(Clone, Default)]
pub struct LoginLimiter {
    attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl LoginLimiter {
    const WINDOW: Duration = Duration::from_mins(5);
    const MAX_ATTEMPTS: usize = 8;

    pub fn check(&self, account_key: &str) -> Result<(), AppError> {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().map_err(|_| AppError::internal())?;
        let entries = attempts.entry(account_key.to_owned()).or_default();
        entries.retain(|timestamp| now.duration_since(*timestamp) < Self::WINDOW);
        if entries.len() >= Self::MAX_ATTEMPTS {
            return Err(AppError::new(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many authentication attempts. Try again later.",
            ));
        }
        entries.push(now);
        Ok(())
    }

    pub fn clear(&self, account_key: &str) {
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts.remove(account_key);
        }
    }
}
