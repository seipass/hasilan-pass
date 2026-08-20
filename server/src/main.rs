//! Hasilan Pass synchronization server executable.

use std::sync::Arc;

use anyhow::Context;
use hasilan_server::{Config, build_router, connect_database};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("hasilan_server=info,tower_http=info")),
        )
        .json()
        .init();
    let config = Arc::new(Config::from_env()?);
    let pool = connect_database(&config)
        .await
        .context("database initialization failed")?;
    let app = build_router(Arc::clone(&config), pool)?;
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(bind = %config.bind, public_url = %config.public_url, "server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error.kind = ?error.kind(), "failed to install ctrl-c handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(error.kind = ?error.kind(), "failed to install terminate handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown requested");
}
