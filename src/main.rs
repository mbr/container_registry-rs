mod config;
pub(crate) mod registry;

use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use anyhow::Context;
use axum::{extract::DefaultBodyLimit, Router};

use gethostname::gethostname;
use registry::ContainerRegistry;
use tower_http::trace::TraceLayer;
use tracing::{debug, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::load_config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse configuration, if available, otherwise use a default.
    let cfg = load_config().context("could not load configuration")?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| (&cfg.rockslide.log).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!(?cfg, "loaded configuration");

    let rockslide_pw = cfg.rockslide.master_key.as_secret_string();
    let auth_provider = Arc::new(cfg.rockslide.master_key);

    let registry = ContainerRegistry::new(&cfg.registry.storage_path, (), auth_provider)?;

    let app = Router::new()
        .merge(registry.make_router())
        .layer(DefaultBodyLimit::max(1024 * 1024)) // See #43.
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(("localhost", 0))
        .await
        .context("failed to bind listener")?;
    axum::serve(listener, app)
        .await
        .context("http server exited with error")?;

    Ok(())
}
