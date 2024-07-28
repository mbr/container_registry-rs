mod config;
pub(crate) mod podman;
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

use crate::{config::load_config, podman::podman_is_remote};

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

    let local_ip: IpAddr = if podman_is_remote() {
        debug!("podman instance is remote, trying to guess our external IP address");
        let local_hostname = gethostname();
        let dummy_addr = (
            local_hostname
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("local hostname is not valid UTF8"))?,
            12345,
        )
            .to_socket_addrs()
            .ok()
            .and_then(|addrs| addrs.into_iter().find(SocketAddr::is_ipv4))
            .ok_or_else(|| anyhow::anyhow!("failed to resolve local hostname to ipv4"))?;
        dummy_addr.ip()
    } else {
        debug!("podman is running locally, using localhost IP");
        [127, 0, 0, 1].into()
    };

    // The address under which our application is reachable, will be passed to podman.
    let local_addr = SocketAddr::from((local_ip, cfg.reverse_proxy.http_bind.port()));

    info!(%local_addr, "guessed local registry (i.e. our) address");

    let registry = ContainerRegistry::new(&cfg.registry.storage_path, (), auth_provider)?;

    let app = Router::new()
        .merge(registry.make_router())
        .layer(DefaultBodyLimit::max(1024 * 1024)) // See #43.
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(cfg.reverse_proxy.http_bind)
        .await
        .context("failed to bind listener")?;
    axum::serve(listener, app)
        .await
        .context("http server exited with error")?;

    Ok(())
}
