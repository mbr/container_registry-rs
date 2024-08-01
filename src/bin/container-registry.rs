use std::{fmt, fs, net::SocketAddr, path, process::ExitCode, sync::Arc};

use anyhow::Context;
use axum::{async_trait, extract::DefaultBodyLimit, Router};
use container_registry::{
    auth::{self, AuthProvider},
    hooks::RegistryHooks,
    storage::ManifestReference,
};
use sec::Secret;
use structopt::StructOpt;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn, Level};

#[derive(Debug, StructOpt)]
struct Opts {
    /// Which address to bind to.
    #[structopt(short, long, default_value = "127.0.0.1:3000")]
    bind: SocketAddr,
    /// Directory to use as storage.
    #[structopt(short, long)]
    storage: Option<path::PathBuf>,
    /// Password to require.
    #[structopt(short, long)]
    password: Option<String>,
}

struct LoggingHook;

#[async_trait]

impl RegistryHooks for LoggingHook {
    /// Notify about an uploaded manifest.
    async fn on_manifest_uploaded(&self, manifest_reference: &ManifestReference) {
        info!(%manifest_reference, "new manifest uploaded");
    }
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(Level::INFO.into()),
        )
        .init();

    let opts = Opts::from_args();

    let (_tmpdir, storage) = if let Some(storage) = opts.storage {
        info!(path=%storage.display(), "storage set");
        if !storage.exists() {
            fs::create_dir(&storage).context("could not create non-existant storage dir")?;
        }

        (None, storage)
    } else {
        let tmp_dir = tempdir::TempDir::new("container_registry_test")
            .context("could not create temporary storage dir")?;
        let storage = tmp_dir.path().to_owned();

        info!(path=%storage.display(), "using temporary storage");
        (Some(tmp_dir), storage)
    };

    let auth_provider: Arc<dyn AuthProvider> = if let Some(password) = opts.password {
        info!("using password supplied on command line");
        let password = Secret::new(password);
        Arc::new(password)
    } else {
        warn!("no password set, allowing access with any credential");
        Arc::new(auth::Permissions::ReadWrite)
    };

    let registry = container_registry::ContainerRegistry::builder()
        .storage(storage)
        .hooks(Box::new(LoggingHook))
        .auth_provider(auth_provider)
        .build()
        .context("failed to instantiate registry")?;

    let app = Router::new()
        .merge(registry.make_router())
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .context("failed to bind listener")?;

    let addr = listener
        .local_addr()
        .context("failed to get local listener address")?;
    info!(%addr, "bound, starting to serve");

    axum::serve(listener, app).await?;

    Ok(())
}

struct FormatErr(anyhow::Error);

impl fmt::Display for FormatErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, err) in self.0.chain().enumerate() {
            if idx != 0 {
                f.write_str(": ")?;
            }

            fmt::Display::fmt(err, f)?;
        }

        Ok(())
    }
}

#[tokio::main]

async fn main() -> ExitCode {
    if let Err(err) = run().await {
        error!(err=%FormatErr(err), "failed");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
