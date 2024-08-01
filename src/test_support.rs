//! Testing support.
//!
//! Requires the `test-support` feature to be enabled.
//!
//! This module contains utility functions to make it easier to both test the `container-registry`
//! itself, as well as provide support when implementing tests in other crate that may need access
//! to a container registry.
//!
//! ## Creating instances for testing
//!
//! Start by constructing a registry with the [`ContainerRegistryBuilder::build_for_testing`]
//! method instead of the regular [`ContainerRegistryBuilder::build`] method:
//!
//! ```
//! use container_registry::ContainerRegistry;
//! use tower::util::ServiceExt;
//!
//! // Note: The registry is preconfigured differently when `build_for_testing` is used.
//! let ctx = ContainerRegistry::builder().build_for_testing();
//!
//! // For testing of the registry itself, it can be turned into an `axum` service:/
//! let mut service = ctx.make_service();
//!
//! // To launch the app and potentially use `app.call`:
//! // let app = service.ready().await.expect("could not launch service");
//! ```
use std::{net::SocketAddr, sync::Arc, thread};

use axum::{body::Body, routing::RouterIntoService};
use tokio::runtime::Runtime;
use tower_http::trace::TraceLayer;

use super::{
    auth::{self, Permissions},
    ContainerRegistry, ContainerRegistryBuilder,
};

/// A context of a container registry instantiated for testing.
pub struct TestingContainerRegistry {
    /// Reference to the registry instance.
    pub registry: Arc<ContainerRegistry>,
    /// Storage used by the registry.
    pub temp_storage: Option<tempdir::TempDir>,
    /// The body limit to set when running standalone.
    pub body_limit: usize,
    /// The address to bind to.
    pub bind_addr: SocketAddr,
}

/// A running registry.
///
/// Dropping it will cause the registry to shut down.
pub struct RunningRegistry {
    bound_addr: SocketAddr,
    join_handle: Option<thread::JoinHandle<()>>,
    _temp_storage: Option<tempdir::TempDir>,
    shutdown: Option<tokio::sync::mpsc::Sender<()>>,
}

impl RunningRegistry {
    /// Returns the address the registry is bound to.
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }
}

impl Drop for RunningRegistry {
    fn drop(&mut self) {
        // First, we signal the registry to shutdown by closing the channel:
        drop(self.shutdown.take());

        // Now we can wait for `axum` and thus the runtime and its thread to exit:
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.join().expect("failed to join");
        }

        // All shut down, the temporary directory will be cleaned up once we exit.
    }
}

impl TestingContainerRegistry {
    /// Creates an `axum` service for the registry.
    pub fn make_service(&self) -> RouterIntoService<Body> {
        self.registry
            .clone()
            .make_router()
            .layer(TraceLayer::new_for_http())
            .into_service::<Body>()
    }

    /// Address to bind to.
    pub fn bind(&mut self, addr: SocketAddr) -> &mut Self {
        self.bind_addr = addr;
        self
    }

    /// Sets the body limit, in bytes.
    pub fn body_limit(&mut self, body_limit: usize) -> &mut Self {
        self.body_limit = body_limit;
        self
    }

    /// Runs a registry in a seperate thread in the background.
    ///
    /// Returns a handle to the registry running in the background. If dropped, the registry will
    /// be shutdown and its storage cleaned up.
    pub fn run_in_background(mut self) -> RunningRegistry {
        let app = axum::Router::new()
            .merge(self.registry.clone().make_router())
            .layer(axum::extract::DefaultBodyLimit::max(self.body_limit));

        let listener =
            std::net::TcpListener::bind(self.bind_addr).expect("could not bind listener");
        listener
            .set_nonblocking(true)
            .expect("could not set listener to non-blocking");
        let bound_addr = listener.local_addr().expect("failed to get local address");

        let listener =
            tokio::net::TcpListener::from_std(listener).expect("could not create tokio listener");

        let (shutdown_sender, mut shutdown_receiver) = tokio::sync::mpsc::channel::<()>(1);
        let rt = Runtime::new().expect("could not create tokio runtime");
        let join_handle = thread::spawn(move || {
            rt.block_on(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        shutdown_receiver.recv().await;
                    })
                    .await
                    .expect("axum io error");
            })
        });

        RunningRegistry {
            bound_addr,
            join_handle: Some(join_handle),
            shutdown: Some(shutdown_sender),
            _temp_storage: self.temp_storage.take(),
        }
    }

    /// Grants access to the registry.
    pub fn registry(&self) -> &ContainerRegistry {
        &self.registry
    }
}

impl ContainerRegistryBuilder {
    /// Constructs a new registry for testing purposes.
    ///
    /// Similar to [`Self::build`], except
    ///
    /// * If no auth provider has been set, a default one granting **full write access** to any
    ///   user, including anonymous ones.
    /// * If no storage path has been set, creates a temporary directory for the registry, which
    ///   will be cleaned up if `TestingContainerRegistry` is dropped.
    ///
    /// # Panics
    ///
    /// Will panic if filesystem operations when setting up storage fail.
    pub fn build_for_testing(mut self) -> TestingContainerRegistry {
        let temp_storage = if self.storage.is_none() {
            let temp_storage = tempdir::TempDir::new("container-registry-for-testing").expect(
                "could not create temporary directory to host testing container registry instance",
            );
            self = self.storage(temp_storage.path());
            Some(temp_storage)
        } else {
            None
        };

        if self.auth_provider.is_none() {
            self = self.auth_provider(Arc::new(auth::Anonymous::new(
                Permissions::ReadWrite,
                Permissions::ReadWrite,
            )));
        }

        let registry = self.build().expect("could not create registry");

        TestingContainerRegistry {
            registry,
            temp_storage,
            bind_addr: ([127, 0, 0, 1], 10101).into(),
            body_limit: 100 * 1024 * 1024,
        }
    }
}
