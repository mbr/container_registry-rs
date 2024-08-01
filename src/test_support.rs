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
use std::sync::Arc;

use axum::{body::Body, routing::RouterIntoService};
use tower_http::trace::TraceLayer;

use super::{
    auth::{self, Permissions},
    ContainerRegistry, ContainerRegistryBuilder,
};

/// A handle to a container registry instantiated for testing.
pub struct TestingContainerRegistry {
    /// Reference to the registry instance.
    pub registry: Arc<ContainerRegistry>,
    /// Storage used by the registry.
    pub temp_storage: Option<tempdir::TempDir>,
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
        }
    }
}
