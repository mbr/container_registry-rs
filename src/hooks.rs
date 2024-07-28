//! Notification hooks for registry changes.

use axum::async_trait;

use super::storage::ManifestReference;

/// A registry hook
///
/// Hooks are used by the registry to notify about changes made by external clients.
///
/// The unit type `()` implements `RegistryHooks`, silently discarding all notifications.
#[async_trait]
pub trait RegistryHooks: Send + Sync {
    /// Notify about an uploaded manifest.
    async fn on_manifest_uploaded(&self, manifest_reference: &ManifestReference) {
        let _ = manifest_reference;
    }
}

impl RegistryHooks for () {}
