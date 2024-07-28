use axum::async_trait;

use super::storage::ManifestReference;

#[async_trait]
pub trait RegistryHooks: Send + Sync {
    async fn on_manifest_uploaded(&self, manifest_reference: &ManifestReference) {
        let _ = manifest_reference;
    }
}

impl RegistryHooks for () {}
