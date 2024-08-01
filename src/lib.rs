#![doc = include_str!("../README.md")]

//! ## Use a library
//!
//! To use this crate as a library, use the [`ContainerRegistry`] type. Here is a minimal example,
//! supplying a unit value (`()`) to indicate it does not use any hooks, and `true` as the auth
//! provider, which will accept any username and password combination as valid:
//!
//! ```
//!# use axum::{extract::DefaultBodyLimit, Router};
//! // The registry requires an existing (empty) directory, which it will initialize.
//! let storage = tempdir::TempDir::new("container_registry_test")
//!     .expect("could not create storage dir");
//!
//! // Instantiate the registry.
//! let registry = container_registry::ContainerRegistry::new(
//!     storage.path(),
//!     Box::new(()),
//!     std::sync::Arc::new(true)
//! ).expect("failed to instantiate registry");
//!
//! // Create an axum app router and mount our new registry on it.
//! let app = Router::new()
//!     .merge(registry.make_router())
//!     // 1 GB body limit.
//!     .layer(DefaultBodyLimit::max(1024 * 1024 * 1024));
//! ```
//!
//! Afterwards, `app` can be launched via [`axum::serve()`], see its documentation for details.

pub mod auth;
pub mod hooks;
pub mod storage;
mod types;
mod www_authenticate;

use std::{
    fmt::{self, Display},
    io,
    str::FromStr,
    sync::Arc,
};

use self::{
    auth::ValidCredentials,
    storage::{FilesystemStorage, ImageLocation, RegistryStorage},
    types::{ImageManifest, OciError, OciErrors},
};
use auth::MissingPermission;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{
        header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION, RANGE},
        StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, head, patch, post, put},
    Router,
};
use futures::stream::StreamExt;
use hex::FromHex;
use serde::{Deserialize, Deserializer, Serialize};
use storage::Reference;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use tracing::info;
use uuid::Uuid;

pub(crate) use {
    auth::{AuthProvider, Unverified},
    hooks::RegistryHooks,
    storage::{FilesystemStorageError, ManifestReference},
};

/// A container registry error.
///
/// Errors produced by the registry have a "safe" [`IntoResponse`] implementation, thus can be
/// returned straight to the user without security concerns.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// A requested item (eg. manifest, blob, etc.) was not found.
    #[error("missing item")]
    NotFound,
    /// Access to a resource was denied.
    #[error("permission denied")]
    PermissionDenied(#[from] MissingPermission),
    /// Error in storage backend.
    #[error(transparent)]
    // TODO: Remove `from` impl.
    Storage(#[from] storage::Error),
    /// Error parsing image manifest.
    #[error("could not parse manifest")]
    ParseManifest(serde_json::Error),
    /// A requested/required feature was not supported by this registry.
    #[error("feature not supported: {0}")]
    NotSupported(&'static str),
    /// Invalid integer supplied for content length.
    #[error("error parsing content length")]
    ContentLengthMalformed(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Incoming stream read error.
    #[error("failed to read incoming data stream")]
    IncomingReadFailed(#[source] axum::Error),
    /// Failed to write local data to storage.
    #[error("local write failed")]
    LocalWriteFailed(#[source] io::Error),
    /// Error building HTTP response.
    #[error("axum http error")]
    // Note: These should never occur.
    AxumHttp(#[from] axum::http::Error),
}

impl IntoResponse for RegistryError {
    #[inline(always)]
    fn into_response(self) -> Response {
        match self {
            // TODO: Need better OciError handling here. Not everything is blob unknown.
            RegistryError::NotFound => (
                StatusCode::NOT_FOUND,
                OciErrors::single(OciError::new(types::ErrorCode::BlobUnknown)),
            )
                .into_response(),
            RegistryError::PermissionDenied(_) => (
                StatusCode::FORBIDDEN,
                // TODO: Should this be a proper OCI error?
                "access to request resource was denied",
            )
                .into_response(),
            RegistryError::Storage(err) => err.into_response(),
            RegistryError::ParseManifest(err) => (
                StatusCode::BAD_REQUEST,
                format!("could not parse manifest: {}", err),
            )
                .into_response(),
            RegistryError::NotSupported(feature) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("feature not supported: {}", feature),
            )
                .into_response(),
            RegistryError::ContentLengthMalformed(err) => (
                StatusCode::BAD_REQUEST,
                format!("invalid content length value: {}", err),
            )
                .into_response(),
            RegistryError::IncomingReadFailed(_err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read input stream",
            )
                .into_response(),
            RegistryError::LocalWriteFailed(_err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not write image locally",
            )
                .into_response(),
            RegistryError::AxumHttp(_err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                // Fixed message, we don't want to leak anything. This should never happen anyway.
                "error building axum HTTP response",
            )
                .into_response(),
        }
    }
}

/// A container registry storing OCI containers.
pub struct ContainerRegistry {
    /// The realm name for the registry.
    ///
    /// Solely used for HTTP auth.
    realm: String,
    /// An implementation for authentication.
    auth_provider: Arc<dyn AuthProvider>,
    /// A storage backend for the registry.
    storage: Box<dyn RegistryStorage>,
    /// A hook consumer for the registry.
    hooks: Box<dyn RegistryHooks>,
}

impl ContainerRegistry {
    /// Creates a new instance of the container registry.
    ///
    /// The instance uses the filesystem as the backend to store manifests and blobs, and requires
    /// an [`AuthProvider`] and [`RegistryHooks`] to provided. Note that it is possible to supply
    /// `()` for both `hooks` and `auth_provider`.
    ///
    /// The current implementation defaults to a filesystem based storage backend at
    /// `storage_path`. It is conceivable to implement other backends, but currently not supported.
    pub fn new<P>(
        storage_path: P,
        hooks: Box<dyn RegistryHooks>,
        auth_provider: Arc<dyn AuthProvider>,
    ) -> Result<Arc<Self>, FilesystemStorageError>
    where
        P: AsRef<std::path::Path>,
    {
        Ok(Arc::new(ContainerRegistry {
            realm: "ContainerRegistry".to_string(),
            auth_provider,
            storage: Box::new(FilesystemStorage::new(storage_path)?),
            hooks,
        }))
    }

    /// Builds an [`axum::routing::Router`] for this registry.
    ///
    /// Produces the core entry point for the registry; create and mount the router into an `axum`
    /// application to use it.
    pub fn make_router(self: Arc<ContainerRegistry>) -> Router {
        Router::new()
            .route("/v2/", get(index_v2))
            .route("/v2/:repository/:image/blobs/:digest", head(blob_check))
            .route("/v2/:repository/:image/blobs/:digest", get(blob_get))
            .route("/v2/:repository/:image/blobs/uploads/", post(upload_new))
            .route(
                "/v2/:repository/:image/uploads/:upload",
                patch(upload_add_chunk),
            )
            .route(
                "/v2/:repository/:image/uploads/:upload",
                put(upload_finalize),
            )
            .route(
                "/v2/:repository/:image/manifests/:reference",
                put(manifest_put),
            )
            .route(
                "/v2/:repository/:image/manifests/:reference",
                get(manifest_get),
            )
            .with_state(self)
    }
}

/// Registry index
///
/// Returns an empty HTTP OK response if provided credentials are okay, otherwise returns
/// UNAUTHORIZED.
async fn index_v2(
    State(registry): State<Arc<ContainerRegistry>>,
    unverified: Unverified,
) -> Response<Body> {
    let realm = &registry.realm;

    // TODO: This code duplicates some of the extraction logic of `Unverified` -- and how does it work for anonymous access?
    if !unverified.is_no_credentials()
        && registry
            .auth_provider
            .check_credentials(&unverified)
            .await
            .is_some()
    {
        return Response::builder()
            .status(StatusCode::OK)
            .header("WWW-Authenticate", format!("Basic realm=\"{realm}\""))
            .body(Body::empty())
            .unwrap();
    }

    // Return `UNAUTHORIZED`, since we want the client to supply credentials.
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", format!("Basic realm=\"{realm}\""))
        .body(Body::empty())
        .unwrap()
}

/// Returns metadata of a specific image blob.
async fn blob_check(
    State(registry): State<Arc<ContainerRegistry>>,
    Path((_, _, image)): Path<(String, String, ImageDigest)>,
    creds: ValidCredentials,
) -> Result<Response, RegistryError> {
    registry
        .auth_provider
        .blob_permissions(&creds, &image)
        .await
        .require_read()?;

    if let Some(metadata) = registry.storage.get_blob_metadata(image.digest).await? {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, metadata.size())
            .header("Docker-Content-Digest", image.to_string())
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Body::empty())
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap())
    }
}

/// Returns a specific image blob.
async fn blob_get(
    State(registry): State<Arc<ContainerRegistry>>,
    Path((_, _, image)): Path<(String, String, ImageDigest)>,
    creds: ValidCredentials,
) -> Result<Response, RegistryError> {
    registry
        .auth_provider
        .blob_permissions(&creds, &image)
        .await
        .require_read()?;

    // TODO: Get size for `Content-length` header.

    let reader = registry
        .storage
        .get_blob_reader(image.digest)
        .await?
        .ok_or(RegistryError::NotFound)?;

    let stream = ReaderStream::new(reader);
    let body = Body::from_stream(stream);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .expect("Building a streaming response with body works. qed"))
}

/// Initiates a new blob upload.
async fn upload_new(
    State(registry): State<Arc<ContainerRegistry>>,
    Path(location): Path<ImageLocation>,
    creds: ValidCredentials,
) -> Result<UploadState, RegistryError> {
    registry
        .auth_provider
        .image_permissions(&creds, &location)
        .await
        .require_write()?;

    // Initiate a new upload
    let upload = registry.storage.begin_new_upload().await?;

    Ok(UploadState {
        location,
        completed: None,
        upload,
    })
}

/// Returns the URI for a specific part of an upload.
fn mk_upload_location(location: &ImageLocation, uuid: Uuid) -> String {
    let repository = &location.repository();
    let image = &location.image();
    format!("/v2/{repository}/{image}/uploads/{uuid}")
}

/// Returns the URI for a specific part of an upload.
fn mk_manifest_location(location: &ImageLocation, reference: &Reference) -> String {
    let repository = &location.repository();
    let image = &location.image();
    format!("/v2/{repository}/{image}/manifests/{reference}")
}

/// Image upload state.
///
/// Represents the state of a partial upload of a specific blob, which may be uploaded in chunks.
///
/// The OCI protocol requires the upload state communicated back through HTTP headers, this type
/// represents said information.
#[derive(Debug)]
struct UploadState {
    /// The location of the image.
    location: ImageLocation,
    /// The amount of bytes completed.
    completed: Option<u64>,
    /// The UUID for this specific upload part.
    upload: Uuid,
}

impl IntoResponse for UploadState {
    fn into_response(self) -> Response {
        let mut builder = Response::builder()
            .header(LOCATION, mk_upload_location(&self.location, self.upload))
            .header(CONTENT_LENGTH, 0)
            .header("Docker-Upload-UUID", self.upload.to_string());

        if let Some(completed) = self.completed {
            builder = builder
                .header(RANGE, format!("0-{}", completed))
                .status(StatusCode::ACCEPTED)
        } else {
            builder = builder
                .header(CONTENT_LENGTH, 0)
                .status(StatusCode::ACCEPTED);
            // The spec says to use `CREATED`, but only `ACCEPTED` works?
        }

        builder.body(Body::empty()).unwrap()
    }
}

/// An upload ID.
#[derive(Copy, Clone, Debug, Deserialize)]
struct UploadId {
    /// The UUID representing this upload.
    upload: Uuid,
}

#[derive(Debug)]

/// An image hash.
///
/// Currently only SHA256 hashes are supported.
pub struct ImageDigest {
    /// The actual image digest.
    digest: storage::Digest,
}

impl Serialize for ImageDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let full = format!("sha256:{}", self.digest);
        full.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ImageDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Note: For some reason, `&str` here causes parsing inside query parameters to fail.
        let raw = <String>::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl ImageDigest {
    /// Creats a new image hash from an existing digest.
    #[inline(always)]
    pub const fn new(digest: storage::Digest) -> Self {
        Self { digest }
    }

    /// Returns the actual digest.
    pub fn digest(&self) -> storage::Digest {
        self.digest
    }
}

/// Error parsing a specific image digest.
#[derive(Debug, Error)]
pub enum ImageDigestParseError {
    /// The given digest was of the wrong length.
    #[error("wrong length")]
    WrongLength,
    /// The given digest had an invalid or unsupported prefix.
    #[error("wrong prefix")]
    WrongPrefix,
    /// The hex encoding was not valid.
    #[error("hex decoding error")]
    HexDecodeError,
}

impl FromStr for ImageDigest {
    type Err = ImageDigestParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        const SHA256_LEN: usize = 32;
        const PREFIX_LEN: usize = 7;
        const DIGEST_HEX_LEN: usize = SHA256_LEN * 2;

        if raw.len() != PREFIX_LEN + DIGEST_HEX_LEN {
            return Err(ImageDigestParseError::WrongLength);
        }

        if !raw.starts_with("sha256:") {
            return Err(ImageDigestParseError::WrongPrefix);
        }

        let hex_encoded = &raw[PREFIX_LEN..];
        debug_assert_eq!(hex_encoded.len(), DIGEST_HEX_LEN);

        let digest = <[u8; SHA256_LEN]>::from_hex(hex_encoded)
            .map_err(|_| ImageDigestParseError::HexDecodeError)?;

        Ok(Self {
            digest: storage::Digest::new(digest),
        })
    }
}

impl Display for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.digest)
    }
}

/// Adds a chunk to an existing upload.
async fn upload_add_chunk(
    State(registry): State<Arc<ContainerRegistry>>,
    Path(location): Path<ImageLocation>,
    Path(UploadId { upload }): Path<UploadId>,
    creds: ValidCredentials,
    request: axum::extract::Request,
) -> Result<UploadState, RegistryError> {
    registry
        .auth_provider
        .image_permissions(&creds, &location)
        .await
        .require_write()?;

    // Check if we have a range - if so, its an unsupported feature, namely monolith uploads.
    if request.headers().contains_key(RANGE) {
        return Err(RegistryError::NotSupported(
            "unsupported feature: chunked uploads",
        ));
    }

    let mut writer = registry.storage.get_upload_writer(0, upload).await?;

    // We'll get the entire file in one go, no range header == monolithic uploads.
    let mut body = request.into_body().into_data_stream();

    let mut completed: u64 = 0;
    while let Some(result) = body.next().await {
        let chunk = result.map_err(RegistryError::IncomingReadFailed)?;
        completed += chunk.len() as u64;
        writer
            .write_all(chunk.as_ref())
            .await
            .map_err(RegistryError::LocalWriteFailed)?;
    }

    writer
        .flush()
        .await
        .map_err(RegistryError::LocalWriteFailed)?;

    Ok(UploadState {
        location,
        completed: Some(completed),
        upload,
    })
}

/// An image digest on a query string.
///
/// Newtype to allow [`axum::extract::Query`] to parse it.
#[derive(Debug, Deserialize)]
struct DigestQuery {
    /// The image in question.
    digest: ImageDigest,
}

/// Finishes an upload.
async fn upload_finalize(
    State(registry): State<Arc<ContainerRegistry>>,
    Path((repository, image, upload)): Path<(String, String, Uuid)>,
    Query(DigestQuery { digest }): Query<DigestQuery>,
    creds: ValidCredentials,
    request: axum::extract::Request,
) -> Result<Response<Body>, RegistryError> {
    let location = ImageLocation::new(repository, image);

    registry
        .auth_provider
        .image_permissions(&creds, &location)
        .await
        .require_write()?;

    // We do not support the final chunk in the `PUT` call, so ensure that's not the case.
    match request.headers().get(CONTENT_LENGTH) {
        Some(value) => {
            let num_bytes: u64 = value
                .to_str()
                .map_err(|err| RegistryError::ContentLengthMalformed(Box::new(err)))?
                .parse()
                .map_err(|err| RegistryError::ContentLengthMalformed(Box::new(err)))?;
            if num_bytes != 0 {
                return Err(RegistryError::NotSupported(
                    "missing content length not implemented",
                ));
            }

            // 0 is the only acceptable value here.
        }
        None => {
            // Omitting is fine, indicating no body.
        }
    }

    registry
        .storage
        .finalize_upload(upload, digest.digest)
        .await?;

    info!(%upload, %digest, "new image uploaded");
    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header("Docker-Content-Digest", digest.to_string())
        .header(LOCATION, mk_upload_location(&location, upload))
        .body(Body::empty())?)
}

/// Uploads a manifest.
async fn manifest_put(
    State(registry): State<Arc<ContainerRegistry>>,
    Path(manifest_reference): Path<ManifestReference>,
    creds: ValidCredentials,
    image_manifest_json: String,
) -> Result<Response<Body>, RegistryError> {
    registry
        .auth_provider
        .image_permissions(&creds, manifest_reference.location())
        .await
        .require_write()?;

    let digest = registry
        .storage
        .put_manifest(&manifest_reference, image_manifest_json.as_bytes())
        .await?;

    info!(%manifest_reference, %digest, "new manifest received");
    // Completed upload, call hook:
    registry
        .hooks
        .on_manifest_uploaded(&manifest_reference)
        .await;

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(
            LOCATION,
            mk_manifest_location(
                manifest_reference.location(),
                manifest_reference.reference(),
            ),
        )
        .header(CONTENT_LENGTH, 0)
        .header(
            "Docker-Content-Digest",
            ImageDigest::new(digest).to_string(),
        )
        .body(Body::empty())
        .unwrap())
}

/// Retrieves a manifest.
async fn manifest_get(
    State(registry): State<Arc<ContainerRegistry>>,
    Path(manifest_reference): Path<ManifestReference>,
    creds: ValidCredentials,
) -> Result<Response<Body>, RegistryError> {
    registry
        .auth_provider
        .image_permissions(&creds, manifest_reference.location())
        .await
        .require_read()?;

    let manifest_json = registry
        .storage
        .get_manifest(&manifest_reference)
        .await?
        .ok_or(RegistryError::NotFound)?;

    let manifest: ImageManifest =
        serde_json::from_slice(&manifest_json).map_err(RegistryError::ParseManifest)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, manifest_json.len())
        .header(CONTENT_TYPE, manifest.media_type())
        .body(manifest_json.into())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{
            header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, LOCATION},
            Request, StatusCode,
        },
        routing::RouterIntoService,
    };
    use base64::Engine;
    use http_body_util::BodyExt;
    use sec::Secret;
    use tempdir::TempDir;
    use tokio::io::AsyncWriteExt;
    use tower::{util::ServiceExt, Service};
    use tower_http::trace::TraceLayer;

    use crate::{
        auth::{Anonymous, Permissions},
        storage::{ImageLocation, ManifestReference, Reference},
        ImageDigest,
    };

    use super::{storage::Digest, ContainerRegistry};

    struct Context {
        _tmp: TempDir,
        password: String,
        registry: Arc<ContainerRegistry>,
    }

    impl Context {
        fn basic_auth(&self) -> String {
            let encoded = base64::prelude::BASE64_STANDARD
                .encode(format!("user:{}", self.password).as_bytes());
            format!("Basic {}", encoded)
        }

        fn invalid_basic_auth(&self) -> String {
            let not_the_password = "user:not-the-password".to_owned() + self.password.as_str();
            let encoded = base64::prelude::BASE64_STANDARD.encode(not_the_password.as_bytes());
            format!("Basic {}", encoded)
        }
    }

    fn mk_test_app() -> (Context, RouterIntoService<Body>) {
        let tmp = TempDir::new("rockslide-test").expect("could not create temporary directory");

        let password = "random-test-password".to_owned();
        let master_key = Arc::new(Secret::new(password.clone()));

        let registry = ContainerRegistry::new(tmp.as_ref(), Box::new(()), master_key)
            .expect("should not fail to create app");
        let router = registry
            .clone()
            .make_router()
            .layer(TraceLayer::new_for_http());

        let service = router.into_service::<Body>();

        (
            Context {
                registry,
                _tmp: tmp,
                password,
            },
            service,
        )
    }

    fn mk_anon_app() -> (Context, RouterIntoService<Body>) {
        let tmp = TempDir::new("rockslide-test").expect("could not create temporary directory");

        let auth = Arc::new(Anonymous::new(Permissions::ReadWrite, true));
        let registry = ContainerRegistry::new(tmp.as_ref(), Box::new(()), auth)
            .expect("should not fail to create app");
        let router = registry
            .clone()
            .make_router()
            .layer(TraceLayer::new_for_http());

        let service = router.into_service::<Body>();

        (
            Context {
                registry,
                _tmp: tmp,
                password: "NOTSET".to_string(),
            },
            service,
        )
    }

    #[tokio::test]
    async fn refuses_access_without_valid_credentials() {
        let (ctx, mut service) = mk_test_app();
        let app = service.ready().await.expect("could not launch service");

        let targets = [("GET", "/v2/")];
        // TODO: Verify all remaining endpoints return `UNAUTHORIZED` without credentials.

        for (method, endpoint) in targets.into_iter() {
            // API should refuse requests without credentials.
            let response = app
                .call(
                    Request::builder()
                        .method(method)
                        .uri(endpoint)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // Wrong credentials should also not grant access.
            let response = app
                .call(
                    Request::builder()
                        .method(method)
                        .uri(endpoint)
                        .header(AUTHORIZATION, ctx.invalid_basic_auth())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // Finally a valid set should grant access.
            let response = app
                .call(
                    Request::builder()
                        .uri("/v2/")
                        .header(AUTHORIZATION, ctx.basic_auth())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::UNAUTHORIZED)
        }
    }

    // Fixtures.
    const RAW_IMAGE: &[u8] = include_bytes!(
        "../fixtures/596a7d877b33569d199046aaf293ecf45026445be36de1818d50b4f1850762ad"
    );
    const RAW_MANIFEST: &[u8] = include_bytes!(
        "../fixtures/9ce67038e4f1297a0b1ce23be1b768ce3649fe9bd496ba8efe9ec1676d153430"
    );

    const IMAGE_DIGEST: ImageDigest = ImageDigest::new(Digest::new([
        0x59, 0x6a, 0x7d, 0x87, 0x7b, 0x33, 0x56, 0x9d, 0x19, 0x90, 0x46, 0xaa, 0xf2, 0x93, 0xec,
        0xf4, 0x50, 0x26, 0x44, 0x5b, 0xe3, 0x6d, 0xe1, 0x81, 0x8d, 0x50, 0xb4, 0xf1, 0x85, 0x07,
        0x62, 0xad,
    ]));

    const MANIFEST_DIGEST: ImageDigest = ImageDigest::new(Digest::new([
        0x9c, 0xe6, 0x70, 0x38, 0xe4, 0xf1, 0x29, 0x7a, 0x0b, 0x1c, 0xe2, 0x3b, 0xe1, 0xb7, 0x68,
        0xce, 0x36, 0x49, 0xfe, 0x9b, 0xd4, 0x96, 0xba, 0x8e, 0xfe, 0x9e, 0xc1, 0x67, 0x6d, 0x15,
        0x34, 0x30,
    ]));

    #[tokio::test]
    async fn chunked_upload() {
        // See https://github.com/opencontainers/distribution-spec/blob/v1.0.1/spec.md#pushing-a-blob-in-chunks
        let (ctx, mut service) = mk_test_app();
        let app = service.ready().await.expect("could not launch service");

        // Step 1: POST for new blob upload.
        let response = app
            .call(
                Request::builder()
                    .method("POST")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri("/v2/tests/sample/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let put_location = response
            .headers()
            .get(LOCATION)
            .expect("expected location header for blob upload")
            .to_str()
            .unwrap()
            .to_owned();

        // Step 2: PATCH blobs.
        let mut sent = 0;
        for chunk in RAW_IMAGE.chunks(32) {
            assert!(!chunk.is_empty());
            let range = format!("{sent}-{}", chunk.len() - 1);
            sent += chunk.len();

            let response = app
                .call(
                    Request::builder()
                        .method("PATCH")
                        .header(AUTHORIZATION, ctx.basic_auth())
                        .header(CONTENT_LENGTH, chunk.len())
                        .header(CONTENT_RANGE, range)
                        .uri(&put_location)
                        .body(Body::from(chunk))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        // Step 3: PUT without (!) final body -- we do not support putting the final piece in `PUT`.
        let response = app
            .call(
                Request::builder()
                    .method("PUT")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri(put_location + "?digest=" + IMAGE_DIGEST.to_string().as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Check the blob is available after.
        let blob_location = format!("/v2/tests/sample/blobs/{}", IMAGE_DIGEST);
        assert!(&ctx
            .registry
            .storage
            .get_blob_reader(IMAGE_DIGEST.digest)
            .await
            .expect("could not access stored blob")
            .is_some());

        // Step 4: Client verifies existence of blob through `HEAD` request.
        let response = app
            .call(
                Request::builder()
                    .method("HEAD")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri(blob_location)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Docker-Content-Digest")
                .unwrap()
                .to_str()
                .unwrap(),
            IMAGE_DIGEST.to_string()
        );

        // Step 5: Upload the manifest
        let manifest_by_tag_location = "/v2/tests/sample/manifests/latest";

        let response = app
            .call(
                Request::builder()
                    .method("PUT")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri(manifest_by_tag_location)
                    .body(Body::from(RAW_MANIFEST))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("Docker-Content-Digest")
                .unwrap()
                .to_str()
                .unwrap(),
            MANIFEST_DIGEST.to_string()
        );

        // Should contain image under given tag.
        assert_eq!(
            ctx.registry
                .storage
                .get_manifest(&ManifestReference::new(
                    ImageLocation::new("tests".to_owned(), "sample".to_owned()),
                    Reference::new_tag("latest"),
                ))
                .await
                .expect("failed to get reference by tag")
                .expect("missing reference by tag"),
            RAW_MANIFEST
        );

        assert_eq!(
            ctx.registry
                .storage
                .get_manifest(&ManifestReference::new(
                    ImageLocation::new("tests".to_owned(), "sample".to_owned()),
                    Reference::new_digest(MANIFEST_DIGEST.digest),
                ))
                .await
                .expect("failed to get reference by digest")
                .expect("missing reference by digest"),
            RAW_MANIFEST
        );
    }

    /// Similar to `chunked_upload`, but uses no credentials to log in.
    #[tokio::test]
    async fn anonymous_upload() {
        let (ctx, mut service) = mk_anon_app();
        let app = service.ready().await.expect("could not launch service");

        // Step 1: POST for new blob upload.
        let response = app
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/v2/tests/sample/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let put_location = response
            .headers()
            .get(LOCATION)
            .expect("expected location header for blob upload")
            .to_str()
            .unwrap()
            .to_owned();

        // Step 2: PATCH blobs.
        let mut sent = 0;
        for chunk in RAW_IMAGE.chunks(32) {
            assert!(!chunk.is_empty());
            let range = format!("{sent}-{}", chunk.len() - 1);
            sent += chunk.len();

            let response = app
                .call(
                    Request::builder()
                        .method("PATCH")
                        .header(CONTENT_LENGTH, chunk.len())
                        .header(CONTENT_RANGE, range)
                        .uri(&put_location)
                        .body(Body::from(chunk))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        // Step 3: PUT without (!) final body -- we do not support putting the final piece in `PUT`.
        let response = app
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(put_location + "?digest=" + IMAGE_DIGEST.to_string().as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Check the blob is available after.
        let blob_location = format!("/v2/tests/sample/blobs/{}", IMAGE_DIGEST);
        assert!(&ctx
            .registry
            .storage
            .get_blob_reader(IMAGE_DIGEST.digest)
            .await
            .expect("could not access stored blob")
            .is_some());

        // Step 4: Client verifies existence of blob through `HEAD` request.
        let response = app
            .call(
                Request::builder()
                    .method("HEAD")
                    .uri(blob_location)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("Docker-Content-Digest")
                .unwrap()
                .to_str()
                .unwrap(),
            IMAGE_DIGEST.to_string()
        );

        // Step 5: Upload the manifest
        let manifest_by_tag_location = "/v2/tests/sample/manifests/latest";

        let response = app
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(manifest_by_tag_location)
                    .body(Body::from(RAW_MANIFEST))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("Docker-Content-Digest")
                .unwrap()
                .to_str()
                .unwrap(),
            MANIFEST_DIGEST.to_string()
        );
    }

    #[tokio::test]
    async fn image_download() {
        let (ctx, mut service) = mk_test_app();
        let app = service.ready().await.expect("could not launch service");

        let manifest_ref_by_tag = ManifestReference::new(
            ImageLocation::new("tests".to_owned(), "sample".to_owned()),
            Reference::new_tag("latest"),
        );

        let manifest_by_tag_location = "/v2/tests/sample/manifests/latest";
        let manifest_by_digest_location = format!("/v2/tests/sample/manifests/{}", MANIFEST_DIGEST);

        // Insert blob data.
        let upload = ctx
            .registry
            .storage
            .begin_new_upload()
            .await
            .expect("could not start upload");
        let mut writer = ctx
            .registry
            .storage
            .get_upload_writer(0, upload)
            .await
            .expect("could not create upload writer");
        writer
            .write_all(RAW_IMAGE)
            .await
            .expect("failed to write image blob");
        ctx.registry
            .storage
            .finalize_upload(upload, IMAGE_DIGEST.digest)
            .await
            .expect("failed to finalize upload");

        // Insert manifest data.
        ctx.registry
            .storage
            .put_manifest(&manifest_ref_by_tag, RAW_MANIFEST)
            .await
            .expect("failed to store manifest");

        // Retrieve manifest via HTTP, both by tag and by digest.
        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri(manifest_by_tag_location)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = collect_body(response.into_body()).await;

        assert_eq!(response_body, RAW_MANIFEST);

        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri(manifest_by_digest_location)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = collect_body(response.into_body()).await;

        assert_eq!(response_body, RAW_MANIFEST);

        // Download blob.
        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri(format!("/v2/testing/sample/blobs/{}", IMAGE_DIGEST))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response_body = collect_body(response.into_body()).await;
        assert_eq!(response_body, RAW_IMAGE);
    }

    #[tokio::test]
    async fn missing_manifest_returns_404() {
        let (ctx, mut service) = mk_test_app();
        let app = service.ready().await.expect("could not launch service");

        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .header(AUTHORIZATION, ctx.basic_auth())
                    .uri("/v2/doesnot/exist/manifests/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    async fn collect_body(mut body: Body) -> Vec<u8> {
        let mut rv = Vec::new();
        while let Some(frame_result) = body.frame().await {
            let data = frame_result
                .expect("failed to retrieve body frame")
                .into_data()
                .expect("not a data frame");

            rv.extend(data.to_vec());
        }

        rv
    }
}
