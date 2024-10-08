//! Storage backends.
//!
//! The `container_registry` crate has somewhat modular storage backends, but currently nothing but
//! filesystem storage is supported. Contact the author if you'd like to see this change.
// Note: This module is in worse shape, documentation wise, than the rest. Cleaning this up is the
//       first step towards supporting custom implementations.
use std::{
    fmt::{self, Display},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

use axum::{async_trait, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sha2::Digest as Sha2Digest;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWrite};
use uuid::Uuid;

use super::{types::ImageManifest, ImageDigest};

/// Length of a SHA256 hash in bytes.
pub const SHA256_LEN: usize = 32;

const BUFFER_SIZE: usize = 1024 * 1024; // 1 MiB

/// An SHA256 digest.
///
/// The `container_registry` crate supports only `sha256` digests at this time.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize)]
pub struct Digest([u8; SHA256_LEN]);

impl Digest {
    /// Creates a digest from an existing hash.
    pub const fn new(bytes: [u8; SHA256_LEN]) -> Self {
        Self(bytes)
    }

    /// Creates a digest by hashing given contents.
    pub fn from_contents(contents: &[u8]) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(contents);

        Self::new(hasher.finalize().into())
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0[..]))
    }
}

#[derive(Debug, Deserialize)]
struct LayerManifest {
    #[serde(rename = "camelCase")]
    #[allow(dead_code)] // TODO
    blob_sum: String,
}

/// Location of a given image.
///
/// In an open container registry, images are stored in what `container-registry` calls
/// "repository" and "image" pairs. For example, the container image specified as
/// `bitnami/nginx:latest` would have a repository of `bitnami`, image of `nginx` and tag (which
/// is not part of [`ImageLocation`] of `latest`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ImageLocation {
    /// The repository part of the image location.
    repository: String,
    /// The image part of the image location.
    image: String,
}

impl Display for ImageLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.repository, self.image)
    }
}

/// Refers to a specific manifest.
///
/// Combines an [`ImageLocation`] with a [`Reference`], e.g. `bitnami/nginx:latest`, which has an
/// [`ImageLocation`] portion of `bitnami/nginx` and a [`Reference::Tag`] `latest`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestReference {
    #[serde(flatten)]
    location: ImageLocation,
    reference: Reference,
}

impl Display for ManifestReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.location, self.reference)
    }
}

impl ManifestReference {
    /// Creates a new manifest reference.
    pub fn new(location: ImageLocation, reference: Reference) -> Self {
        Self {
            location,
            reference,
        }
    }

    /// Returns the location portion of the image location.
    pub fn location(&self) -> &ImageLocation {
        &self.location
    }

    /// Returns the reference portion of the image location.
    pub fn reference(&self) -> &Reference {
        &self.reference
    }
}

impl ImageLocation {
    /// Creates a new image location.
    pub fn new(repository: String, image: String) -> Self {
        Self { repository, image }
    }

    /// Returns the repository portion of the given image location.
    #[inline(always)]
    pub fn repository(&self) -> &str {
        self.repository.as_ref()
    }

    /// Returns the image portion of the given image location.
    #[inline(always)]
    pub fn image(&self) -> &str {
        self.image.as_ref()
    }
}

/// Reference to a specific version of an image.
#[derive(Clone, Debug)]
pub enum Reference {
    /// Image reference by given tag (e.g. `latest`).
    Tag(String),
    /// Image referenced by given specific hash.
    Digest(Digest),
}

impl<'de> Deserialize<'de> for Reference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <&str>::deserialize(deserializer)?;

        match ImageDigest::from_str(raw) {
            Ok(digest) => Ok(Self::Digest(digest.digest)),
            Err(_) => Ok(Self::Tag(raw.to_owned())),
        }
    }
}

impl Serialize for Reference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Reference::Tag(tag) => tag.serialize(serializer),
            Reference::Digest(digest) => ImageDigest::new(*digest).serialize(serializer),
        }
    }
}

impl Reference {
    /// Creates a new by-tag reference.
    #[inline(always)]
    pub fn new_tag<S: ToString>(s: S) -> Self {
        Reference::Tag(s.to_string())
    }

    /// Creats a new by-hash reference.
    #[inline(always)]
    pub fn new_digest(d: Digest) -> Self {
        Reference::Digest(d)
    }

    /// Returns reference as naked tag, if it is a tag.
    pub fn as_tag(&self) -> Option<&str> {
        match self {
            Reference::Tag(tag) => Some(tag),
            Reference::Digest(_) => None,
        }
    }
}

impl Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reference::Tag(tag) => Display::fmt(tag, f),
            Reference::Digest(digest) => Display::fmt(digest, f),
        }
    }
}

/// A storage error.
#[derive(Debug, Error)]
pub enum Error {
    /// Attempted to submit data to an upload that does not exist.
    #[error("given upload does not exist")]
    UploadDoesNotExit,
    /// A content hash mismatched.
    #[error("digest did not match")]
    DigestMismatch,
    /// An IO error.
    // TODO: Not great to have a catch-all IO error, to be replaced later.
    #[error("io error")]
    Io(io::Error),
    /// A background task panicked.
    #[error("background task panicked")]
    BackgroundTaskPanicked(#[source] tokio::task::JoinError),
    /// Invalid image manifest submitted.
    #[error("invalid image manifest")]
    InvalidManifest(#[source] serde_json::Error),
    /// Attempted to store a manifest under a digest instead of a tag.
    #[error("cannot store manifest under hash")]
    NotATag,
}

impl IntoResponse for Error {
    #[inline]
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::UploadDoesNotExit => StatusCode::NOT_FOUND.into_response(),
            Error::InvalidManifest(_) | Error::NotATag => StatusCode::BAD_REQUEST.into_response(),
            Error::DigestMismatch | Error::Io(_) | Error::BackgroundTaskPanicked(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct BlobMetadata {
    #[allow(dead_code)] // TODO
    digest: Digest,
    size: u64,
}

impl BlobMetadata {
    #[allow(dead_code)] // TODO
    pub(crate) fn digest(&self) -> Digest {
        self.digest
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }
}

#[async_trait]
pub(crate) trait RegistryStorage: Send + Sync {
    async fn begin_new_upload(&self) -> Result<Uuid, Error>;

    async fn get_blob_reader(
        &self,
        digest: Digest,
    ) -> Result<Option<Box<dyn AsyncRead + Send + Unpin>>, Error>;

    async fn get_blob_metadata(&self, digest: Digest) -> Result<Option<BlobMetadata>, Error>;

    async fn get_upload_writer(
        &self,
        start_at: u64,
        upload: Uuid,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin>, Error>;

    async fn finalize_upload(&self, upload: Uuid, hash: Digest) -> Result<(), Error>;

    async fn get_manifest(
        &self,
        manifest_reference: &ManifestReference,
    ) -> Result<Option<Vec<u8>>, Error>;

    async fn put_manifest(
        &self,
        manifest_reference: &ManifestReference,
        manifest: &[u8],
    ) -> Result<Digest, Error>;
}

/// A filesystem backend error.
#[derive(Debug, Error)]
pub enum FilesystemStorageError {
    /// The storage path given could not be canonicalized.
    #[error("could not canonicalize root {}", path.display())]
    CouldNotCanonicalizeRoot {
        path: PathBuf,
        #[source]
        err: io::Error,
    },
    /// Failed to create directory in storage path.
    #[error("could not create directory {}", path.display())]
    FailedToCreateDir {
        path: PathBuf,
        #[source]
        err: io::Error,
    },
}

#[derive(Debug)]
pub(crate) struct FilesystemStorage {
    uploads: PathBuf,
    blobs: PathBuf,
    manifests: PathBuf,
    tags: PathBuf,
    rel_manifest_to_blobs: PathBuf,
}

impl FilesystemStorage {
    pub(crate) fn new<P: AsRef<Path>>(root: P) -> Result<Self, FilesystemStorageError> {
        let raw_root = root.as_ref();
        let root = raw_root.canonicalize().map_err(|err| {
            FilesystemStorageError::CouldNotCanonicalizeRoot {
                path: raw_root.to_owned(),
                err,
            }
        })?;

        let uploads = root.join("uploads");
        let blobs = root.join("blobs");
        let manifests = root.join("manifests");
        let tags = root.join("tags");
        let rel_manifest_to_blobs = PathBuf::from("../../../manifests");

        for dir in [&uploads, &blobs, &manifests, &tags] {
            if !dir.exists() {
                fs::create_dir(dir).map_err(|err| FilesystemStorageError::FailedToCreateDir {
                    path: dir.to_owned(),
                    err,
                })?;
            }
        }

        Ok(FilesystemStorage {
            uploads,
            blobs,
            manifests,
            tags,
            rel_manifest_to_blobs,
        })
    }
    fn blob_path(&self, digest: Digest) -> PathBuf {
        self.blobs.join(format!("{}", digest))
    }
    fn upload_path(&self, upload: Uuid) -> PathBuf {
        self.uploads.join(format!("{}.partial", upload))
    }

    fn manifest_path(&self, digest: Digest) -> PathBuf {
        self.manifests.join(format!("{}", digest))
    }

    fn blob_rel_path(&self, digest: Digest) -> PathBuf {
        self.rel_manifest_to_blobs.join(format!("{}", digest))
    }

    fn tag_path(&self, location: &ImageLocation, tag: &str) -> PathBuf {
        self.tags
            .join(location.repository())
            .join(location.image())
            .join(tag)
    }

    fn temp_tag_path(&self) -> PathBuf {
        self.tags.join(Uuid::new_v4().to_string())
    }
}

#[async_trait]
impl RegistryStorage for FilesystemStorage {
    async fn begin_new_upload(&self) -> Result<Uuid, Error> {
        let upload = Uuid::new_v4();
        let out_path = self.upload_path(upload);

        // Write zero-sized file.
        let _file = tokio::fs::File::create(out_path).await.map_err(Error::Io)?;

        Ok(upload)
    }

    async fn get_blob_metadata(&self, digest: Digest) -> Result<Option<BlobMetadata>, Error> {
        let blob_path = self.blob_path(digest);

        if !blob_path.exists() {
            return Ok(None);
        }

        let metadata = tokio::fs::metadata(blob_path).await.map_err(Error::Io)?;

        Ok(Some(BlobMetadata {
            digest,
            size: metadata.len(),
        }))
    }

    async fn get_blob_reader(
        &self,
        digest: Digest,
    ) -> Result<Option<Box<dyn AsyncRead + Send + Unpin>>, Error> {
        let blob_path = self.blob_path(digest);

        if !blob_path.exists() {
            return Ok(None);
        }

        let reader = tokio::fs::File::open(blob_path).await.map_err(Error::Io)?;

        Ok(Some(Box::new(reader)))
    }

    async fn get_upload_writer(
        &self,
        start_at: u64,
        upload: Uuid,
    ) -> Result<Box<dyn AsyncWrite + Send + Unpin>, Error> {
        let location = self.upload_path(upload);

        if !location.exists() {
            return Err(Error::UploadDoesNotExit);
        }

        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .truncate(false)
            .open(location)
            .await
            .map_err(Error::Io)?;

        file.seek(io::SeekFrom::Start(start_at))
            .await
            .map_err(Error::Io)?;

        Ok(Box::new(file))
    }

    async fn finalize_upload(&self, upload: Uuid, digest: Digest) -> Result<(), Error> {
        // We are to validate the uploaded partial, then move it into the proper store.
        // TODO: Lock in place so that the hash cannot be corrupted/attacked.

        let upload_path = self.upload_path(upload);

        if !upload_path.exists() {
            return Err(Error::UploadDoesNotExit);
        }

        // We offload hashing to a blocking thread.
        let actual = {
            let upload_path = upload_path.clone();
            tokio::task::spawn_blocking::<_, Result<Digest, Error>>(move || {
                let mut src = fs::File::open(upload_path).map_err(Error::Io)?;

                // Uses `vec!` instead of `Box`, as initializing the latter blows the stack:
                let mut buf = vec![0; BUFFER_SIZE];
                let mut hasher = sha2::Sha256::new();

                loop {
                    let read = src.read(buf.as_mut()).map_err(Error::Io)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buf[..read]);
                }

                let actual = hasher.finalize();
                Ok(Digest::new(actual.into()))
            })
        }
        .await
        .map_err(Error::BackgroundTaskPanicked)??;

        if actual != digest {
            return Err(Error::DigestMismatch);
        }

        // The uploaded file matches, we can rename it now.
        let dest = self.blob_path(digest);
        tokio::fs::rename(upload_path, dest)
            .await
            .map_err(Error::Io)?;

        // All good.
        Ok(())
    }

    async fn get_manifest(
        &self,
        manifest_reference: &ManifestReference,
    ) -> Result<Option<Vec<u8>>, Error> {
        let manifest_path = match manifest_reference.reference() {
            Reference::Tag(ref tag) => self.tag_path(manifest_reference.location(), tag),
            Reference::Digest(digest) => self.manifest_path(*digest),
        };

        match tokio::fs::read(manifest_path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    async fn put_manifest(
        &self,
        manifest_reference: &ManifestReference,
        manifest: &[u8],
    ) -> Result<Digest, Error> {
        // TODO: Validate all blobs are completely uploaded.
        let _manifest: ImageManifest =
            serde_json::from_slice(manifest).map_err(Error::InvalidManifest)?;

        let digest = Digest::from_contents(manifest);
        let dest = self.manifest_path(digest);
        tokio::fs::write(dest, &manifest).await.map_err(Error::Io)?;

        let tag = self.tag_path(
            manifest_reference.location(),
            manifest_reference
                .reference()
                .as_tag()
                .ok_or(Error::NotATag)?,
        );

        let tag_parent = tag.parent().expect("should have parent");

        if !tag_parent.exists() {
            tokio::fs::create_dir_all(tag_parent)
                .await
                .map_err(Error::Io)?;
        }

        let tmp_tag = self.temp_tag_path();

        tokio::fs::symlink(self.blob_rel_path(digest), &tmp_tag)
            .await
            .map_err(Error::Io)?;
        tokio::fs::rename(tmp_tag, tag).await.map_err(Error::Io)?;

        Ok(digest)
    }
}
