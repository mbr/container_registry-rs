//! Authentication backends.
//!
//! The `container-registry` supports pluggable authentication, as anything that implements the
//! [`AuthProvider`] trait can be used as an authentication (and authorization) backend. Included
//! are implementations for the following types:
//!
//! * `Permissions`: The [`Permissions`] type itself is an auth provider, it will allow
//!                  access with the given permissions to any non-anonymous client.
//! * `HashMap<String, Secret<String>>`: A mapping of usernames to (unencrypted) passwords.
//! * `Secret<String>`: Master password, ignores all usernames and just compares the password.
//! * `Anonymous`: A decorator that wraps around another [`AuthProvider`], will grant a fixed set
//!                of permissions to anonymous user, while deferring everything else to the inner
//!                provider.
//!
//! All the above implementations deal with **authentication** only, once authorized, full
//! write access to everything is granted.
//!
//! To provide some safety against accidentally leaking passwords via stray `Debug` implementations,
//! this crate uses the [`sec`]'s crate [`Secret`] type.

use std::{any::Any, collections::HashMap, str, sync::Arc};

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{
        header::{self},
        request::Parts,
        StatusCode,
    },
};
use sec::Secret;
use thiserror::Error;

use crate::{storage::ImageLocation, ImageDigest};

use super::{
    www_authenticate::{self},
    ContainerRegistry,
};

/// A set of credentials supplied that has not been verified.
#[derive(Debug)]
pub enum Unverified {
    /// A set of username and password credentials.
    UsernameAndPassword {
        /// The given username.
        username: String,
        /// The provided password.
        password: Secret<String>,
    },
    /// No credentials were given.
    NoCredentials,
}

impl Unverified {
    /// Returns whether or not this set of unverified credentials is actually no credentials at all.
    #[inline(always)]
    pub fn is_no_credentials(&self) -> bool {
        matches!(self, Unverified::NoCredentials)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Unverified {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION) {
            let (_unparsed, basic) = www_authenticate::basic_auth_response(auth_header.as_bytes())
                .map_err(|_| StatusCode::BAD_REQUEST)?;

            Ok(Unverified::UsernameAndPassword {
                username: str::from_utf8(&basic.username)
                    .map_err(|_| StatusCode::BAD_REQUEST)?
                    .to_owned(),
                password: Secret::new(
                    str::from_utf8(&basic.password)
                        .map_err(|_| StatusCode::BAD_REQUEST)?
                        .to_owned(),
                ),
            })
        } else {
            Ok(Unverified::NoCredentials)
        }
    }
}

/// A set of credentials that has been validated.
///
/// Every [`AuthProvider`] is free to put [`Any`] type in the credentials and is guaranteed
/// to be passed back only instances it created itself. Use [`Self::extract_ref`] to retrieve the
/// passed in actual type.
#[derive(Debug)]
pub struct ValidCredentials(pub Box<dyn Any + Send + Sync>);

impl ValidCredentials {
    /// Creates a new set of valid credentials.
    #[inline(always)]
    pub fn new<T: Send + Sync + 'static>(inner: T) -> Self {
        ValidCredentials(Box::new(inner))
    }

    /// Extracts a reference to the contained inner type.
    pub fn extract_ref<T: 'static>(&self) -> &T {
        self.0.downcast_ref::<T>().expect("could not downcast `ValidCredentials` into expected type - was auth provider called with the wrong set of credentials?")
    }
}

#[async_trait]
impl FromRequestParts<Arc<ContainerRegistry>> for ValidCredentials {
    type Rejection = StatusCode;

    #[inline(always)]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ContainerRegistry>,
    ) -> Result<Self, Self::Rejection> {
        let unverified = Unverified::from_request_parts(parts, state).await?;

        // We got a set of credentials, now verify.
        match state.auth_provider.check_credentials(&unverified).await {
            Some(creds) => Ok(creds),
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

/// A set of permissions granted on a specific image location to a given set of credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Permissions {
    /// Access forbidden.
    NoAccess = 0,
    /// Write only access.
    WriteOnly = 2,
    /// Read access.
    ReadOnly = 4,
    /// Read and write access.
    ReadWrite = 6,
}

impl Permissions {
    /// Returns whether or not permissions include read access.
    #[inline(always)]
    #[must_use = "should not check read permissions and discard the result"]
    pub fn has_read_permission(self) -> bool {
        match self {
            Permissions::NoAccess | Permissions::WriteOnly => false,
            Permissions::ReadOnly | Permissions::ReadWrite => true,
        }
    }

    /// Returns whether or not permissions include write access.
    #[inline(always)]
    #[must_use = "should not check write permissions and discard the result"]
    pub fn has_write_permission(self) -> bool {
        match self {
            Permissions::NoAccess | Permissions::ReadOnly => false,
            Permissions::WriteOnly | Permissions::ReadWrite => true,
        }
    }

    /// Returns an error if no read permission is included.
    #[inline(always)]
    pub fn require_read(self) -> Result<(), MissingPermission> {
        if !self.has_read_permission() {
            Err(MissingPermission)
        } else {
            Ok(())
        }
    }

    /// Returns an error if no write permission is included.
    #[inline(always)]
    pub fn require_write(self) -> Result<(), MissingPermission> {
        if !self.has_write_permission() {
            Err(MissingPermission)
        } else {
            Ok(())
        }
    }
}

/// Error indicating a missing permission.
#[derive(Debug, Error)]
#[error("not permitted")]
pub struct MissingPermission;

/// An authentication and authorization provider.
///
/// At the moment, `container-registry` gives full access to any valid user.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Checks whether the supplied unverified credentials are valid.
    ///
    /// Must return `None` if the credentials are not valid at all, malformed or similar.
    ///
    /// This is an **authenticating** function, returning `Some` indicates that the "login" was
    /// successful, but makes not statement about what these credentials can actually access (see
    /// `allowed_read()` and `allowed_write()` for authorization checks).
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials>;

    /// Determine permissions for given credentials at image location.
    ///
    /// This is an **authorizing** function that determines permissions for previously authenticated
    /// credentials on a given [`ImageLocation`].
    async fn image_permissions(
        &self,
        creds: &ValidCredentials,
        image: &ImageLocation,
    ) -> Permissions;

    /// Determine permissions for given credentials to a specific blob.
    ///
    /// This is an **authorizing** function that determines permissions for previously authenticated
    /// credentials on a given [`ImageLocation`].
    ///
    /// Note that blob permissions are only ever queried for reading blobs. Writing blobs does not
    /// involve the uploader sending a hash beforehand, thus this function cannot be used to
    /// implement a blacklist for specific blobs.
    async fn blob_permissions(&self, creds: &ValidCredentials, blob: &ImageDigest) -> Permissions;
}

/// Anonymous access auth provider.
///
/// The [`Anonymous`] grants a fixed set of permissions to anonymous users, i.e. those not
/// supplying any credentials at all. For others it defers to the wrapped [`AuthProvider`] `A`.
#[derive(Debug)]
pub struct Anonymous<A> {
    anon_permissions: Permissions,
    inner: A,
}

impl<A> Anonymous<A> {
    /// Creates a new anonymous auth provider that decorates `inner`.
    pub fn new(anon_permissions: Permissions, inner: A) -> Self {
        Self {
            anon_permissions,
            inner,
        }
    }
}

/// A set of possibly anonymous credentials.
#[derive(Debug)]
enum AnonCreds {
    /// No credentials provided, user is anonymous.
    Anonymous,
    /// Valid credentials supplied by inner auth provider.
    Valid(ValidCredentials),
}

#[async_trait]
impl<A> AuthProvider for Anonymous<A>
where
    A: AuthProvider,
{
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        match unverified {
            Unverified::NoCredentials => Some(ValidCredentials::new(AnonCreds::Anonymous)),
            _other => self.inner.check_credentials(unverified).await,
        }
    }

    async fn image_permissions(
        &self,
        creds: &ValidCredentials,
        image: &ImageLocation,
    ) -> Permissions {
        match creds.extract_ref::<AnonCreds>() {
            AnonCreds::Anonymous => self.anon_permissions,
            _other => self.inner.image_permissions(creds, image).await,
        }
    }

    async fn blob_permissions(&self, creds: &ValidCredentials, blob: &ImageDigest) -> Permissions {
        match creds.extract_ref::<AnonCreds>() {
            AnonCreds::Anonymous => self.anon_permissions,
            _other => self.inner.blob_permissions(creds, blob).await,
        }
    }
}

#[async_trait]
impl AuthProvider for Permissions {
    #[inline(always)]
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        match unverified {
            Unverified::NoCredentials => None,
            _other => Some(ValidCredentials::new(())),
        }
    }

    #[inline(always)]
    async fn image_permissions(
        &self,
        _creds: &ValidCredentials,
        _image: &ImageLocation,
    ) -> Permissions {
        *self
    }

    #[inline(always)]
    async fn blob_permissions(
        &self,
        _creds: &ValidCredentials,
        _blob: &ImageDigest,
    ) -> Permissions {
        *self
    }
}

#[async_trait]
impl AuthProvider for HashMap<String, Secret<String>> {
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        match unverified {
            Unverified::UsernameAndPassword {
                username: unverified_username,
                password: unverified_password,
            } => {
                if let Some(correct_password) = self.get(unverified_username) {
                    if constant_time_eq::constant_time_eq(
                        correct_password.reveal().as_bytes(),
                        unverified_password.reveal().as_bytes(),
                    ) {
                        return Some(ValidCredentials::new(unverified_username.clone()));
                    }
                }

                None
            }
            Unverified::NoCredentials => None,
        }
    }

    #[inline(always)]
    async fn image_permissions(
        &self,
        _creds: &ValidCredentials,
        _image: &ImageLocation,
    ) -> Permissions {
        Permissions::ReadWrite
    }

    #[inline(always)]
    async fn blob_permissions(
        &self,
        _creds: &ValidCredentials,
        _blob: &ImageDigest,
    ) -> Permissions {
        Permissions::ReadWrite
    }
}

#[async_trait]
impl<T> AuthProvider for Box<T>
where
    T: AuthProvider,
{
    #[inline(always)]
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        <T as AuthProvider>::check_credentials(self, unverified).await
    }

    #[inline(always)]
    async fn image_permissions(
        &self,
        _creds: &ValidCredentials,
        _image: &ImageLocation,
    ) -> Permissions {
        Permissions::ReadWrite
    }

    #[inline(always)]
    async fn blob_permissions(
        &self,
        _creds: &ValidCredentials,
        _blob: &ImageDigest,
    ) -> Permissions {
        Permissions::ReadWrite
    }
}

#[async_trait]
impl<T> AuthProvider for Arc<T>
where
    T: AuthProvider,
{
    #[inline(always)]
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        <T as AuthProvider>::check_credentials(self, unverified).await
    }

    #[inline(always)]
    async fn image_permissions(
        &self,
        _creds: &ValidCredentials,
        _image: &ImageLocation,
    ) -> Permissions {
        Permissions::ReadWrite
    }

    #[inline(always)]
    async fn blob_permissions(
        &self,
        _creds: &ValidCredentials,
        _blob: &ImageDigest,
    ) -> Permissions {
        Permissions::ReadWrite
    }
}

#[async_trait]
impl AuthProvider for Secret<String> {
    #[inline(always)]
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        match unverified {
            Unverified::UsernameAndPassword {
                username: _,
                password,
            } => {
                if constant_time_eq::constant_time_eq(
                    password.reveal().as_bytes(),
                    self.reveal().as_bytes(),
                ) {
                    Some(ValidCredentials::new(()))
                } else {
                    None
                }
            }
            Unverified::NoCredentials => None,
        }
    }

    #[inline(always)]
    async fn image_permissions(
        &self,
        _creds: &ValidCredentials,
        _image: &ImageLocation,
    ) -> Permissions {
        Permissions::ReadWrite
    }

    #[inline(always)]
    async fn blob_permissions(
        &self,
        _creds: &ValidCredentials,
        _blob: &ImageDigest,
    ) -> Permissions {
        Permissions::ReadWrite
    }
}
