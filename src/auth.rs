//! Authentication backends.
//!
//! The `container-registry` supports pluggable authentication, as anything that implements the
//! [`AuthProvider`] trait can be used as an authentication (and authorization) backend. Included
//! are implementations for the following types:
//!
//! * `bool`: A simple always deny (`false`) / always allow (`true`) backend, mainly used in tests
//!           and example code.
//! * `HashMap<String, Secret<String>>`: A mapping of usernames to (unencrypted) passwords.
//! * `Secret<String>`: Master password, ignores all usernames and just compares the password.
//!
//! To provide some safety against accidentally leaking passwords via stray `Debug` implementations,
//! this crate uses the [`sec`]'s crate [`Secret`] type.

use std::{collections::HashMap, str, sync::Arc};

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

use super::{
    www_authenticate::{self},
    ContainerRegistry,
};

/// A set of credentials supplied that has not been verified.
#[derive(Debug)]
pub struct UnverifiedCredentials {
    /// The given username.
    pub username: String,
    /// The provided password.
    pub password: Secret<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for UnverifiedCredentials {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION) {
            let (_unparsed, basic) = www_authenticate::basic_auth_response(auth_header.as_bytes())
                .map_err(|_| StatusCode::BAD_REQUEST)?;

            Ok(UnverifiedCredentials {
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
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// A set of credentials that has been validated.
///
/// Newtype used to avoid accidentally granting access from unverified credentials.
#[derive(Debug)]
pub struct ValidUser(String);

impl ValidUser {
    /// Returns the valid user's username.
    #[inline(always)]
    pub fn username(&self) -> &str {
        &self.0
    }
}

#[async_trait]
impl FromRequestParts<Arc<ContainerRegistry>> for ValidUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ContainerRegistry>,
    ) -> Result<Self, Self::Rejection> {
        let unverified = UnverifiedCredentials::from_request_parts(parts, state).await?;

        // We got a set of credentials, now verify.
        if !state.auth_provider.check_credentials(&unverified).await {
            Err(StatusCode::UNAUTHORIZED)
        } else {
            Ok(Self(unverified.username))
        }
    }
}

/// An authentication and authorization provider.
///
/// At the moment, `container-registry` gives full access to any valid user.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    type VerifiedCredentials;

    /// Determines whether the supplied credentials are valid.
    ///
    /// Must return `true` if and only if the given unverified credentials are valid.
    async fn check_credentials(
        &self,
        creds: &UnverifiedCredentials,
    ) -> Option<Self::VerifiedCredentials>;
}

#[async_trait]
impl AuthProvider for bool {
    type VerifiedCredentials = ();

    async fn check_credentials(&self, _creds: &UnverifiedCredentials) -> Option<()> {
        if self {
            Some(())
        } else {
            None
        }
    }
}

#[async_trait]
impl AuthProvider for HashMap<String, Secret<String>> {
    type VerifiedCredentials = String;

    async fn check_credentials(
        &self,
        UnverifiedCredentials {
            username: unverified_username,
            password: unverified_password,
        }: &UnverifiedCredentials,
    ) -> bool {
        if let Some(correct_password) = self.get(unverified_username) {
            if constant_time_eq::constant_time_eq(
                correct_password.reveal().as_bytes(),
                unverified_password.reveal().as_bytes(),
            ) {
                Some(unverified_username.clone())
            } else {
                None
            }
        }

        false
    }
}

#[async_trait]
impl<T> AuthProvider for Box<T>
where
    T: AuthProvider,
{
    type VerifiedCredentials = <T as AuthProvider>::VerifiedCredentials;

    #[inline(always)]
    async fn check_credentials(
        &self,
        creds: &UnverifiedCredentials,
    ) -> Option<Self::VerifiedCredentials> {
        <T as AuthProvider>::check_credentials(self, creds).await
    }
}

#[async_trait]
impl<T> AuthProvider for Arc<T>
where
    T: AuthProvider,
{
    type VerifiedCredentials = <T as AuthProvider>::VerifiedCredentials;

    #[inline(always)]
    async fn check_credentials(
        &self,
        creds: &UnverifiedCredentials,
    ) -> Option<Self::VerifiedCredentials> {
        <T as AuthProvider>::check_credentials(self, creds).await
    }
}

#[async_trait]
impl AuthProvider for Secret<String> {
    type VerifiedCredentials = ();

    #[inline(always)]
    async fn check_credentials(&self, creds: &UnverifiedCredentials) -> Option<()> {
        if constant_time_eq::constant_time_eq(
            creds.password.reveal().as_bytes(),
            self.reveal().as_bytes(),
        ) {
            Some(())
        } else {
            None
        }
    }
}
