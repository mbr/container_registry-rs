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
#[derive(Debug)]
pub struct ValidCredentials(pub Box<dyn Any + Send>);

impl ValidCredentials {
    /// Creates a new set of valid credentials.
    fn new<T: Send + 'static>(inner: T) -> Self {
        ValidCredentials(Box::new(inner))
    }
}

#[async_trait]
impl FromRequestParts<Arc<ContainerRegistry>> for ValidCredentials {
    type Rejection = StatusCode;

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

/// An authentication and authorization provider.
///
/// At the moment, `container-registry` gives full access to any valid user.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Determines whether the supplied credentials are valid.
    ///
    /// Must return `None` if the credentials are not valid at all, or may return any set of
    /// provider specific credentials (e.g. a username or ID) if they are valid.
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials>;
}

#[async_trait]
impl AuthProvider for bool {
    async fn check_credentials(&self, _unverified: &Unverified) -> Option<ValidCredentials> {
        if *self {
            Some(ValidCredentials::new(()))
        } else {
            None
        }
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
}

#[async_trait]
impl<T> AuthProvider for Box<T>
where
    T: AuthProvider,
{
    #[inline(always)]
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        <T as AuthProvider>::check_credentials(self, creds).await
    }
}

#[async_trait]
impl<T> AuthProvider for Arc<T>
where
    T: AuthProvider,
{
    #[inline(always)]
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        <T as AuthProvider>::check_credentials(self, creds).await
    }
}

#[async_trait]
impl AuthProvider for Secret<String> {
    #[inline(always)]
    async fn check_credentials(&self, unverified: &Unverified) -> Option<ValidCredentials> {
        match creds {
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
}
