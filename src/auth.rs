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
use serde::Deserialize;

use super::{
    www_authenticate::{self},
    ContainerRegistry,
};

#[derive(Debug)]
pub struct UnverifiedCredentials {
    pub username: String,
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

#[derive(Debug)]
pub(crate) struct ValidUser(UnverifiedCredentials);

impl ValidUser {
    #[allow(dead_code)] // TODO
    pub(crate) fn username(&self) -> &str {
        &self.0.username
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
            Ok(Self(unverified))
        }
    }
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Determine whether the supplied credentials are valid.
    async fn check_credentials(&self, creds: &UnverifiedCredentials) -> bool;

    /// Check if the given user has access to the given repo.
    async fn has_access_to(&self, username: &str, namespace: &str, image: &str) -> bool;
}

#[async_trait]
impl AuthProvider for bool {
    async fn check_credentials(&self, _creds: &UnverifiedCredentials) -> bool {
        *self
    }

    async fn has_access_to(&self, _username: &str, _namespace: &str, _image: &str) -> bool {
        *self
    }
}

#[async_trait]
impl AuthProvider for HashMap<String, Secret<String>> {
    async fn check_credentials(
        &self,
        UnverifiedCredentials {
            username: unverified_username,
            password: unverified_password,
        }: &UnverifiedCredentials,
    ) -> bool {
        if let Some(correct_password) = self.get(unverified_username) {
            // TODO: Use constant-time compare. Maybe add to `sec`?
            if correct_password == unverified_password {
                return true;
            }
        }

        false
    }

    async fn has_access_to(&self, _username: &str, _namespace: &str, _image: &str) -> bool {
        true
    }
}

#[async_trait]
impl<T> AuthProvider for Box<T>
where
    T: AuthProvider,
{
    #[inline(always)]
    async fn check_credentials(&self, creds: &UnverifiedCredentials) -> bool {
        <T as AuthProvider>::check_credentials(self, creds).await
    }

    #[inline(always)]
    async fn has_access_to(&self, username: &str, namespace: &str, image: &str) -> bool {
        <T as AuthProvider>::has_access_to(self, username, namespace, image).await
    }
}

#[async_trait]
impl<T> AuthProvider for Arc<T>
where
    T: AuthProvider,
{
    #[inline(always)]
    async fn check_credentials(&self, creds: &UnverifiedCredentials) -> bool {
        <T as AuthProvider>::check_credentials(self, creds).await
    }

    #[inline(always)]
    async fn has_access_to(&self, username: &str, namespace: &str, image: &str) -> bool {
        <T as AuthProvider>::has_access_to(self, username, namespace, image).await
    }
}

#[derive(Debug, Default)]
pub(crate) enum MasterKey {
    #[default]
    Locked,
    Key(Secret<String>),
}

impl MasterKey {
    #[cfg(test)]
    #[inline(always)]
    pub(crate) fn new_key(key: String) -> MasterKey {
        MasterKey::Key(Secret::new(key))
    }

    pub(crate) fn as_secret_string(&self) -> Secret<String> {
        match self {
            MasterKey::Locked => Secret::new(String::new()),
            MasterKey::Key(key) => key.clone(),
        }
    }
}

#[async_trait]
impl AuthProvider for MasterKey {
    #[inline]
    async fn check_credentials(&self, creds: &UnverifiedCredentials) -> bool {
        match self {
            MasterKey::Locked => false,
            MasterKey::Key(sec_pw) => constant_time_eq::constant_time_eq(
                creds.password.reveal_str().as_bytes(),
                sec_pw.reveal_str().as_bytes(),
            ),
        }
    }

    /// Check if the given user has access to the given repo.
    #[inline]
    async fn has_access_to(&self, _username: &str, _namespace: &str, _image: &str) -> bool {
        true
    }
}

impl<'de> Deserialize<'de> for MasterKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Option::<String>::deserialize(deserializer)?
            .map(Secret::new)
            .map(MasterKey::Key)
            .unwrap_or(MasterKey::Locked))
    }
}
