use thiserror::Error;
use crate::session::AuthSessionId;
 
/// The error type
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    UserNotFound(String),
    #[error("The account was disabled!")]
    UserDisabled(Vec<String>),
    #[error("Failed to calculate hash!")]
    HashFailed,
    #[error("{0}")]
    CredentialDuplicate(String),
    #[error("{0}")]
    CredentialOnly(String),
    #[error("{0}")]
    CredentialNotFound(String),
    #[error("No MFA code was provided or it was incorrect!")]
    MfaRequired(AuthSessionId),
    #[error("IO error!")]
    Io(std::io::Error),
    #[error("{0}")]
    SaveFailed(String),
    #[error("{0}")]
    UpdateFailed(String), 
    #[error("The token is expired!")]
    TokenExpired,
    #[error("The token is invalid!")]
    TokenInvalid,
    #[error("Something went with the database!")]
    DatabaseFailed(surrealdb::Error),
    #[error("{0}")]
    Unknown(String),
}

impl From<surrealdb::Error> for AuthError {
    fn from(value: surrealdb::Error) -> Self {
        Self::DatabaseFailed(value)
    }
}

impl From<argon2::password_hash::Error> for AuthError {
    fn from(_value: argon2::password_hash::Error) -> Self {
        Self::HashFailed
    }
}

impl From<std::io::Error> for AuthError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(_value: jsonwebtoken::errors::Error) -> Self {
        Self::TokenInvalid
    }
}

impl From<totp_rs::TotpUrlError> for AuthError {
    fn from(_value: totp_rs::TotpUrlError) -> Self {
        Self::Unknown("MFA code verification failed!".into())
    }
}

/// A time-saving replacement for [Result]
pub type AuthResult<T> = std::result::Result<T, AuthError>;
