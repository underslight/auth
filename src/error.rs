use thiserror::Error;
use serde::Serialize;
 
/// The error type
#[non_exhaustive]
#[derive(Error, Debug, Serialize)]
pub enum AuthError {
    #[error("Invalid user UUID!")]
    InvalidUserUuid,
    #[error("Invalid user attributes!")]
    InvalidUserAttributes,
    #[error("Invalid user metadata!")]
    InvalidUserMetadata,
    #[error("The user doesn't exist or could not be found!")]
    InexistentUser,
    #[error("The user's account has been disabled!")]
    DisabledUser, // don't call it that lol

    #[error("Fucked with the database!")]
    Database(surrealdb::Error),

    #[error("Invalid credential identifier!")]
    InvalidCredentialIdentifier,
    #[error("Invalid credential type!")]
    InvalidCredentialType,

    #[error("Failed to update the last access timestamp")]
    FailedLastAccessUpdate,

    #[error("Failed to calculate hash!")]
    Hash,

    #[error("The credentials provided were incorrect!")]
    IncorrectCredential,
    #[error("The credential/user already exists!")]
    DuplicateCredential,
    #[error("The credential isn't associated with the user!")]
    UnassociatedCredential,
    #[error("Cannot delete the only authentication method!")]
    CannotRemoveOnlyCredential,

    #[error("Token error!")]
    Token,

    #[error("IO error!")]
    Io,

    #[error("Something went critically wrong! Avoided panic!")]
    Panic(String),
}

impl From<surrealdb::Error> for AuthError {
    fn from(value: surrealdb::Error) -> Self {
        Self::Database(value)
    }
}

impl From<argon2::password_hash::Error> for AuthError {
    fn from(_value: argon2::password_hash::Error) -> Self {
        Self::Hash
    }
}

impl From<std::io::Error> for AuthError {
    fn from(_value: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(_value: jsonwebtoken::errors::Error) -> Self {
        Self::Token
    }
}

/// A time-saving replacement for [Result]
pub type AuthResult<T> = std::result::Result<T, AuthError>;
