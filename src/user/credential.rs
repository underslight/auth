use serde::{Deserialize, Serialize};
use surrealdb::{engine::remote::ws::Client, sql::Thing, Surreal};
use crate::{prelude::*, session::AuthSessionId};
use strum_macros::{EnumString, Display};

/// Email/password authentication
pub mod email_password;
/// TOTP MFA authentication
pub mod totp;

#[typetag::serde(tag = "type")]
pub trait DbAuthMethod: std::fmt::Debug + Send + Sync {
    /// Returns the auth method's id
    /// 
    /// # Note:
    /// Auth method ids have a particular structure: they're an array of two strings.
    /// The first string represent the method type (e.g `EmailPassword`, `GoogleOauth`, etc.)
    /// while the second string is the actual method identifier (which is usually the [User]'s email).
    /// This is because different credential types tend to have the same identifier.
    fn id(&self) -> Thing;
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, EnumString, Display, PartialEq)]
pub enum AuthMethodType {
    EmailPassword,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, EnumString, Display, PartialEq)]
pub enum MfaMethodType {
    Totp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaCode {
    pub method: MfaMethodType,
    pub data: String,
}

/// Defines all primary credential types
#[async_trait::async_trait]
#[typetag::serde(tag = "type")]
pub trait AuthMethod: std::fmt::Debug {

    /// Returns the type of authentication method
    fn r#type(&self) -> AuthMethodType;

    // /// Returns the restructured credential that should be inserted into the DB
    fn into_db(&self) -> AuthResult<Box<dyn DbAuthMethod>>; 

    /// Uses the credentials provided to authenticate the [User]. If the credential values are correct, the 
    /// function will return the [User] associated with it
    /// 
    /// # Example
    /// ```ignore
    /// use auth::user::credential::EmailPasswordCredential;
    /// use auth::prelude::*;
    /// 
    /// let user = EmailPasswordCredential::new(
    ///         "email@example.com".into(),
    ///         "Sup3r_S3cure_P4ssword".into()
    ///     )
    ///     .authenticate(&db)
    ///     .await
    ///     .unwrap();
    /// ```
    async fn authenticate(&self, db: &Surreal<Client>, mfa: Option<MfaCode>) -> AuthResult<(User, AuthSessionId)>;
}

#[async_trait::async_trait]
#[typetag::serde(tag = "type")]
pub trait MfaMethod: std::fmt::Debug + Send {
    fn id(&self) -> Thing; 
    fn r#type(&self) -> MfaMethodType;
    async fn verify(&self, user: &User, db: &Surreal<Client>, input: String) -> AuthResult<AuthSessionId>;
}