use serde::{Deserialize, Serialize};
use surrealdb::{engine::remote::ws::Client, sql::Thing, Surreal};
use crate::prelude::*;

/// Email/password authentication
pub mod email_password;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    EmailPassword,
}

/// Defines all credential types
#[async_trait::async_trait]
#[typetag::serde(tag = "type")]
pub trait Credential: std::fmt::Debug {

    // /// Saves the credential to the database. 
    // /// When a credential is saved to the DB it automatically creates
    // /// a new empty [User] and associates itself with that [User].
    // async fn save(&self, db: &Self::Database) -> AuthResult<User>;

    // /// This does a very similar thing as [save](Credential::save), except
    // /// it associates the [Credential] with a preexisting [User].
    // /// 
    // /// This should be used when a [User] adds a new auth method.
    // async fn associate(&self, db: &Self::Database, user: &User) -> AuthResult<Self>;

    /// Returns the credential's id
    /// 
    /// # Note:
    /// Credential ids have a particular structure: they're an array of two strings.
    /// The first string represent the credential type (e.g `EmailPassword`, `GoogleOauth`, etc.)
    /// while the second string is the actual credential identifier (which is usually the [User]'s email).
    /// This is because different credential types tend to have the same identifier (usually an email).
    fn id(&self) -> &Thing;

    fn r#type(&self) -> CredentialType;

    /// Returns a credential with all the sensitive data hashed.
    /// This should only be used when binding to a query
    fn hashed(&self) -> AuthResult<Box<dyn Credential>>;

    /// Authenticates a credential. If the credential values are correct, the 
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
    async fn authenticate(&self, db: &Surreal<Client>) -> AuthResult<User>;
}
