use super::Credential;
use crate::prelude::*;
use argon2::{ 
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use serde::{Deserialize, Serialize};
use crate::user::DbUser;
use surrealdb::{
    engine::remote::ws::Client,
    sql::{Id, Thing},
    Surreal,
};

/// The Email/Password auth method (the oldest trick in the book lol)
/// 
/// This allows a [User] to authenticate via their email and password.
/// The password is hashed with Argon2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailPasswordCredential {
    /// The credential's identifier. This is actually an array with two
    /// strings: the first one represents the credential type (in this case `EmailPassword`)
    /// while the second one is the actual identifier (which in the case is the [User]'s email).
    pub id: Thing,
    data: String,
    #[serde(skip)]
    hashed: bool,
    #[serde(skip_serializing, rename(deserialize = "out"))]
    associated_user: Option<Thing>,
}

impl EmailPasswordCredential {
    /// The credential's constructor
    pub fn new(email: String, password: String) -> Self {
        Self {
            id: Thing::from((
                "credential".to_string(),
                Id::Array(vec!["EmailPassword".to_string(), email].into()),
            )),
            data: password,
            hashed: false,
            associated_user: None,
        }
    }
}

#[typetag::serde]
#[async_trait::async_trait]
impl Credential for EmailPasswordCredential {

    fn id(&self) -> &Thing {
        &self.id 
    }

    fn hashed(&self) -> AuthResult<Box<dyn Credential>> {
        
        // Checks if the credential has already been hashed
        if self.hashed {
            return Ok(Box::new(self.clone()));
        }

        Ok(Box::new(Self {
            id: self.id.clone(),
            data: Argon2::default()
                .hash_password(self.data.as_bytes(), &SaltString::generate(&mut OsRng))?
                .to_string(),
            hashed: true,
            associated_user: self.associated_user.clone(),
        }))
    }

    async fn authenticate(&self, db: &Surreal<Client>) -> AuthResult<User> {
        // Fetches the credential with the identifier (if it exists)
        let credential: Self = db
            .query("SELECT * FROM $credential_id->authenticates;")
            .bind(("credential_id", self.id.clone()))
            .await?
            .take::<Option<Self>>(0)?
            .ok_or(AuthError::CredentialNotFound("The credential is incorrect or could not be found!".into()))?;

        // Checks if the password and the hash match
        Argon2::default()
            .verify_password(self.data.as_ref(), &PasswordHash::new(&credential.data)?)
            .map_err(|_| AuthError::CredentialNotFound("The credential is incorrect or could not be found!".into()))?;

        // Fetches the user associated with the user id
        let mut user: User = db
            .query("SELECT * FROM $user_id;")
            .bind(("user_id", credential.associated_user))
            .await?
            .take::<Option<DbUser>>(0)?
            .ok_or(AuthError::Unknown("The associated user doesn't exist!".into()))?
            .into();

        // Checks if the user's account has been disabled
        if user.metadata.disabled {
            return Err(AuthError::UserDisabled);
        }

        // Updates the last access timestamp
        user.metadata.last_access = jsonwebtoken::get_current_timestamp();
        user
            .update(&db)
            .await
            .map_err(|_| AuthError::UpdateFailed("Failed to update last access!".into()))?;

        Ok(user)
    }
}
