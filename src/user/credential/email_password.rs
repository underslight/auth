use super::{AuthMethod, AuthMethodType, DbAuthMethod, MfaCode};
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
pub struct EmailPasswordMethod {
    /// The user's email
    pub email: String,
    password: String,
}

/// The database representation of the Email/Password auth 
/// method. This is fundamentally different from [EmailPasswordMethod]:
///  - Since the password it contains is hashed, it *cannot* be converted
///    back to an [EmailPasswordMethod]
///  - It contains a SurrealDb id
///  - It contains the owner's ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DbEmailPasswordMethod {
    #[serde(rename(deserialize = "in"))]
    pub id: Thing,
    data: String,
    #[serde(skip_serializing, rename(deserialize = "out"))]
    associated_user: Option<Thing>,
}

#[typetag::serde]
impl DbAuthMethod for DbEmailPasswordMethod {
    fn id(&self) -> Thing {
        self.id.clone()
    }
}

impl EmailPasswordMethod {
    /// The auth method's constructor
    pub fn new(email: String, password: String) -> Self {
        Self { email, password }
    }
}

#[typetag::serde]
#[async_trait::async_trait]
impl AuthMethod for EmailPasswordMethod {

    fn r#type(&self) -> AuthMethodType {
        AuthMethodType::EmailPassword
    }

    fn into_db(&self) -> AuthResult<Box<dyn DbAuthMethod>> {
        Ok(Box::new(DbEmailPasswordMethod {
            id: Thing::from((
                "credential".to_string(),
                Id::Array(vec![self.r#type().to_string(), self.email.clone()].into()),
            )),
            data: Argon2::default()
                .hash_password(self.password.as_bytes(), &SaltString::generate(&mut OsRng))?
                .to_string(),
            associated_user: None,
        }))
    }

    async fn authenticate(&self, db: &Surreal<Client>, mfa: Option<MfaCode>) -> AuthResult<User> {
        
        // Fetches the credential with the identifier (if it exists)
        let credential: DbEmailPasswordMethod = db
            .query("SELECT * FROM $credential_id->authenticates;")
            .bind(("credential_id", self.into_db()?.id()))
            .await?
            .take::<Option<DbEmailPasswordMethod>>(0)?
            .ok_or(AuthError::CredentialNotFound("1 The credential is incorrect or could not be found!".into()))?;

        // Checks if the password and the hash match
        Argon2::default()
            .verify_password(self.password.as_ref(), &PasswordHash::new(&credential.data)?)
            .map_err(|_| AuthError::CredentialNotFound("2 The credential is incorrect or could not be found!".into()))?;

        // Fetches the user associated with the user id
        let mut user: User = db
            .query("SELECT * FROM $user_id;")
            .bind(("user_id", credential.associated_user))
            .await?
            .take::<Option<DbUser>>(0)?
            .ok_or(AuthError::Unknown("The associated user doesn't exist!".into()))?
            .into();

        // Checks the MFA code
        match mfa {
            Some(code) => {

                let mfa_credentials = user
                    .get_mfa_credentials(db, Some(code.method))
                    .await?;

                    let mfa_credential = mfa_credentials.get(0);

                if let Some(mfa_credential) = mfa_credential {

                    // Checks if the code is invalid
                    if !mfa_credential.verify(code.data)? {
                        return Err(AuthError::CredentialNotFound("The MFA credential is incorrect!".into()))
                    }
                } else {

                    // The MFA method isn't supported
                    return Err(AuthError::CredentialNotFound("The MFA credential is incorrect!".into()))
                }
            },
            None => {

                // Checks if MFA is required
                if user.get_mfa_methods(db).await?.len() > 0 {
                    return Err(AuthError::MfaRequired);
                }
            }
        }

        // Checks if the user's account has been disabled
        if let Some(reason) = user.metadata.disabled {
            return Err(AuthError::UserDisabled(reason));
        }

        // Updates the last access timestamp
        user.metadata.last_access = jsonwebtoken::get_current_timestamp();
        user
            .update(db)
            .await
            .map_err(|_| AuthError::UpdateFailed("Failed to update last access!".into()))?;

        Ok(user)
    }

    async fn authenticate_loose(&self, db: &Surreal<Client>) -> AuthResult<User> {
        
        // Fetches the credential with the identifier (if it exists)
        let credential: DbEmailPasswordMethod = db
            .query("SELECT * FROM $credential_id->authenticates;")
            .bind(("credential_id", self.into_db()?.id()))
            .await?
            .take::<Option<DbEmailPasswordMethod>>(0)?
            .ok_or(AuthError::CredentialNotFound("1 The credential is incorrect or could not be found!".into()))?;

        // Checks if the password and the hash match
        Argon2::default()
            .verify_password(self.password.as_ref(), &PasswordHash::new(&credential.data)?)
            .map_err(|_| AuthError::CredentialNotFound("2 The credential is incorrect or could not be found!".into()))?;

        // Fetches the user associated with the user id
        let user: User = db
            .query("SELECT * FROM $user_id;")
            .bind(("user_id", credential.associated_user))
            .await?
            .take::<Option<DbUser>>(0)?
            .ok_or(AuthError::Unknown("The associated user doesn't exist!".into()))?
            .into();

        // Checks if the user's account has been disabled
        if let Some(reason) = user.metadata.disabled {
            return Err(AuthError::UserDisabled(reason));
        }

        Ok(user)
    }
}
