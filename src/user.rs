/// Credentials and authentication methods
/// 
/// Since [Users](User) can have multiple authentication methods, [Credentials](Credential), in the database,
/// are stored as separate nodes all connected to a [User] via a graph edge. This allows us to store any number
/// of authentication methods without changing the [User] schema and without requiring all of them for authentication.
/// 
/// # Credential Id
/// The credential `id` field is stored as a [Thing] to allow for easier queries with the DB, nonetheless all credentials
/// have a fairly complex ID structure: they are an array containing two strings. The first string represent the credential 
/// type (e.g. `EmailPassword`, `GoogleOauth`, etc.) which the second string is the actual identifier (which is usually the email).
/// 
/// # Other fields
/// The fields of the credential vary based on the [Credential] type, but most store all of the important data in the `data` field.
pub mod credential;

/// [User] metadata
/// 
/// The user's metadata contains auth data which can be used to protect the [User]'s account with additional authentication factors.
/// For example the metadata stores previous access times and locations: if an account is inactive for a long time or it's accessed 
/// from a new location, an additional security factor may be applied.
pub mod metadata;

/// Custom [User] attributes 
///
/// The [User] struct has an `attributes` field.
/// This field can contain any struct (that implements [UserAttribute]).
/// It should be used to contain custom data associated with each user, 
/// such as name, role, etc. 
pub mod attributes;

/// Jwts and all sorts of auth tokens
pub mod token;

use attributes::UserAttribute;
use jsonwebtoken::get_current_timestamp;
use serde::Deserialize;
use surrealdb::engine::remote::ws::Client;
use surrealdb::sql::Value;
use surrealdb::Surreal;

use crate::builder::*;
use crate::prelude::*;
use metadata::UserMetadata;
use serde::Serialize;
use surrealdb::sql::Thing;


use uuid::Uuid;

use self::credential::Credential;
use self::token::IdToken;
use self::token::Token;
use self::token::TokenClaims;
use self::token::TokenType;

/// This struct contains the metadata and attributes of each user.
/// 
/// The actual credential data isn't associated with the [User] struct 
/// in any way: since a single [User] can have multiple [Credentials](credential::Credential),
/// they're only associated in the DB via graph relations.
/// 
/// Creating a [User] is straightforward: 
/// ```ignore
/// let user = User::builder ()
///     .attributes(...)
///     .metadata(...)
///     .id(...)
///     .build()?;
/// ``` 
/// 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    /// This contains the [User]'s UUID.
    pub id: Uuid,
    /// The attributes are a set of custom fields that contain unique data
    /// about the user.
    pub attributes: Option<Box<dyn UserAttribute>>,
    /// The metadata contains auth data such as previous password, 
    /// last access location, and such.
    pub metadata: UserMetadata,
}

/// This struct is the database representation of the [User] struct.
/// 
/// It's necessary since the DB requires that the id is a [Thing], but
/// this makes the struct awkward when using it outside the auth module, 
/// so we have this.
/// 
/// Whenever a [User] is saved to the DB, it's converted to a [DbUser], and viceversa.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DbUser {
    /// This contains the [User]'s UUID.
    pub id: Thing,
    /// The attributes are a set of custom fields that contain unique data
    /// about the user.
    pub attributes: Option<Box<dyn UserAttribute>>,
    /// The metadata contains auth data such as previous password, 
    /// last access location, and such.
    pub metadata: UserMetadata,
}

impl From<&User> for DbUser {
    fn from(value: &User) -> Self {
        Self {
            id: Thing::from(("user".into(), value.id.to_string())),
            attributes: value.attributes.clone(),
            metadata: value.metadata.clone(),
        }
    }
} 

impl From<DbUser> for User {
    fn from(value: DbUser) -> Self {
        Self {
            id: Uuid::parse_str(match &value.id.id {
                surrealdb::sql::Id::String(id) => id.as_str(),
                _ => panic!() // This should never happen!!!
            }).unwrap(),
            attributes: value.attributes.clone(),
            metadata: value.metadata.clone(),
        }
    }
}

/// This is the [Builder] struct for [User].
#[derive(Clone, Debug, Default)]
pub struct UserBuilder {
    /// The [User]'s UUID
    pub id: Option<Uuid>,
    /// The [User]'s attributes
    pub attributes: Option<Box<dyn UserAttribute>>,
    /// The [User]'s metadata 
    pub metadata: Option<UserMetadata>,
}

impl Buildable for User {
    type Builder = UserBuilder;
}

impl Builder for UserBuilder {
    type Buildable = User;

    fn new() -> Self {
        Self::default()
    }

    fn build(&self) -> AuthResult<Self::Buildable> {
        Ok(self.build_safe())
    }

    fn build_safe(&self) -> Self::Buildable {
        Self::Buildable {
            id: match &self.id {
                Some(id) => id.clone(),
                None => Uuid::new_v4(),
            },
            attributes: self.attributes.clone(),
            metadata: match &self.metadata {
                Some(metadata) => metadata.clone(),
                None => UserMetadata::default(),
            },
        }
    }
}

impl UserBuilder {
    /// Sets the [User]'s UUID
    pub fn id(&mut self, id: Uuid) -> &mut Self {
        self.id = Some(id);
        self
    }

    /// Sets the [User]'s custom attributes
    pub fn attributes(&mut self, attributes: Box<dyn UserAttribute>) -> &mut Self {
        self.attributes = Some(attributes);
        self
    }

    /// Sets the [User]'s metadata
    pub fn metadata(&mut self, metadata: UserMetadata) -> &mut Self { 
        self.metadata = Some(metadata);
        self
    }
}

impl User {
    /// Sets the `disabled` flag in the [UserMetadata] struct
    /// 
    /// # Note:
    /// To apply the changes you must call the [update](Self::update) method
    pub fn disabled(&mut self, disabled: Option<Vec<String>>) -> &mut Self {
        self.metadata.disabled = disabled;
        self

    }

    /// Sets the `verified` flag in the [UserMetadata] struct
    /// 
    /// # Note:
    /// To apply the changes you must call the [update](Self::update) method
    pub fn verified(&mut self, verified: bool) -> &mut Self {
        self.metadata.verified = verified;
        self
    }

    /// Sets the `attributes` field in the [User] struct
    pub fn attributes(&mut self, attributes: Box<dyn UserAttribute>) -> &mut Self {
        self.attributes = Some(attributes);
        self
    }

    /// Saves the [User] to the database and associates it to the given credential
    pub async fn save<T: Credential + Serialize>(&self, db: &Surreal<Client>, credential: &T) -> AuthResult<Self> {
        Ok(db
            .query("
                BEGIN TRANSACTION;
                    CREATE $credential.id;
                    CREATE user CONTENT $user;
                    RELATE ($credential.id)->authenticates->($user.id) CONTENT $credential;
                    RETURN $user;
                COMMIT TRANSACTION;
            ")
            .bind(("credential", credential.hashed()?))
            .bind(("user", DbUser::from(self)))
            .await?
            .take::<Option<DbUser>>(0)
            .map_err(|_| AuthError::CredentialDuplicate("This user is already registered!".into()))?
            .ok_or(AuthError::SaveFailed("Failed to save user!".into()))?
            .into())
    }

    /// Applies any changes in the [User] struct by saving the in the DB
    pub async fn update(&self, db: &Surreal<Client>) -> AuthResult<Self> {
        Ok(db
            .query("UPDATE $user.id CONTENT $user RETURN AFTER;")
            .bind(("user", DbUser::from(self)))
            .await?
            .take::<Option<DbUser>>(0)
            .map_err(|_| AuthError::UpdateFailed("Failed to update user!".into()))?
            .ok_or(AuthError::UpdateFailed("Failed to update user!".into()))?
            .into())
    }

    /// Associates a new credential with the [User]
    pub async fn add_credential(&self, db: &Surreal<Client>, credential: Box<dyn Credential>) -> AuthResult<Self> {

        // Checks if this type of credential has already been associated
        let already_associated = self
            .credentials(&db)
            .await?
            .iter()
            .find(|id| match &id.id {
                surrealdb::sql::Id::Array(array) => match &array.0[0] {
                    Value::Strand(r#type) => r#type.0 == format!("{:?}", credential.r#type()),
                    _ => false,
                }
                _ => false,
            }).is_some();

        if already_associated {
            return Err(AuthError::CredentialDuplicate("Cannot associate the same credential twice!".into()));
        }

        Ok(db 
            .query("
                BEGIN TRANSACTION;
                    CREATE $credential.id;
                    RELATE ($credential.id)->authenticates->($user.id) CONTENT $credential;
                    RETURN $user;
                COMMIT TRANSACTION;
            ")
            .bind(("credential", credential.hashed()?))
            .bind(("user", DbUser::from(self)))
            .await?
            .take::<Option<DbUser>>(0)
            .map_err(|_| AuthError::CredentialDuplicate("Cannot associate the same credential twice!".into()))?
            .ok_or(AuthError::UpdateFailed("Failed to add the authentication method!".into()))?
            .into())
    }

    /// Deletes the [User] from the database
    pub async fn delete(&self, db: &Surreal<Client>) -> AuthResult<()> {
        let credentials = self
            .credentials(&db)
            .await?;

        db
            .query("DELETE $user_id, $credential_ids;")
            .bind(("user_id", DbUser::from(self).id))
            .bind(("credential_ids", credentials))
            .await?;

        Ok(())
    }

    /// Generates and signs an Id token
    pub fn get_id_token(&self) -> AuthResult<IdToken> {

        // Generates the claims
        let timestamp = get_current_timestamp();
        let access_claims = TokenClaims {
            iss: "auth-alpha".into(),
            r#type: token::TokenType::Access,
            sub: self.id,
            aud: "some-client-id".into(),
            iat: timestamp,
            exp: timestamp + 3600,
        };

        let mut refresh_claims = access_claims.clone();
        refresh_claims.r#type = TokenType::Refresh;
        refresh_claims.exp = timestamp + 3600 * 24 * 7;

        Ok(IdToken {
            access: Token::generate(&access_claims)?,
            refresh: Token::generate(&refresh_claims)?,
        })
    }

    /// Fetches a user by their UUID
    pub async fn get_by_uuid(db: &Surreal<Client>, uuid: &Uuid) -> AuthResult<Self> {
        Ok(db
            .query("SELECT * FROM $user_id;")
            .bind(("user_id", Thing::from(("user".to_string(), uuid.to_string()))))
            .await?
            .take::<Option<DbUser>>(0)?
            .ok_or(AuthError::UserNotFound("The user couldn't be found or doesn't exist!".into()))?
            .into())
    }

    /// Fetches the user that owns a given ID token
    pub async fn get_by_id_token(db: &Surreal<Client>, id_token: &IdToken) -> AuthResult<Self> {

        // Verifies the access token
        let access_claims = Token::verify(&id_token.access, None)?;

        // Fetches the user
        Self::get_by_uuid(db, &access_claims.sub)
            .await
    }

    /// Fetches the list of credentials associated with the [User]
    pub async fn credentials(&self, db: &Surreal<Client>) -> AuthResult<Vec<Thing>> {
        let credentials: Vec<Thing> = db
            .query("SELECT in FROM ($user_id)<-authenticates;")
            .bind(("user_id", DbUser::from(self).id))
            .await?
            .take("in")?;

        Ok(credentials)
    }

    /// Deletes a given credential as long as it's associated with the [User] and it's not the only credential
    pub async fn remove_credential<T: Credential + Serialize>(&self, db: &Surreal<Client>, credential: &T) -> AuthResult<Self> {

        // Gets all the credentials associated with the user
        let credentials = self
            .credentials(&db)
            .await?;

        // Checks if the credential exists
        if credentials.iter().find(|&cred| cred == credential.id()).is_some() {

            // Cannot delete the user's only authentication method
            if credentials.len() > 1 {

                // Deletes the credential
                db 
                    .query("DELETE $credential;")
                    .bind(("credential", credential))
                    .await?;
            } else {
                return Err(AuthError::CredentialOnly("Cannot remove the only authentication method!".into()));
            }
        } else {
            return Err(AuthError::CredentialNotFound("The authentication method couldn't be found or doesn't exist!".into()));
        }

        Ok(self.clone())
    }
}
