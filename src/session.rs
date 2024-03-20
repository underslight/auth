use serde::{Deserialize, Serialize};
use surrealdb::{engine::remote::ws::Client, Surreal};
use uuid::Uuid;

use crate::prelude::{AuthError, AuthResult};

pub type AuthSessionId = String;

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthSessionState {
    PendingMfa,
    Authenticated,
}

#[derive(Debug, Serialize, Deserialize)] 
pub struct AuthSession {
    pub id: AuthSessionId,
    pub user: Uuid,
    pub state: AuthSessionState,
    pub expires: u64,
    pub agent: Option<String>,
}

impl AuthSession {
    pub fn new(user_id: &Uuid, state: AuthSessionState, agent: Option<String>) -> Self {
        Self {
            id: String::from("sad"),
            user: user_id.clone(),
            state,
            expires: 1,
            agent,
        }
    }

    pub async fn save(&self, db: &Surreal<Client>) -> AuthResult<Self> {
        Ok(
            db
            .query("CREATE auth_session CONTENT $session;")
            .bind(("session", self))
            .await?
            .take::<Option<Self>>(0)
            .map_err(|_| AuthError::CredentialDuplicate("This user is already authenticated!".into()))?
            .ok_or(AuthError::SaveFailed("Failed to create the session!".into()))?
            .into()
        )
    }

    pub async fn get_by_id(db: &Surreal<Client>, id: AuthSessionId) -> AuthResult<Self> {
        Ok(
            db 
            .query("SELECT * FROM type::thing('auth_session', $session_id);")
            .bind(("session_id", id))
            .await?
            .take::<Option<Self>>(0)
            .map_err(|_| AuthError::CredentialDuplicate("This user is already authenticated!".into()))?
            .ok_or(AuthError::SaveFailed("The session doesn't exist or couldn't be found!".into()))?
            .into()
        )
    }
}