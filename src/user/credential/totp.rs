use rand::{distributions::Uniform, Rng};
use serde::{Serialize, Deserialize};
use surrealdb::{engine::remote::ws::Client, sql::{Id, Thing}, Surreal};
use totp_rs::TOTP;
use uuid::Uuid;
use crate::{prelude::*, session::{AuthSessionId, AuthSessionState}};
use super::{MfaMethod, MfaMethodType};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpMethod {
    #[serde(rename(deserialize = "in"))]
    id: Thing,
    secret: Vec<u8>,
}

impl TotpMethod {
    const CODE_LENGTH: usize = 6;
    const CODE_SKEW: u8 = 1;
    const CODE_DURATION: u64 = 30;

    pub fn new (user_id: Uuid) -> Self {

        // Generates the secret
        let secret = rand::thread_rng()
            .sample_iter(Uniform::new(u8::MIN, u8::MAX))
            .take(128)
            .collect();

        Self { 
            id: Thing::from((
                "credential".to_string(),
                Id::Array(vec![MfaMethodType::Totp.to_string(), user_id.to_string()].into())
            )),
            secret
        }
    }

    pub fn get_qr_code(&self) -> AuthResult<String> {
        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            Self::CODE_LENGTH,
            Self::CODE_SKEW, 
            Self::CODE_DURATION,
            self.secret.clone(),
            Some(String::from("Underslight")),
            String::from("test") 
        )?;

        totp
            .get_qr_base64()
            .map_err(|err| AuthError::Unknown(err))
    }

    pub fn get_secret(&self) -> AuthResult<String> {
        let totp = TOTP::new(
            totp_rs::Algorithm::SHA1,
            Self::CODE_LENGTH,
            Self::CODE_SKEW, 
            Self::CODE_DURATION,
            self.secret.clone(),
            Some(String::from("Underslight")),
            String::from("test")
        )?;

        Ok(totp.get_secret_base32())
    }
}

#[async_trait::async_trait]
#[typetag::serde]
impl MfaMethod for TotpMethod {
    fn id(&self) -> Thing {
        self.id.clone()
    }
    
    fn r#type(&self) -> MfaMethodType {
        MfaMethodType::Totp
    }   

    async fn verify(&self, user: &User, db: &Surreal<Client>, token: String) -> AuthResult<AuthSessionId> {
        
        let totp = TOTP::new( 
            totp_rs::Algorithm::SHA1,
            Self::CODE_LENGTH,
            Self::CODE_SKEW, 
            Self::CODE_DURATION,
            self.secret.clone(),
            Some(String::from("Underslight")),
            String::from("test")
        )?;

        let valid = totp.check(
            token.as_str(), 
            jsonwebtoken::get_current_timestamp()
        );

        if valid {

            // Creates the auth session
            let session = user 
                .create_auth_session(db, AuthSessionState::Authenticated, None)
                .await?;

            return Ok(session);
        } else {

            // Creates the pending auth session
            let session = user 
                .create_auth_session(db, AuthSessionState::PendingMfa, None)
                .await?;

            return Err(AuthError::MfaRequired(session));
        }
    }
}