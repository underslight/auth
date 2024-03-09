use serde::{Serialize, Deserialize};
use surrealdb::sql::{Thing, Id};
use uuid::Uuid;
use crate::prelude::*;
use super::{MfaMethod, MfaMethodType};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpMethod {
    #[serde(rename(deserialize = "in"))]
    id: Thing,
    secret: String,
}

impl TotpMethod {
    pub fn new (user_id: Uuid, secret: String) -> Self {
        Self { 
            id: Thing::from((
                "credential".to_string(),
                Id::Array(vec![MfaMethodType::Totp.to_string(), user_id.to_string()].into())
            )),
            secret 
        }
    }
}

#[typetag::serde]
impl MfaMethod for TotpMethod {
    fn id(&self) -> Thing {
        self.id.clone()
    }
    
    fn r#type(&self) -> MfaMethodType {
        MfaMethodType::Totp
    }   

    fn verify(&self, input: String) -> AuthResult<bool> {
        Ok(boringauth::oath::TOTPBuilder::new()
            .base32_key(&self.secret)
            .output_len(6)
            .finalize()
            .map_err(|_| AuthError::Unknown("Failed to initialize the TOTP state!".into()))?
            .is_valid(&input)
        )
    }
}