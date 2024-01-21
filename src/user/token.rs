use std::{fs::File, io::{BufReader, Read}};
use crate::prelude::*;
use jsonwebtoken::{decode, encode, get_current_timestamp, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Specifies the scope and permissions of a token
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TokenType {
    /// Allows the token to generate new access tokens
    Refresh,
    /// Allows the token to authenticate the associated [User]
    Access,
    /// Allows the token to verify an email or other auth method
    Verification,
    /// Allows the token to reset a [Credential](super::credential::Credential) associated with the [User] 
    Reset,
}

/// The claims for a token
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// The scope and permissions of the token
    pub r#type: TokenType,
    /// The owner of the token
    pub sub: uuid::Uuid,
    /// Id of the server that issued the token
    pub iss: String,
    /// The ID of the SDK which is allowed to consume the token
    pub aud: String,
    /// The creation timestamp 
    pub iat: u64,
    /// The expiry timestamp
    pub exp: u64,
}

/// The general structure of a token
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    /// The actual raw token data
    pub data: String,
    /// The expiration timestamp
    /// 
    /// This is already stored in the token header, but to avoid 
    /// decoding the token, it's easier to provide it directly. 
    pub expires: u64,
}

impl Token {

    /// Gets the private key to sign a token
    /// 
    /// TODO: Fix this!!!
    fn get_encoding_key() -> AuthResult<EncodingKey> {
        
        // Reads the key bytes
        let key_file = File::open("C:\\Users\\User\\Documents\\GitHub\\overslight\\auth\\src\\keys\\private.pem")?;
        let mut reader = BufReader::new(key_file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;

        Ok(EncodingKey::from_ec_pem(buffer.as_slice())?)
    } 

    /// Gets the public key to verify a token
    /// 
    /// TODO: FIX THIS!!!
    fn get_decoding_key() -> AuthResult<DecodingKey> {
        // Reads the key bytes
        let key_file = File::open("C:\\Users\\User\\Documents\\GitHub\\overslight\\auth\\src\\keys\\public.pem")?;
        let mut reader = BufReader::new(key_file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;

        Ok(DecodingKey::from_ec_pem(buffer.as_slice())?)
    }

    /// Generates a new token with the given claims
    pub fn generate(claims: &TokenClaims) -> AuthResult<Self> {

        // Generates the header
        let token_header = Header {
            typ: None,
            alg: jsonwebtoken::Algorithm::ES256,
            cty: None,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None
        };

        // Generates the token
        Ok(Self {
            data: encode(&token_header, claims, &Self::get_encoding_key()?)?,
            expires: claims.exp,
        })
    }

    /// Verifies the validity of a token
    pub fn verify(token: &Self, sub: String) -> AuthResult<TokenClaims> {
        let mut validation_config = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation_config.leeway = 5;
        validation_config.set_audience(&["some-client-id"]);
        validation_config.set_issuer(&["auth-alpha"]);
        validation_config.sub = Some(sub);
        validation_config.validate_exp = false; // This will be checked independantly

        let claims = decode::<TokenClaims>(
            token.data.as_str(), &
            Self::get_decoding_key()?, 
            &validation_config
        )?.claims;

        // Checks if the token is expired
        if get_current_timestamp() > claims.exp {
            return Err(AuthError::TokenExpired);
        }

        Ok(claims)
    }
}

/// A [User]'s ID token
/// 
/// This type of token is used to authenticate with the API
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdToken {
    /// Used to authenticate the [User]
    pub access: Token,
    /// USed to refresh the access token when it expires
    pub refresh: Token,
}