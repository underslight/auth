// use auth::builder::{Buildable, Builder};
use auth::prelude::*;
use auth::user::attributes::UserAttribute;

// use auth::user::credential::email_password::EmailPasswordCredential;
// use auth::user::credential::Credential;
// use auth::user::metadata::UserMetadata;
use serde::{Deserialize, Serialize};
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Database;
use surrealdb::Surreal;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CustomAttributes {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CustomAttributesB {
    pub role: String,
    pub old: bool,
}

#[typetag::serde]
impl UserAttribute for CustomAttributes {}

#[typetag::serde]
impl UserAttribute for CustomAttributesB {}

#[tokio::main]
async fn main() -> AuthResult<()> {
    let db = Surreal::new::<Ws>("127.0.0.1:8000").await.unwrap();

    db.signin(Database {
        namespace: "dev",
        database: "alpha",
        username: "dev",
        password: "ved",
    }) 
    .await
    .unwrap();

    Ok(())
}
