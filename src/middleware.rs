use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub username: String,
    pub exp: i64,
}

pub struct JwtMiddleware {
    secret_key: String,
}

impl JwtMiddleware {
    pub fn new(secret_key: String) -> Self {
        Self { secret_key }
    }
}

#[async_trait]
impl Handler for JwtMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = auth_str.trim_start_matches("Bearer ").trim();

                    let decoded = decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(self.secret_key.as_bytes()),
                        &Validation::default(),
                    );

                    match decoded {
                        Ok(token_data) => {
                            depot.insert("claims", token_data.claims);
                            return;
                        }
                        Err(_) => {
                            res.status_code(StatusCode::UNAUTHORIZED);
                            ctrl.skip_rest();
                            return;
                        }
                    }
                }
            }
        }

        res.status_code(StatusCode::UNAUTHORIZED);
        ctrl.skip_rest();
    }
}

pub fn generate_token(
    claims: Claims,
    secret_key: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.as_bytes()),
    )
}

pub fn get_claims(depot: &Depot) {
    depot.get::<&Claims>("claims").copied().unwrap();
}
