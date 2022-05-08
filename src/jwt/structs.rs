use jsonwebtoken::Algorithm::RS256;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(PartialEq, Debug)]
pub enum Audience {
    Sandbox,
    Prod,
    ExperienceCloud(String),
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct JwtRequest {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: usize,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct JwtResponse {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
    pub instance_url: String,
    pub id: String,
    pub sfdc_site_url: Option<String>,
    pub sfdc_site_id: Option<String>,
}

impl JwtRequest {
    pub fn new(client_id: String, audience: Audience, username: String) -> Self {
        JwtRequest {
            iss: client_id,
            aud: match audience {
                Audience::Sandbox => "https://test.salesforce.com".to_owned(),
                Audience::Prod => "https://login.salesforce.com".to_owned(),
                Audience::ExperienceCloud(value) => value,
            },
            sub: username,
            exp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .checked_add(120000)
                .unwrap() as usize,
        }
    }

    pub fn send(self, key: &[u8], instance_url: String) -> Result<JwtResponse, String> {
        let jwt = encode(
            &Header::new(RS256),
            &self,
            &EncodingKey::from_rsa_pem(key).unwrap(),
        )
        .unwrap();
        let client = reqwest::blocking::Client::new();
        let response = client
            .post(format!("{}/services/oauth2/token", instance_url))
            .body(jwt)
            .send()
            .unwrap();
        match response.status() {
            StatusCode::OK => {
                Ok(serde_json::from_str::<JwtResponse>(response.text().unwrap().as_str()).unwrap())
            }
            _ => Err(format!(
                "received a {} response with a body of {}",
                response.status().as_u16(),
                response.text().unwrap()
            )),
        }
    }
}
