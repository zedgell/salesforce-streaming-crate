use std::time::SystemTime;

#[derive(PartialEq, Debug)]
pub enum Audience {
    Sandbox,
    Prod,
    ExperienceCloud,
}

#[derive(PartialEq)]
pub struct JwtRequest {
    pub iss: String,
    pub aud: Audience,
    pub sub: String,
    pub exp: String,
}

impl JwtRequest {
    pub fn new(client_id: String, audience: Audience, username: String) -> Self {
        JwtRequest {
            iss: client_id,
            aud: audience,
            sub: username,
            exp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .checked_add(120000)
                .unwrap()
                .to_string(),
        }
    }
}
