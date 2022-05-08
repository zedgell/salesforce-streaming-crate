mod jwt;

#[cfg(test)]
mod tests {
    use crate::jwt::structs::Audience;
    use crate::jwt::structs::JwtRequest;
    use httpmock::prelude::*;
    use serde_json::json;
    use std::time::SystemTime;

    #[test]
    fn test_jwt_constructor() {
        let jwt_struct = JwtRequest::new(
            "1234567890abc".to_owned(),
            Audience::Prod,
            "test@test.com".to_owned(),
        );
        assert_eq!(jwt_struct.iss, "1234567890abc".to_owned());
        assert_eq!(jwt_struct.aud, "https://login.salesforce.com".to_owned());
        assert_eq!(jwt_struct.sub, "test@test.com".to_owned());
        assert_eq!(
            jwt_struct.exp,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .checked_add(120000)
                .unwrap() as usize
        );
        let jwt_struct = JwtRequest::new(
            "1234567890abc".to_owned(),
            Audience::Sandbox,
            "test@test.com".to_owned(),
        );
        assert_eq!(jwt_struct.iss, "1234567890abc".to_owned());
        assert_eq!(jwt_struct.aud, "https://test.salesforce.com".to_owned());
        assert_eq!(jwt_struct.sub, "test@test.com".to_owned());
        assert_eq!(
            jwt_struct.exp,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .checked_add(120000)
                .unwrap() as usize
        );
        let jwt_struct = JwtRequest::new(
            "1234567890abc".to_owned(),
            Audience::ExperienceCloud("https://someurl.com".to_owned()),
            "test@test.com".to_owned(),
        );
        assert_eq!(jwt_struct.iss, "1234567890abc".to_owned());
        assert_eq!(jwt_struct.aud, "https://someurl.com".to_owned());
        assert_eq!(jwt_struct.sub, "test@test.com".to_owned());
        assert_eq!(
            jwt_struct.exp,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .checked_add(120000)
                .unwrap() as usize
        );
    }

    #[test]
    fn test_send_jwt_200() {
        let server = MockServer::start();
        let salesforce_mock = server.mock(|when, then| {
            when.method(POST).path("/success/services/oauth2/token");
            then.status(200).body(
                json!({
                    "access_token":"00Dxx0000001gPL!AR8AQJXg5oj8jXSgxJfA0lBog.39AsX.LVpxezPwuX5VAIrrbbHMuol7GQxnMeYMN7cj8EoWr78nt1u44zU31IbYNNJguseu",
                    "scope":"web openid api id",
                    "instance_url":"https://yourInstance.salesforce.com",
                    "id":"https://yourInstance.salesforce.com/id/00Dxx0000001gPLEAY/005xx000001SwiUAAS",
                    "token_type":"Bearer"}
                ).to_string()
            );
        });

        let jwt_struct = JwtRequest::new(
            "1234567890abc".to_owned(),
            Audience::ExperienceCloud("https://someurl.com".to_owned()),
            "test@test.com".to_owned(),
        );
        let jwt_response = jwt_struct.send(
            include_bytes!("../private-key.pem"),
            format!("http://127.0.0.1:{}/success", server.port()),
        );
        salesforce_mock.assert();
        assert_eq!(jwt_response.is_ok(), true);
        let jwt_response = jwt_response.unwrap();
        assert_eq!(jwt_response.access_token,
                   "00Dxx0000001gPL!AR8AQJXg5oj8jXSgxJfA0lBog.39AsX.LVpxezPwuX5VAIrrbbHMuol7GQxnMeYMN7cj8EoWr78nt1u44zU31IbYNNJguseu"
                       .to_owned());
        assert_eq!(jwt_response.scope, "web openid api id".to_owned());
        assert_eq!(
            jwt_response.instance_url,
            "https://yourInstance.salesforce.com".to_owned()
        );
        assert_eq!(
            jwt_response.id,
            "https://yourInstance.salesforce.com/id/00Dxx0000001gPLEAY/005xx000001SwiUAAS"
                .to_owned()
        );
        assert_eq!(jwt_response.token_type, "Bearer".to_owned())
    }
}
