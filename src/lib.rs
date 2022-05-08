

mod jwt;

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use crate::jwt::structs::JwtRequest;
    use crate::jwt::structs::Audience;
    #[test]
    fn test_jwt_constructor() {
        let jwt_struct = JwtRequest::new(
            "1234567890abc".to_owned(),
            Audience::Prod,
            "test@test.com".to_owned()
        );
        assert_eq!(jwt_struct.iss, "1234567890abc".to_owned());
        assert_eq!(jwt_struct.aud, Audience::Prod);
        assert_eq!(jwt_struct.sub, "test@test.com".to_owned());
        assert_eq!(jwt_struct.exp.parse::<u64>().unwrap(), SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .checked_add(120000)
            .unwrap());
        let jwt_struct = JwtRequest::new(
            "1234567890abc".to_owned(),
            Audience::Sandbox,
            "test@test.com".to_owned()
        );
        assert_eq!(jwt_struct.iss, "1234567890abc".to_owned());
        assert_eq!(jwt_struct.aud, Audience::Sandbox);
        assert_eq!(jwt_struct.sub, "test@test.com".to_owned());
        assert_eq!(jwt_struct.exp.parse::<u64>().unwrap(), SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .checked_add(120000)
            .unwrap());
        let jwt_struct = JwtRequest::new(
            "1234567890abc".to_owned(),
            Audience::ExperienceCloud,
            "test@test.com".to_owned()
        );
        assert_eq!(jwt_struct.iss, "1234567890abc".to_owned());
        assert_eq!(jwt_struct.aud, Audience::ExperienceCloud);
        assert_eq!(jwt_struct.sub, "test@test.com".to_owned());
        assert_eq!(jwt_struct.exp.parse::<u64>().unwrap(), SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .checked_add(120000)
            .unwrap());
    }
}
