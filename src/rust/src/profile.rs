pub fn profile_for(email: &String) -> String {
    let blacklist = ['&', '='];

    for character in email.chars() {
        if blacklist.contains(&character) {
            panic!(format!("Illegal character '{}'.", character))
        }
    }

    format!("email={}&uid={}&role={}", email, 10, "user")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_for_test() {
        let email = "foo@bar.com".to_string();
        let expected = "email=foo@bar.com&uid=10&role=user".to_string();
        let actual = profile_for(&email);

        assert_eq!(actual, expected);
    }
}