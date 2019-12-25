use std::collections::HashMap;

pub fn encoded_profile_to_map(encoded_profile: &String) -> HashMap<String, String> {
    let key_values: Vec<(&str, &str)> = encoded_profile.split("&")
        .collect::<Vec<&str>>()
        .iter()
        .map(|entry| {
            let key_and_value = entry.split("=").collect::<Vec<&str>>();

            (key_and_value[0], key_and_value[1])
        }).collect();

    let mut map = HashMap::new();
    for (key, value) in key_values.iter() {
        map.insert(key.to_string(), value.to_string());
    }

    map
}

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