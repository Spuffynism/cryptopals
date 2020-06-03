extern crate hex;

pub fn hex_string_to_bytes(hex_input: &str) -> Vec<u8> {
    hex::decode(hex_input).unwrap()
}

pub fn hex_to_bytes(hex_input: &[u8]) -> Vec<u8> {
    hex_string_to_bytes(String::from_utf8(hex_input.to_vec()).unwrap().as_str())
}

#[cfg(test)]
mod tests {

    #[test]
    fn hex_string_to_bytes_test() {
        assert!(false);
    }

    #[test]
    fn hex_to_bytes_test() {
        assert!(false);
    }
}