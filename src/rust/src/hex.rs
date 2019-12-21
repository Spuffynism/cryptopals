extern crate hex;

pub fn hex_string_to_bytes(hex_input: &str) -> Vec<u8> {
    hex::decode(hex_input).unwrap()
}

pub fn hex_to_bytes(hex_input: &Vec<u8>) -> Vec<u8> {
    hex_string_to_bytes(String::from_utf8(hex_input.as_slice().to_vec()).unwrap().as_str())
}