use rand::RngCore;

pub fn generate_aes_128_cbc_iv() -> Vec<Vec<u8>> {
    vec![
        generate_bytes_for_length(4),
        generate_bytes_for_length(4),
        generate_bytes_for_length(4),
        generate_bytes_for_length(4)
    ]
}

pub fn generate_aes_128_key() -> Vec<u8> {
    generate_bytes_for_length(16)
}

pub fn generate_bytes_for_length(length: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; length as usize];
    rand::thread_rng().fill_bytes(&mut bytes);

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_aes_128_cbc_iv() {
        // TODO(nich): implement
    }

    #[test]
    fn generate_aes_128_key_test() {
        let key = generate_aes_128_key();

        assert!(!key.is_empty());
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn generate_bytes_for_length_test() {
        // TODO(nich): implement
    }
}