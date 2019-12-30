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

pub fn generate_bytes_for_length(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_aes_128_cbc_iv_test() {
        let iv = generate_aes_128_cbc_iv();

        assert_some_randomness(&iv);
        assert_eq!(iv.len(), 4);

        iv.iter()
            .for_each(|row| {
                assert_some_randomness(&row);
                assert_eq!(row.len(), 4);
            });
    }

    #[test]
    fn generate_aes_128_key_test() {
        let key = generate_aes_128_key();

        assert_some_randomness(&key);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn generate_bytes_for_length_test() {
        let length = 51;
        let bytes = generate_bytes_for_length(length);

        assert_some_randomness(&bytes);
        assert_eq!(bytes.len(), length as usize);
    }

    fn assert_some_randomness<T>(random_bytes: &Vec<T>) {
        assert!(!random_bytes.is_empty());
        // assert!(!random_bytes.is_sorted());
    }
}