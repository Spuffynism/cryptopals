use ::vs;
use rand::{RngCore, Rng};
use aes;
use aes::BlockCipherMode;
use human;
use std::collections::HashSet;

pub fn generate_aes_key() -> Vec<u8> {
    generate_bytes_for_length(16)
}

fn generate_bytes_for_length(length: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; length as usize];
    rand::thread_rng().fill_bytes(&mut bytes);

    bytes
}

pub fn encrypt_under_random_key(content: &Vec<u8>) -> (Vec<u8>, BlockCipherMode) {
    let key = generate_aes_key();
    let prefix = generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));
    let suffix = generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));

    let padded_content: Vec<u8> = [prefix.clone(), content.clone(), suffix.clone()].concat();

    let mode = match rand::random() {
        true => aes::BlockCipherMode::ECB,
        false => {
            // TODO(nich): Generate random iv
            let iv = vec![vec![1u8; 4]; 4];
            aes::BlockCipherMode::CBC(iv)
        }
    };

    let cipher = aes::encrypt_aes_128(&padded_content, &key, &mode);

    (cipher, mode)
}

fn detect_block_cipher_mode(cipher: &Vec<u8>) -> BlockCipherMode {
    let chunks = cipher.chunks(16);
    let chunks_count = chunks.len();
    if chunks_count < 2 {
        panic!("Can't detect block cipher mode when cipher is less than 2 blocks long.");
    }

    let unique_chunks = &chunks.into_iter().collect::<HashSet<&[u8]>>();

    if chunks_count < unique_chunks.len() { BlockCipherMode::ECB } else { BlockCipherMode::CBC(vec![vec![0; 4]; 4]) }
}

/*pub fn byte_at_a_time_ecb_decryption(unknown_string: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    for char in human::ALPHABET.iter() {
        let block_size;

        for i in
    }

    vec![]
}*/

#[cfg(test)]
mod tests {
    use super::*;
    use aes;
    use file_util;
    use aes::BlockCipherMode;

    #[test]
    fn challenge9() {
        let message = vs!("YELLOW SUBMARINE");
        let expected_result = [message.as_slice(), &[0x04, 0x04, 0x04, 0x04]].concat();

        let actual_result = aes::pkcs7_pad(&message, 20);

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn challenge9_no_padding_needed() {
        let message = vs!("YELLOW SUBMARINE");
        let expected_result = message.as_slice();

        let actual_result = aes::pkcs7_pad(&message, 16);

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn challenge10() {
        let cbc_cipher = file_util::read_base64_file_bytes("./resources/10.txt");
        let key = vs!("YELLOW SUBMARINE");
        let iv = vec![vec![0x00; 4]; 4];
        let mode = BlockCipherMode::CBC(iv);

        let deciphered = aes::decrypt_aes_128(&cbc_cipher, &key, &mode);

        assert!(deciphered.starts_with(&vs!("I'm back and I'm ringin' the bell")));
    }

    #[test]
    fn generate_aes_key_test() {
        let key = generate_aes_key();

        assert!(!key.is_empty());
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn challenge11() {
        let input = vec![0u8; 16 * 8];
        let (cipher, expected_mode) = &encrypt_under_random_key(&input);

        let found_mode = &detect_block_cipher_mode(&cipher);

        assert_eq!(std::mem::discriminant(found_mode), std::mem::discriminant(expected_mode))
    }

    #[test]
    fn challenge12() {
        let unknown_string = file_util::read_base64_file_bytes("./resources/12.txt");
        //byte_at_a_time_ecb_decryption(&unknown_string, &generate_aes_key());
    }
}
