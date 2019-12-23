use ::vs;
use rand::{RngCore, Rng, random};
use aes;

// TODO(nich): Move to pkcs7 mod
pub fn pkcs7_pad(bytes: &Vec<u8>, to_length: u8) -> Vec<u8> {
    assert!(bytes.len() < to_length as usize);
    let mut padded = vec![0; to_length as usize];
    let pad = to_length - bytes.len() as u8;

    // copy initial bytes
    for (i, byte) in bytes.iter().enumerate() {
        padded[i] = *byte;
    }

    // pad remaining bytes with length of pad.
    for i in bytes.len()..to_length as usize {
        padded[i] = pad;
    }

    padded
}

pub fn generate_aes_key() -> Vec<u8> {
    generate_bytes_for_length(16)
}

fn generate_bytes_for_length(length: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; length as usize];
    rand::thread_rng().fill_bytes(&mut bytes);

    bytes
}

pub fn encrypt_under_random_key(content: Vec<u8>) -> Vec<u8> {
    let key = generate_aes_key();
    let prefix = generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));
    let suffix = generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));

    let padded_content = [prefix, content, suffix].concat();

    let mut mode = match rand::random() {
        true => aes::BlockCipherMode::ECB,
        false => {
            let iv = vec![vec![0; 4]; 4];
            aes::BlockCipherMode::CBC(iv)
        }
    };

    aes::encrypt_aes_128(&padded_content, &key, &mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes;
    use file_util;
    use aes::BlockCipherMode;

    #[test]
    fn challenge9() {
        let message = vs!("YELLOW SUBMARINE");
        let desired_length = 20u8;
        let expected_result = [message.as_slice(), &[0x04, 0x04, 0x04, 0x04]].concat();

        let actual_result = pkcs7_pad(&message, 20);

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn challenge10() {
        let cbc_cipher = file_util::read_base64_file_bytes("./resources/10.txt");
        let key = vs!("YELLOW SUBMARINE");
        let iv = vec![vec![0x00; 4]; 4];
        let mode = BlockCipherMode::CBC(iv);

        let expected_content = file_util::read_file_bytes("./test_resources/expected_lyrics.txt");

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
    fn challenge11() {}
}
