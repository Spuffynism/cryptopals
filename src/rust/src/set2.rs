use ::vs;
use rand::Rng;
use aes;
use aes::BlockCipherMode;
use std::collections::HashMap;

pub fn encrypt_under_random_key(content: &Vec<u8>) -> (Vec<u8>, BlockCipherMode) {
    let key = aes::generate::generate_aes_128_key();
    let prefix = aes::generate::generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));
    let suffix = aes::generate::generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));

    let padded_content: Vec<u8> = [prefix.clone(), content.clone(), suffix.clone()].concat();

    let mode = match rand::random() {
        true => aes::BlockCipherMode::ECB,
        false => {
            let iv = aes::generate::generate_aes_128_cbc_iv();
            aes::BlockCipherMode::CBC(iv)
        }
    };

    let cipher = aes::encrypt_aes_128(&padded_content, &key, &mode);

    (cipher, mode)
}

fn prepend_and_append(input: &Vec<u8>) -> Vec<u8> {
    let prefix = vs!("comment1=cooking%20MCs;userdata=");
    let suffix = vs!(";comment2=%20like%20a%20pound%20of%20bacon");

    let mut sanitized_input = Vec::with_capacity(input.len());

    for byte in input {
        if [';' as u8, '=' as u8].contains(byte) {
            sanitized_input.push('\\' as u8);
        }
        sanitized_input.push(*byte);
    }

    [&prefix[..], &sanitized_input[..], &suffix[..]].concat()
}

fn cbc_encrypt_under_key(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    aes::encrypt_aes_128(&input, &key, &BlockCipherMode::CBC(vec![vec![1u8; 4]; 4]))
}

fn cbc_decrypt_under_key(cipher: &Vec<u8>, key: &Vec<u8>, iv: &Vec<Vec<u8>>) -> bool {
    let text = aes::decrypt_aes_128(&cipher, &key, &BlockCipherMode::CBC(iv.to_vec()));

    //let map = encoded_message_to_map(&text);

    false
}

/*fn encoded_message_to_map(message: &Vec<u8>) -> HashMap<String, String> {
    let key_values: Vec<(&str, &str)> = message.split(";")
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
}*/

#[cfg(test)]
mod tests {
    use super::*;
    use ::aes;
    use file_util;
    use aes::BlockCipherMode;
    use aes::attack::ecb_cut_and_paste;

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
    fn challenge11() {
        for _i in 0..100 {
            let repeated_bytes = aes::generate::generate_bytes_for_length(16);
            let mut input = Vec::with_capacity(16 * 8);
            for j in 0..(16 * 8) {
                // the input repeats the repeated bytes, in order
                // (i.e.: 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 , ...)
                input.push(repeated_bytes[(j % repeated_bytes.len()) as usize]);
            }
            let (cipher, expected_mode) = &encrypt_under_random_key(&input);

            let found_mode = &aes::attack::detect_block_cipher_mode(&cipher);

            assert_eq!(std::mem::discriminant(found_mode), std::mem::discriminant(expected_mode))
        }
    }

    #[test]
    #[ignore] // takes up to 2 minutes to run.
    fn challenge12() {
        let unknown_string = file_util::read_base64_file_bytes("./resources/12.txt");
        let key = aes::generate::generate_aes_128_key();
        let oracle = aes::attack::build_byte_at_a_time_simple_oracle(&unknown_string, &key);
        let deciphered = aes::attack::byte_at_a_time_ecb_simple_decryption(oracle, 0, &vec![]);

        assert!(deciphered.starts_with(&vs!("Rollin' in my 5.0\nWith")));
        assert!(deciphered.ends_with(&vs!("No, I just drove by\n")));
    }

    #[test]
    fn challenge13() {
        let key = aes::generate::generate_aes_128_key();

        let cipher = ecb_cut_and_paste(&key);
        let decrypted_encoded_profile = aes::decrypt_aes_128(&cipher, &key,
                                                             &BlockCipherMode::ECB);

        let result = String::from_utf8(decrypted_encoded_profile).unwrap();
        assert!(result.contains("uid=10&role=admin"));
    }

    #[test]
    #[ignore] // takes up to 2 minutes to run.
    fn challenge14() {
        let random_prefix = aes::generate::generate_bytes_for_length(rand::thread_rng().gen_range
        (5, 64));
        let unknown_string = file_util::read_base64_file_bytes("./resources/12.txt");
        let key = aes::generate::generate_aes_128_key();
        let oracle = aes::attack::build_byte_at_a_time_harder_oracle(
            &random_prefix,
            &unknown_string,
            &key,
        );
        let deciphered = aes::attack::byte_at_a_time_ecb_harder_decryption(oracle);

        assert!(deciphered.starts_with(&vs!("Rollin' in my 5.0\nWith")));
        assert!(deciphered.ends_with(&vs!("No, I just drove by\n")));
    }

    #[test]
    fn challenge15_valid_case() {
        let valid_case = &[&vs!("ICE ICE BABY")[..], &vec![0x04; 4][..]].concat();

        let result = std::panic::catch_unwind(|| aes::validate_pkcs7_pad(valid_case));
        assert!(result.is_ok())
    }

    #[test]
    fn challenge15_no_padding() {
        let valid_case = vs!("ICE ICE BABY!!!!");

        let result = std::panic::catch_unwind(|| aes::validate_pkcs7_pad(&valid_case));
        assert!(result.is_ok())
    }

    #[test]
    #[should_panic]
    fn challenge15_too_short_padding_compared_to_padding_byte() {
        let invalid_padding_length = [&vs!("ICE ICE BABY")[..], &vec![0x05; 4][..]].concat();

        aes::validate_pkcs7_pad(&invalid_padding_length);
    }

    #[test]
    #[should_panic]
    fn challenge15_too_long_padding_compared_to_padding_byte() {
        let too_long_padding = [&vs!("ICE ICE BABY")[..], &vec![0x04; 5][..]].concat();

        aes::validate_pkcs7_pad(&too_long_padding);
    }

    #[test]
    #[should_panic]
    fn challenge15_invalid_bytes() {
        let invalid_bytes = [&vs!("ICE ICE BABY")[..], &vec![0x01, 0x02, 0x03, 0x04][..]].concat();

        aes::validate_pkcs7_pad(&invalid_bytes);
    }

    #[test]
    fn challenge16() {
        let key = aes::generate::generate_aes_128_key();

        let result = prepend_and_append(&vs!("userdata=;;"));
    }
}
