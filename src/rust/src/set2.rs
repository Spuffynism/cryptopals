use rand::Rng;
use aes;
use aes::{BlockCipherMode, AESEncryptionOptions, Padding};

pub fn encrypt_under_random_key<'a>(content: &[u8], iv: &'a aes::Iv) -> (Vec<u8>,
                                                                         BlockCipherMode<'a>) {
    let key = aes::generate::generate_aes_128_key();
    let prefix = aes::generate::generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));
    let suffix = aes::generate::generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));

    let padded_content = [&prefix[..], &content[..], &suffix[..]].concat();

    let block_cipher_mode = match rand::random() {
        true => aes::BlockCipherMode::ECB,
        false => {
            aes::BlockCipherMode::CBC(iv)
        }
    };

    let cipher = aes::encrypt_aes_128(
        &padded_content,
        &key,
        &AESEncryptionOptions::new(&block_cipher_mode, &Padding::PKCS7),
    );

    (cipher, block_cipher_mode)
}

pub fn is_admin(cipher: &[u8], key: &aes::Key, iv: &aes::Iv) -> bool {
    let text = aes::decrypt_aes_128(&cipher, &key, &BlockCipherMode::CBC(iv));
    let as_string = String::from_utf8_lossy(&text);

    as_string.contains(";admin=true;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::aes;
    use file;
    use aes::BlockCipherMode;
    use aes::PaddingError::{PaddingNotConsistent, InvalidLastPaddingByte};

    #[test]
    fn challenge9_some_padding() {
        let message = "YELLOW SUBMARINE".as_bytes();
        let expected_result = [&message[..], &[0x04u8; 4][..]].concat();

        let actual_result = aes::pkcs7_pad(&message, 20);

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn challenge9_full_block_padding_needed() {
        let block_size = 16u8;
        let message = "YELLOW SUBMARINE".as_bytes();
        let expected_result = &[
            &message[..],
            &vec![block_size; block_size as usize][..]
        ].concat();

        let actual_result = &aes::pkcs7_pad(&message, block_size);

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn challenge10() {
        let cbc_cipher = &file::read_base64_file_bytes("./resources/10.txt");
        let key = &aes::Key::new_from_string("YELLOW SUBMARINE");
        let iv = &aes::Iv::empty();
        let mode = &BlockCipherMode::CBC(iv);

        let deciphered = aes::decrypt_aes_128(cbc_cipher, key, mode);

        assert!(deciphered.starts_with("I'm back and I'm ringin' the bell".as_bytes()));
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
            let iv = &aes::generate::generate_aes_128_cbc_iv();
            let (cipher, expected_mode) = encrypt_under_random_key(&input, iv);

            let iv = &aes::Iv::empty();
            let found_mode = aes::attack::detect_block_cipher_mode(&cipher, iv);

            assert_eq!(std::mem::discriminant(&found_mode), std::mem::discriminant(&expected_mode))
        }
    }

    #[test]
    #[ignore] // takes up to 2 minutes to run.
    fn challenge12() {
        let unknown_string = file::read_base64_file_bytes("./resources/12.txt");
        let key = aes::generate::generate_aes_128_key();
        let oracle = aes::attack::build_byte_at_a_time_simple_oracle(&unknown_string, &key);
        let deciphered = aes::attack::byte_at_a_time_ecb_simple_decryption(oracle, 0, &vec![]);

        assert!(deciphered.starts_with("Rollin' in my 5.0\nWith".as_bytes()));
        assert!(deciphered.ends_with("No, I just drove by\n".as_bytes()));
    }

    #[test]
    fn challenge13() {
        let key = aes::generate::generate_aes_128_key();

        let cipher = aes::attack::ecb_cut_and_paste(&key);
        let decrypted_encoded_profile = aes::decrypt_aes_128(&cipher, &key,
                                                             &BlockCipherMode::ECB);

        // it is normal that the encoded profile is not a properly encoded utf-8 string
        let result = String::from_utf8_lossy(&decrypted_encoded_profile);
        assert!(result.contains("uid=10&role=admin"));
    }

    #[test]
    #[ignore] // takes up to 2 minutes to run.
    fn challenge14() {
        let random_prefix = aes::generate::generate_bytes_for_length(rand::thread_rng().gen_range
        (5, 64));
        let unknown_string = file::read_base64_file_bytes("./resources/12.txt");
        let key = aes::generate::generate_aes_128_key();
        let oracle = aes::attack::build_byte_at_a_time_harder_oracle(
            &random_prefix,
            &unknown_string,
            &key,
        );
        let deciphered = aes::attack::byte_at_a_time_ecb_harder_decryption(oracle);

        assert!(deciphered.starts_with("Rollin' in my 5.0\nWith".as_bytes()));
        assert!(deciphered.ends_with("No, I just drove by\n".as_bytes()));
    }

    #[test]
    fn challenge15_valid_case() {
        let block_size = 16;
        let valid_case = &["ICE ICE BABY".as_bytes(), &vec![0x04; 4][..]].concat();

        let result = aes::validate_pkcs7_pad(valid_case, block_size);
        assert!(result.is_ok())
    }

    #[test]
    fn challenge15_zero_padding_length() {
        let block_size = 16;
        let invalid_padding_length = ["ICE ICE BABY!!!".as_bytes(), &vec![0x00][..]].concat();

        assert_eq!(
            aes::validate_pkcs7_pad(&invalid_padding_length, block_size),
            Err(InvalidLastPaddingByte)
        );
    }

    #[test]
    fn challenge15_padding_length_bigger_than_block_size() {
        let block_size = 16;
        let invalid_padding_length = [
            "ICE ICE BABY!!!".as_bytes(),
            &[block_size + 1][..]
        ].concat();

        assert_eq!(
            aes::validate_pkcs7_pad(&invalid_padding_length, block_size),
            Err(InvalidLastPaddingByte)
        );
    }

    #[test]
    fn challenge15_padding_length_bigger_than_bytes() {
        let block_size = 16;
        let invalid_padding_length = ["ICE ICE BABY!!!".as_bytes(), &vec![0xff][..]].concat();

        assert_eq!(
            aes::validate_pkcs7_pad(&invalid_padding_length, block_size),
            Err(InvalidLastPaddingByte)
        );
    }

    #[test]
    fn challenge15_inconsistent_padding() {
        let block_size = 16;
        let invalid_padding_length = ["ICE ICE BABY".as_bytes(), &vec![0x01, 0x02, 0x03, 0x04][..]]
            .concat();

        assert_eq!(
            aes::validate_pkcs7_pad(&invalid_padding_length, block_size),
            Err(PaddingNotConsistent)
        );
    }

    #[test]
    fn challenge16() {
        let key = &aes::generate::generate_aes_128_key();
        let iv = &aes::generate::generate_aes_128_cbc_iv();
        let mode = &BlockCipherMode::CBC(iv);
        let oracle = aes::attack::build_cbc_bitflip_oracle(key, mode);

        let cipher = aes::attack::cbc_bitflip(&oracle, key, iv);
        let is_admin = is_admin(&cipher, key, iv);

        assert!(is_admin);
    }
}
