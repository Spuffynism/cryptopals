use aes;
use rand::Rng;
use aes::{BlockCipherMode, AESEncryptionOptions, Padding};
use attack::CipherWithIvAndKey;

pub fn generate_cbc_padding_oracle_cipher<'a>(
    lines: &'a Vec<Vec<u8>>,
    key: &'a aes::Key,
    iv: &'a aes::Iv) ->
    CipherWithIvAndKey<'a> {
    let selected_line = &lines[rand::thread_rng().gen_range(0, lines.len())];

    let cipher = &aes::encrypt_aes_128(
        &selected_line,
        key,
        &AESEncryptionOptions::new(&BlockCipherMode::CBC(&iv), &Padding::PKCS7),
    );

    CipherWithIvAndKey { cipher: cipher.to_vec(), iv, key }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::{file, attack};
    use human::calculate_human_resemblance_score;
    use aes::{remove_pkcs7_padding, decrypt_aes_128, encrypt_aes_128, Key};
    use aes::generate::{generate_bytes_for_length, generate_aes_128_key};
    use std::convert::TryInto;
    use attack::ctr::break_fixed_nonce_ctr_mode_using_substitutions;

    #[test]
    fn challenge17_base_case() {
        let lines = file::read_file_lines("./resources/17.txt");
        let key = aes::generate::generate_aes_128_key();
        let iv = aes::generate::generate_aes_128_cbc_iv();
        let cipher_with_iv_and_key = generate_cbc_padding_oracle_cipher(&lines, &key, &iv);
        let padding_is_ok = attack::cbc::check_cipher_padding(&cipher_with_iv_and_key);

        assert!(padding_is_ok);
    }

    #[test]
    fn challenge17_do_attack() {
        let lines = file::read_file_lines("./resources/17.txt");
        let key = aes::generate::generate_aes_128_key();
        let iv = aes::generate::generate_aes_128_cbc_iv();
        let cipher_with_iv_and_key = generate_cbc_padding_oracle_cipher(&lines, &key, &iv);
        let oracle = attack::cbc::build_cbc_padding_oracle(
            &cipher_with_iv_and_key.key,
            &cipher_with_iv_and_key.iv,
        );

        let deciphered = attack::cbc::cbc_padding_attack(&cipher_with_iv_and_key.cipher, oracle);
        let deciphered_without_padding = remove_pkcs7_padding(&deciphered);

        assert_eq!(calculate_human_resemblance_score(&deciphered_without_padding), 1f32);
    }

    #[test]
    fn challenge18_implement_ctr_mode() {
        let input = base64::decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
        ).unwrap();
        let key = Key::new_from_string("YELLOW SUBMARINE");
        let mode = BlockCipherMode::CTR(&[0u8; 8]);

        let deciphered = encrypt_aes_128(&input, &key, &AESEncryptionOptions::new(&mode, &Padding::None));

        assert_eq!(calculate_human_resemblance_score(&deciphered), 1f32);
    }

    #[test]
    fn challenge19_break_fixed_nonce_ctr_mode_using_substitutions() {
        let lines = file::read_base64_file_lines("./resources/19.txt");

        let nonce = &[0u8; 8];
        let key = generate_aes_128_key();
        let mode = BlockCipherMode::CTR(nonce);
        let options = AESEncryptionOptions::new(&mode, &Padding::None);

        let mut ciphers = lines.iter()
            .map(|line| encrypt_aes_128(&line, &key, &options))
            .collect();

        let deciphered = break_fixed_nonce_ctr_mode_using_substitutions(&ciphers);

        deciphered.iter()
            .for_each(|line| {
                assert!(calculate_human_resemblance_score(line) > 0.95f32)
            });
    }

    #[test]
    fn challenge20_break_fixed_nonce_ctr_mode_statistically() {
        let lines = file::read_base64_file_lines("./resources/20.txt");

        let nonce = &[0u8; 8];
        let key = generate_aes_128_key();
        let mode = BlockCipherMode::CTR(nonce);
        let options = AESEncryptionOptions::new(&mode, &Padding::None);

        let mut ciphers = lines.iter()
            .map(|line| encrypt_aes_128(&line, &key, &options))
            .collect();

        // TODO(nich): Break multiple repeating-key xor
    }
}