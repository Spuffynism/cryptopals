use aes;
use rand::Rng;
use aes::{BlockCipherMode, AESEncryptionOptions, Padding};
use aes::attack::CipherWithIvAndKey;

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
    use file_util;
    use human::calculate_human_resemblance_score;
    use aes::remove_pkcs7_padding;

    #[test]
    fn challenge17_base_case() {
        let lines = file_util::read_file_lines("./resources/17.txt");
        let key = aes::generate::generate_aes_128_key();
        let iv = aes::generate::generate_aes_128_cbc_iv();
        let cipher_with_iv_and_key = generate_cbc_padding_oracle_cipher(&lines, &key, &iv);
        let padding_is_ok = aes::attack::check_cipher_padding(&cipher_with_iv_and_key);

        assert!(padding_is_ok);
    }

    #[test]
    fn challenge17_do_attack() {
        let lines = file_util::read_file_lines("./resources/17.txt");
        let key = aes::generate::generate_aes_128_key();
        let iv = aes::generate::generate_aes_128_cbc_iv();
        let cipher_with_iv_and_key = generate_cbc_padding_oracle_cipher(&lines, &key, &iv);
        let oracle = aes::attack::build_cbc_padding_oracle(
            &cipher_with_iv_and_key.key,
            &cipher_with_iv_and_key.iv,
        );

        let deciphered = aes::attack::cbc_padding_attack(&cipher_with_iv_and_key.cipher, oracle);
        let deciphered_without_padding = remove_pkcs7_padding(&deciphered);

        assert_eq!(calculate_human_resemblance_score(&deciphered_without_padding), 1f32);
    }
}