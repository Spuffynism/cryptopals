use aes;
use rand::Rng;
use aes::{BlockCipherMode, AESEncryptionOptions, Padding};
use aes::attack::CipherWithIvAndKey;

pub fn generate_cbc_padding_oracle_cipher<'a>(lines: &'a Vec<Vec<u8>>, key: &'a Vec<u8>) ->
CipherWithIvAndKey {
    let selected_line = &lines[rand::thread_rng().gen_range(0, lines.len())];
    let iv = &aes::generate::generate_aes_128_cbc_iv();
    let cipher = &aes::encrypt_aes_128(
        &selected_line,
        &key,
        &AESEncryptionOptions::new(&BlockCipherMode::CBC(iv.to_vec()), &Padding::PKCS7),
    );

    CipherWithIvAndKey {
        cipher: cipher.to_vec(),
        iv: iv.to_vec(),
        key: key.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use file_util;

    #[test]
    fn challenge17_base_case() {
        let lines = file_util::read_file_lines("./resources/17.txt");
        let key = aes::generate::generate_aes_128_key();
        let cipher_with_iv_and_key = generate_cbc_padding_oracle_cipher(&lines, &key);
        let padding_is_ok = aes::attack::check_cipher_padding(&cipher_with_iv_and_key);

        assert!(padding_is_ok);
    }

    #[test]
    fn challenge17_do_attack() {
        let lines = file_util::read_file_lines("./resources/17.txt");
        let key = aes::generate::generate_aes_128_key();
        let cipher_with_iv_and_key = generate_cbc_padding_oracle_cipher(&lines, &key);
        //let mode = BlockCipherMode::CBC(cipher_with_iv_and_key.iv.to_vec());
        let oracle = aes::attack::build_cbc_padding_oracle(
            &cipher_with_iv_and_key.key,
            &cipher_with_iv_and_key.iv,
        );

        let deciphered = aes::attack::cbc_padding_attack(&cipher_with_iv_and_key.cipher, oracle);

        dbg!(deciphered);
    }
}