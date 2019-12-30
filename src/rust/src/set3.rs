use ::vs;
use aes;
use rand::Rng;
use aes::{BlockCipherMode, validate_pkcs7_pad};

pub struct CipherWithIvAndKey {
    cipher: Vec<u8>,
    iv: Vec<Vec<u8>>,
    key: Vec<u8>,
}

pub fn generate_cbc_padding_oracle_cipher<'a>(lines: &'a Vec<Vec<u8>>, key: &'a Vec<u8>) ->
CipherWithIvAndKey {
    let selected_line = &lines[rand::thread_rng().gen_range(0, lines.len())];
    let iv = &aes::generate::generate_aes_128_cbc_iv();
    let cipher = &aes::encrypt_aes_128(&selected_line, &key, &BlockCipherMode::CBC(iv.to_vec()));

    CipherWithIvAndKey {
        cipher: cipher.to_vec(),
        iv: iv.to_vec(),
        key: key.to_vec(),
    }
}

/// models the server's consumption of an encrypted session token, as if it was a cookie
pub fn check_cipher_padding(cipher_with_iv_and_key: &CipherWithIvAndKey) -> bool {
    let deciphered = aes::decrypt_aes_128(
        &cipher_with_iv_and_key.cipher,
        &cipher_with_iv_and_key.key,
        &BlockCipherMode::CBC(cipher_with_iv_and_key.iv.to_vec()),
    );

    validate_pkcs7_pad(&deciphered).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use file_util;
    use aes::generate::generate_aes_128_key;

    #[test]
    fn challenge17() {
        let lines = file_util::read_base64_file_lines("./resources/17.txt");

        let key = aes::generate::generate_aes_128_key();


        dbg!(lines);
    }
}