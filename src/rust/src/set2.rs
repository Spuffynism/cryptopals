use ::vs;

// TODO(nich): Move to pkcs7 mod
fn pkcs7_pad(bytes: &Vec<u8>, to_length: u8) -> Vec<u8> {
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

fn cbc_encrypt(bytes: Vec<u8>, iv_byte: u8) {
    let iv = vec![iv_byte; 16];
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
}
