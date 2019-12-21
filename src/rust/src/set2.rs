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

    #[test]
    fn challenge9() {
        let message = vs!("YELLOW SUBMARINE");
        let desired_length = 20u8;
        let expected_result = [message.as_slice(), &[0x04, 0x04, 0x04, 0x04]].concat();

        let actual_result = pkcs7_pad(&message, 20);

        assert_eq!(actual_result, expected_result);
    }

    fn challenge10() {
        let key = vs!("YELLOW SUBMARINE");
        let iv = 0u8;
    }
}
