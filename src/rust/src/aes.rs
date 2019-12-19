pub fn decrypt_in_ecb_mode(cipher: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut deciphered = Vec::with_capacity(cipher.len());

    for (i, cipher_byte) in cipher.iter().enumerate() {
        deciphered.push(cipher_byte ^ key[i % key.len()]);
    }

    return deciphered;
}