use aes::{Key, Iv, BlockCipherMode, AESEncryptionOptions, Padding};
use aes;
use attack::CipherWithIvAndKey;
use aes::generate::generate_bytes_for_length;

pub fn cbc_bitflip<O>(
    oracle: O,
    key: &Key,
    iv: &Iv) -> Vec<u8>
    where O: Fn(&[u8]) -> Vec<u8> {
    let block_size = 16;

    let trigger = &vec![0x01; block_size];
    let sought_for = &[
        &[0xff][..],
        "admin".as_bytes(),
        &[0xff][..],
        "true".as_bytes(),
        &[0xff][..],
        &vec![0x01; 4][..]].concat();

    let result = oracle(&[&trigger[..], &sought_for[..]].concat());

    let mut xor_block = vec![];

    for byte in result[2 * block_size..2 * block_size + block_size].iter() {
        xor_block.push(*byte);
    }

    let letter_changes = vec![
        (0, ';'),
        (6, '='),
        (11, ';')
    ];
    for (pos, change) in letter_changes.iter() {
        for i in 0..=255 {
            let manipulated_byte = ((xor_block[*pos as usize] as u32 + i as u32) % 256u32) as u8;
            let current_cipher = [
                &result[..2 * block_size + *pos],
                &[manipulated_byte][..],
                &result[(2 * block_size) + *pos + 1..],
            ].concat();

            let text = aes::decrypt_aes_128(&current_cipher, key, &BlockCipherMode::CBC(iv));

            if text[3 * block_size + *pos] == *change as u8 {
                xor_block[*pos] = manipulated_byte;
                break;
            }
        }
    }


    [
        &result[..2 * block_size],
        &xor_block[..],
        &result[3 * block_size..],
    ].concat()
}

pub fn build_cbc_bitflip_oracle<'a>(
    key: &'a aes::Key,
    block_cipher_mode: &'a BlockCipherMode<'a>,
) -> impl Fn(&[u8]) -> Vec<u8> + 'a {
    move |crafted_input: &[u8]| -> Vec<u8> {
        let encoded_input = prepend_and_append(&crafted_input);

        aes::encrypt_aes_128(
            &encoded_input,
            &key,
            &AESEncryptionOptions::new(block_cipher_mode, &Padding::None),
        )
    }
}

pub fn cbc_padding_attack<O>(original_cipher: &[u8], padding_oracle: O) -> Vec<u8>
    where O: Fn(&[u8]) -> bool {
    let block_size = 16;
    let mut result = Vec::new();

    for i in 0usize..(original_cipher.len() as f32 / block_size as f32).floor() as usize - 1 {
        let penultimate_block = &original_cipher[(i * block_size)..(i * block_size) + block_size];
        let last_block = &original_cipher[(i * block_size) + block_size..(i * block_size) +
            (block_size * 2)];

        let mut block_result = Vec::new();
        let mut intermediate_block = Vec::new();

        let rand_bytes = &generate_bytes_for_length(block_size)[..];

        let mut found = false;
        for padding_length in 1u8..=16u8 {
            let xored_intermediate_block = &intermediate_block.iter()
                .map(|v| v ^ padding_length)
                .rev()
                .collect::<Vec<u8>>()[..];

            for padding_byte in 0u8..=255u8 {
                let modified_penultimate_block = &[
                    &rand_bytes[..block_size - padding_length as usize],
                    &[padding_byte][..],
                    &xored_intermediate_block[..]
                ].concat();

                assert_eq!(modified_penultimate_block.len(), block_size);

                let modified_cipher = &[
                    &modified_penultimate_block[..],
                    &last_block
                ].concat();

                let padding_is_valid = padding_oracle(&modified_cipher);
                if padding_is_valid {
                    intermediate_block.push(padding_byte ^ padding_length);
                    block_result.push(
                        penultimate_block[block_size - padding_length as usize] ^
                            *intermediate_block.last().unwrap());
                    break;
                }
            }
        }

        let mut ordered_block_result = &mut block_result.iter().cloned().rev().collect::<Vec<u8>>();
        result.append(ordered_block_result);
    }

    result
}

pub fn build_cbc_padding_oracle<'a>(key: &'a aes::Key, iv: &'a aes::Iv,
) -> impl Fn(&[u8]) -> bool + 'a {
    move |cipher: &[u8]| -> bool {
        let cipher_with_iv_and_key = CipherWithIvAndKey {
            cipher: cipher.to_vec(),
            key,
            iv,
        };

        check_cipher_padding(&cipher_with_iv_and_key)
    }
}

/// models the server's consumption of an encrypted session token, as if it was a cookie
pub fn check_cipher_padding(cipher_with_iv_and_key: &CipherWithIvAndKey) -> bool {
    let deciphered = aes::decrypt_aes_128(
        &cipher_with_iv_and_key.cipher,
        &cipher_with_iv_and_key.key,
        &BlockCipherMode::CBC(cipher_with_iv_and_key.iv),
    );

    let block_size = 16;

    match aes::validate_pkcs7_pad(&deciphered, block_size) {
        Err(PaddingError) => false,
        Ok(_) => {
            true
        }
    }
}

fn prepend_and_append(input: &[u8]) -> Vec<u8> {
    let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();

    let mut sanitized_input = Vec::with_capacity(input.len());

    for byte in input {
        if [b';', b'='].contains(byte) {
            sanitized_input.push(b'\\');
        }
        sanitized_input.push(*byte);
    }

    [&prefix[..], &sanitized_input[..], &suffix[..]].concat()
}