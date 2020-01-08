use aes::{BlockCipherMode, AESEncryptionOptions, Padding, Key, Iv, PaddingError};
use std::collections::{HashSet, HashMap, VecDeque};
use std::ops::Range;
use ::{human, aes};
use profile::profile_for;

/// Detectes the block cipher mode of a cipher.
pub fn detect_block_cipher_mode<'a>(cipher: &[u8], iv: &'a Iv) -> BlockCipherMode<'a> {
    let chunks = cipher.chunks(16);
    let chunks_count = chunks.len();

    if chunks_count < 2 {
        panic!("Can't detect block cipher mode when cipher is less than 2 blocks long.");
    }

    let unique_chunks = &chunks.into_iter().collect::<HashSet<&[u8]>>();

    if unique_chunks.len() < chunks_count {
        BlockCipherMode::ECB
    } else {
        BlockCipherMode::CBC(&iv)
    }
}

fn detect_oracle_block_size<O>(oracle: &O, placeholder_byte: u8) -> usize where O: Fn(&[u8])
    -> Vec<u8> {
    for bytes_count in 1..64 * 8 {
        let repeated_bytes = vec![placeholder_byte; bytes_count];

        let cipher = oracle(&repeated_bytes);

        for block_size in (8..64).rev() {
            let cipher_blocks = cipher.chunks(block_size);
            let cipher_blocks_count = cipher_blocks.len();
            let unique_blocks: &HashSet<&[u8]> = &cipher_blocks.into_iter()
                .collect::<HashSet<&[u8]>>();

            if unique_blocks.len() < cipher_blocks_count {
                return block_size;
            }
        }
    }

    panic!("Block size not in range.");
}

fn confirm_oracle_mode<O>(oracle: &O, bytes: &[u8], mode: &BlockCipherMode) -> () where O:
Fn(&[u8]) -> Vec<u8> {
    let cipher = oracle(&bytes);

    let iv = &aes::Iv::empty();
    let block_cipher_mode = detect_block_cipher_mode(&cipher, iv);
    if &block_cipher_mode != mode {
        panic!("Wrong block cipher mode.");
    }
}

/// Crafts a one-byte short block used by the byte-by-byte oracle decryption
fn craft_short_block(block_size: usize, placeholder_byte: &u8, known_characters: &[u8])
                     -> Vec<u8> {
    vec![*placeholder_byte; block_size - (known_characters.len() % block_size) - 1]
}

/// Populate the last byte map used to discover characters.
fn populate_last_byte_map<O>(block: &[u8],
                             oracle: O,
                             current_block_range: &Range<usize>) ->
                             HashMap<Vec<u8>, u8> where O: Fn(&[u8]) -> Vec<u8> {
    let mut last_byte_map: HashMap<Vec<u8>, u8> = HashMap::with_capacity(human::ALPHABET.len());
    for character in human::ALPHABET.iter() {
        let crafted_block = [
            &block[..],
            &[*character as u8]
        ].concat();
        let ciphered_crafted_block = oracle(&crafted_block);
        let key = ciphered_crafted_block[current_block_range.start..current_block_range.end].to_vec();
        last_byte_map.insert(key, *character as u8);
    }

    last_byte_map
}

pub fn build_byte_at_a_time_simple_oracle<'a>(
    unknown_string: &'a Vec<u8>,
    key: &'a Key) -> impl Fn(&[u8]) -> Vec<u8> + 'a {
    move |crafted_input: &[u8]| -> Vec<u8> {
        let input = &[&crafted_input[..], &unknown_string[..]].concat();

        aes::encrypt_aes_128(
            &input,
            &key,
            &AESEncryptionOptions::new(&BlockCipherMode::ECB, &Padding::PKCS7),
        )
    }
}

pub fn ecb_cut_and_paste(key: &Key) -> Vec<u8> {
    let initial_email = "foo@bar.com".to_string();
    let initial_email_bytes = initial_email.as_bytes();
    let block_size = 16;
    let profile = profile_for(&initial_email);
    let profile_bytes = profile.as_bytes();

    let email_starting_index = profile_bytes.iter()
        .enumerate()
        .position(|(i, _)| {
            i < profile_bytes.len() - initial_email_bytes.len()
                && profile_bytes[i..i + initial_email_bytes.len()] == initial_email_bytes[..]
        })
        .unwrap();

    let crafted_email_bytes = {
        let first_email_bytes = &profile_bytes[email_starting_index..block_size];
        let last_email_bytes = &profile_bytes[block_size..block_size + (initial_email_bytes.len() -
            first_email_bytes.len())];
        let admin_role = "admin".to_string();
        let crafted_admin_block = aes::pkcs7_pad(admin_role.as_bytes(), block_size as u8);

        [first_email_bytes, &crafted_admin_block[..], last_email_bytes].concat()
    };
    let crafted_profile = profile_for(&String::from_utf8(crafted_email_bytes).unwrap());
    let email_block_range = block_size..block_size * 2;
    let cipher_to_create_admin_block = aes::encrypt_aes_128(
        crafted_profile.as_bytes(),
        &key,
        &AESEncryptionOptions::new(&BlockCipherMode::ECB, &Padding::PKCS7),
    );

    let email_cipher_block = &cipher_to_create_admin_block[email_block_range];

    // make email so that "user" (from role=user) is first part of block
    let crafted_final_email = {
        let role_equals_bytes = "role=".as_bytes();
        let role_starting_index = profile_bytes.iter()
            .enumerate()
            .position(|(i, _)| {
                i < profile_bytes.len() - role_equals_bytes.len()
                    && profile_bytes[i..i + role_equals_bytes.len()] == role_equals_bytes[..]
            }).unwrap();

        let necessary_additional_characters = block_size - role_equals_bytes.len() -
            (role_starting_index % block_size);

        &[&vec![b'a'; necessary_additional_characters][..], &initial_email_bytes[..]].concat()
    };

    let crafted_profile_to_replace_role = profile_for(&String::from_utf8(crafted_final_email.to_vec()).unwrap());
    let cipher_to_replace_role = &mut aes::encrypt_aes_128(
        crafted_profile_to_replace_role.as_bytes(),
        &key,
        &AESEncryptionOptions::new(&BlockCipherMode::ECB, &Padding::PKCS7),
    );

    let mut i = cipher_to_replace_role.len() - 1;
    for byte in email_cipher_block.iter().rev() {
        cipher_to_replace_role[i] = *byte;
        i -= 1;
    }

    cipher_to_replace_role.to_vec()
}

pub fn byte_at_a_time_ecb_harder_decryption<O>(oracle: O) -> Vec<u8> where O: Fn(&[u8]) -> Vec<u8> {
    let placeholder_byte = b'A';
    let block_size = detect_oracle_block_size(&oracle, placeholder_byte);
    let repeated_bytes = vec![placeholder_byte; block_size * 8];

    confirm_oracle_mode(&oracle, &repeated_bytes, &BlockCipherMode::ECB);

    let original_cipher = oracle(&vec![]);
    let original_cipher_blocks = original_cipher
        .chunks(block_size)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let cipher_with_added_byte = oracle(&vec![placeholder_byte; 1]);
    let cipher_with_added_byte_blocks = cipher_with_added_byte
        .chunks(block_size)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let mut uncontrolled_end_block_index = 0;
    for (i, block) in cipher_with_added_byte_blocks.iter().enumerate() {
        if block != &original_cipher_blocks[i] {
            uncontrolled_end_block_index = i;
            break;
        }
    }

    // manipulating starting block
    let mut padding_to_arrive_at_new_block = 0;
    let mut last_block = original_cipher_blocks[uncontrolled_end_block_index].to_vec();
    for padding_amount in 1..block_size + 1 {
        let crafted_bytes = &vec![placeholder_byte; padding_amount];
        let cipher = oracle(&crafted_bytes);
        let cipher_blocks = cipher
            .chunks(block_size)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<Vec<u8>>>();
        let block = &cipher_blocks[uncontrolled_end_block_index];

        // if previous pad is current pad, previous pad's index is needed pad amount
        if last_block[..] == block[..] {
            padding_to_arrive_at_new_block = padding_amount - 1;
            break;
        }

        last_block = block.to_vec();
    }

    // create our crafted prefix to start at a manipulable block when doing byte-at-a-time
    // decryption
    let prefix = vec![placeholder_byte; padding_to_arrive_at_new_block];

    let block_index_in_which_starts_controlled_bytes = if padding_to_arrive_at_new_block == 0 {
        uncontrolled_end_block_index
    } else {
        uncontrolled_end_block_index + 1
    };

    byte_at_a_time_ecb_simple_decryption(&oracle, block_index_in_which_starts_controlled_bytes, &prefix)
}

/// Decrypts a cipher using its oracle, one byte at a time.
pub fn byte_at_a_time_ecb_simple_decryption<O>(
    oracle: O,
    controlled_bytes_block_start_index: usize,
    prefix: &[u8],
) -> Vec<u8> where O: Fn(&[u8]) -> Vec<u8> {
    let placeholder_byte = b'a';

    let block_size = detect_oracle_block_size(&oracle, placeholder_byte);

    let repeated_bytes = vec![placeholder_byte; block_size * 8];
    confirm_oracle_mode(&oracle, &repeated_bytes, &BlockCipherMode::ECB);

    let mut known_characters = Vec::with_capacity(
        oracle(&prefix).len() - (controlled_bytes_block_start_index * block_size)
    );
    // brute-force cipher characters one-by-one by using crafted input
    for i in (controlled_bytes_block_start_index * block_size)..oracle(&prefix).len() {
        let current_block_index = (i as f32 / block_size as f32).floor() as usize;
        let start_of_block_index = current_block_index * block_size;
        let current_block_range = start_of_block_index..start_of_block_index + block_size;

        // craft one-byte short block used for the map and for discovering the end-of-block byte
        let short_crafted_block = craft_short_block(block_size, &placeholder_byte, &known_characters);

        // populate last-byte character map
        let last_byte_map = populate_last_byte_map(
            &[
                &prefix[..],
                &short_crafted_block[..],
                &known_characters[..]
            ].concat(),
            &oracle,
            &current_block_range,
        );

        let ciphered_crafted_input = oracle(&[&prefix[..], &short_crafted_block[..]].concat());

        // get the block for which we have a correspondence in the map
        let current_block = &ciphered_crafted_input[current_block_range].to_vec();
        if let Some(character) = last_byte_map.get(current_block) {
            known_characters.push(*character);
        } else {
            // non-human or padding character was encountered
            break;
        }
    }

    known_characters
}

pub fn build_byte_at_a_time_harder_oracle<'a>(
    random_prefix: &'a Vec<u8>,
    unknown_string: &'a Vec<u8>,
    key: &'a Key) -> impl Fn(&[u8]) -> Vec<u8> + 'a {
    move |crafted_input: &[u8]| -> Vec<u8> {
        let input = &[
            &random_prefix[..],
            &crafted_input[..],
            &unknown_string[..]
        ].concat();

        aes::encrypt_aes_128(
            &input,
            &key,
            &AESEncryptionOptions::new(&BlockCipherMode::ECB, &Padding::PKCS7),
        )
    }
}

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

pub fn cbc_padding_attack<O>(original_cipher: &[u8], padding_oracle: O) -> Vec<u8>
    where O: Fn(&[u8]) -> bool {
    let block_size = 16;

    let last_block = &original_cipher[original_cipher.len() - block_size..];
    let penultimate_block = &original_cipher[
        original_cipher.len() - (block_size * 2)..original_cipher.len() - block_size
        ];

    let mut block_result = Vec::new();
    // I2
    let mut intermediate_block = Vec::new();

    for padding_length in 1u8..=15u8 {
        let xored_intermediate_block = &intermediate_block.iter()
            .map(|v| v ^ padding_length)
            .rev()
            .collect::<Vec<u8>>()[..];

        // C1'[]
        for padding_byte in 0u8..=255u8 {
            // C1'
            let modified_penultimate_block = &[
                &penultimate_block[..block_size - padding_length as usize],
                &[padding_byte][..],
                &xored_intermediate_block[..]
            ].concat();

            assert_eq!(xored_intermediate_block.len() as u8, padding_length - 1);

            ///assert_eq!(modified_penultimate_block.len(), 16usize);

            let modified_cipher = &[
                &modified_penultimate_block[..],
                &last_block
            ].concat();

            let padding_is_valid = padding_oracle(&modified_cipher);
            if padding_is_valid {
                // I2
                intermediate_block.push(padding_byte ^ padding_length);
                block_result.push(
                    penultimate_block[block_size - padding_length as usize] ^
                        *intermediate_block.last().unwrap());
                break;
            }
        }
    }

    dbg!(&block_result);
    dbg!(String::from_utf8_lossy(&block_result));

    vec![]
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

// TODO: Implement new for this
pub struct CipherWithIvAndKey<'a> {
    pub cipher: Vec<u8>,
    pub iv: &'a aes::Iv,
    pub key: &'a aes::Key,
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
            dbg!("in decipherer:");
            dbg!(String::from_utf8_lossy(&deciphered));
            dbg!(&deciphered.len());
            true
        }
    }
}
