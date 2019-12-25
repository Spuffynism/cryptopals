use aes::BlockCipherMode;
use std::collections::{HashSet, HashMap};
use std::ops::Range;
use ::{human, aes};
use profile::profile_for;
use profile;
use ::vs;

/// Detectes the block cipher mode of a cipher.
pub fn detect_block_cipher_mode(cipher: &Vec<u8>) -> BlockCipherMode {
    let chunks = cipher.chunks(16);
    let chunks_count = chunks.len();

    if chunks_count < 2 {
        panic!("Can't detect block cipher mode when cipher is less than 2 blocks long.");
    }

    let unique_chunks = &chunks.into_iter().collect::<HashSet<&[u8]>>();

    if unique_chunks.len() < chunks_count { BlockCipherMode::ECB } else { BlockCipherMode::CBC(vec![vec![0; 4]; 4]) }
}

/// Decrypts a cipher using its oracle, one byte at a time.
pub fn byte_at_a_time_ecb_decryption<O>(oracle: O) -> Vec<u8> where O: Fn(&Vec<u8>) -> Vec<u8> {
    let mut block_size = 0;
    let block_size_range = 1..64;
    let placeholder_byte = 'A' as u8;

    // detect the block size
    for possible_block_size in block_size_range {
        let repeated_bytes = vec![placeholder_byte; possible_block_size * 2];

        let cipher = oracle(&repeated_bytes);

        let known_chars_slice = &cipher[..possible_block_size];
        let expected_cipher_slice = &cipher[possible_block_size..possible_block_size * 2];

        if known_chars_slice == expected_cipher_slice {
            block_size = possible_block_size;
            break;
        }
    }

    // confirm that the cipher is in ECB mode
    let repeated_bytes = vec![placeholder_byte; block_size * 8];
    let cipher_repeated_bytes = oracle(&repeated_bytes);

    let detected_block_cipher_mode = detect_block_cipher_mode(&cipher_repeated_bytes);
    if detected_block_cipher_mode != BlockCipherMode::ECB {
        panic!("Wrong block cipher mode.");
    }

    // brute-force cipher characters one-by-one by using crafted input
    let mut known_characters = Vec::new();
    let empty_vec = vec![];
    let block_count = oracle(&empty_vec).len() / block_size;
    for current_block_index in 0..block_count {
        for position_in_block in 0..block_size {
            let start_of_block = current_block_index * block_size;
            let current_block_range = start_of_block..start_of_block + block_size;

            // craft one-byte short block used for the map
            let short_crafted_block = craft_short_block(block_size, &placeholder_byte, &known_characters);

            // populate last-byte character map
            let last_byte_map = populate_last_byte_map(
                &[&short_crafted_block[..], &known_characters[..]].concat(),
                &oracle,
                &current_block_range,
            );

            let ciphered_crafted_input = oracle(&short_crafted_block);

            // get the block for which we have a correspondence in the map
            let current_block = &ciphered_crafted_input[current_block_range].to_vec();
            match last_byte_map.get(current_block) {
                None => {
                    // non-human or padding character was encountered
                    break;
                }
                Some(character) => {
                    known_characters.push(*character);
                }
            }
        }
    }

    known_characters
}

/// Crafts a one-byte short block used by the byte-by-byte oracle decryption
fn craft_short_block(block_size: usize, placeholder_byte: &u8, known_characters: &Vec<u8>)
                     -> Vec<u8> {
    vec![*placeholder_byte; block_size - (known_characters.len() % block_size) - 1]
}

/// Populate the last byte map used to discover characters.
fn populate_last_byte_map<O>(block: &Vec<u8>,
                             oracle: O,
                             current_block_range: &Range<usize>) ->
                             HashMap<Vec<u8>, u8> where O: Fn(&Vec<u8>) -> Vec<u8> {
    let mut last_byte_map: HashMap<Vec<u8>, u8> = HashMap::new();
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

pub fn build_byte_at_a_time_oracle<'a>(unknown_string: &'a Vec<u8>, key: &'a Vec<u8>) -> impl Fn(&Vec<u8>) ->
Vec<u8> + 'a {
    move |crafted_input: &Vec<u8>| -> Vec<u8> {
        let input = &[&crafted_input[..], &unknown_string[..]].concat();

        aes::encrypt_aes_128(&input, &key, &aes::BlockCipherMode::ECB)
    }
}

pub fn build_ecb_cut_and_paste_oracle<'a>(key: &'a Vec<u8>) -> impl Fn
(&Vec<u8>) ->
    Vec<u8> + 'a {
    move |email: &Vec<u8>| -> Vec<u8> {
        let encoded_profile = &profile::profile_for(&String::from_utf8(email.to_vec()).unwrap());
        let encoded_profile_bytes = vs!(encoded_profile.as_str());

        aes::encrypt_aes_128(&encoded_profile_bytes, &key, &aes::BlockCipherMode::ECB)
    }
}

pub fn ecb_cut_and_paste(key: &Vec<u8>) -> Vec<u8> {
    let initial_email = "foo@bar.com".to_string();
    let initial_email_bytes: Vec<u8> = vs!(&initial_email);
    let block_size = 16;
    let profile = profile_for(&initial_email);
    let profile_bytes: Vec<u8> = vs!(&profile);

    let mut email_starting_index = 0;
    for (i, _) in profile_bytes.iter().enumerate() {
        if i < profile_bytes.len() - initial_email_bytes.len()
            && profile_bytes[i..i + initial_email_bytes.len()] == initial_email_bytes[..] {
            email_starting_index = i;
            break;
        }
    }

    let first_email_bytes = &profile_bytes[email_starting_index..block_size];
    let last_email_bytes = &profile_bytes[block_size..block_size + (initial_email_bytes.len() -
        first_email_bytes.len())];
    let admin_role = "admin".to_string();
    let crafted_admin_block = aes::pkcs7_pad(&vs!(admin_role), block_size as u8);
    let crafted_email_bytes = [first_email_bytes, &crafted_admin_block[..], last_email_bytes].concat();
    let crafted_profile = profile_for(&String::from_utf8(crafted_email_bytes).unwrap());
    let email_block_range = block_size..block_size * 2;
    let cipher_to_create_admin_block = aes::encrypt_aes_128(&vs!(crafted_profile), &key, &BlockCipherMode::ECB);

    let email_cipher_block = &cipher_to_create_admin_block[email_block_range];

    // make email so that "user" (from role=user) is first part of block
    let role_equals_bytes = vs!("role=");
    let mut role_starting_index = 0;
    for (i, _) in profile_bytes.iter().enumerate() {
        if i < profile_bytes.len() - role_equals_bytes.len()
            && profile_bytes[i..i + role_equals_bytes.len()] == role_equals_bytes[..] {
            role_starting_index = i;
            break;
        }
    }

    let necessary_additional_characters = block_size - role_equals_bytes.len() -
        (role_starting_index % block_size);
    let crafted_final_email: &[u8] = &[
        &vec!['a' as u8; necessary_additional_characters][..],
        &initial_email_bytes[..]
    ].concat();
    let crafted_profile_to_replace_role = profile_for(&String::from_utf8(crafted_final_email.to_vec()).unwrap());
    let mut cipher_to_replace_role = &mut aes::encrypt_aes_128(&vs!(crafted_profile_to_replace_role), &key, &BlockCipherMode::ECB);

    let mut continue_replacing = true;
    let mut i = cipher_to_replace_role.len() - 1;
    for byte in email_cipher_block.iter().rev() {
        cipher_to_replace_role[i] = *byte;
        i -= 1;
    }

    cipher_to_replace_role.to_vec()
}