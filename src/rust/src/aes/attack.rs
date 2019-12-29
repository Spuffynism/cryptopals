use aes::BlockCipherMode;
use std::collections::{HashSet, HashMap};
use std::ops::Range;
use ::{human, aes};
use profile::profile_for;
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

fn detect_oracle_block_size<O>(oracle: &O, placeholder_byte: u8) -> usize where O: Fn(&Vec<u8>)
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

fn confirm_oracle_mode<O>(oracle: &O, bytes: &Vec<u8>, mode: &BlockCipherMode) -> () where O:
Fn(&Vec<u8>) -> Vec<u8> {
    let cipher = oracle(&bytes);

    let block_cipher_mode = &detect_block_cipher_mode(&cipher);
    if block_cipher_mode != mode {
        panic!("Wrong block cipher mode.");
    }
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

pub fn build_byte_at_a_time_simple_oracle<'a>(unknown_string: &'a Vec<u8>, key: &'a Vec<u8>) -> impl Fn(&Vec<u8>) ->
Vec<u8> + 'a {
    move |crafted_input: &Vec<u8>| -> Vec<u8> {
        let input = &[&crafted_input[..], &unknown_string[..]].concat();

        aes::encrypt_aes_128(&input, &key, &aes::BlockCipherMode::ECB)
    }
}

pub fn ecb_cut_and_paste(key: &Vec<u8>) -> Vec<u8> {
    let initial_email = "foo@bar.com".to_string();
    let initial_email_bytes: Vec<u8> = vs!(&initial_email);
    let block_size = 16;
    let profile = profile_for(&initial_email);
    let profile_bytes: Vec<u8> = vs!(&profile);

    let email_starting_index = {
        let mut email_starting_index = 0;
        for (i, _) in profile_bytes.iter().enumerate() {
            if i < profile_bytes.len() - initial_email_bytes.len()
                && profile_bytes[i..i + initial_email_bytes.len()] == initial_email_bytes[..] {
                email_starting_index = i;
                break;
            }
        }

        email_starting_index
    };

    let crafted_email_bytes = {
        let first_email_bytes = &profile_bytes[email_starting_index..block_size];
        let last_email_bytes = &profile_bytes[block_size..block_size + (initial_email_bytes.len() -
            first_email_bytes.len())];
        let admin_role = "admin".to_string();
        let crafted_admin_block = aes::pkcs7_pad(&vs!(admin_role), block_size as u8);

        [first_email_bytes, &crafted_admin_block[..], last_email_bytes].concat()
    };
    let crafted_profile = profile_for(&String::from_utf8(crafted_email_bytes).unwrap());
    let email_block_range = block_size..block_size * 2;
    let cipher_to_create_admin_block = aes::encrypt_aes_128(&vs!(crafted_profile), &key, &BlockCipherMode::ECB);

    let email_cipher_block = &cipher_to_create_admin_block[email_block_range];

    // make email so that "user" (from role=user) is first part of block
    let crafted_final_email = {
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

        &[&vec!['a' as u8; necessary_additional_characters][..], &initial_email_bytes[..]].concat()
    };

    let crafted_profile_to_replace_role = profile_for(&String::from_utf8(crafted_final_email.to_vec()).unwrap());
    let cipher_to_replace_role = &mut aes::encrypt_aes_128(&vs!(crafted_profile_to_replace_role), &key, &BlockCipherMode::ECB);

    let mut i = cipher_to_replace_role.len() - 1;
    for byte in email_cipher_block.iter().rev() {
        cipher_to_replace_role[i] = *byte;
        i -= 1;
    }

    cipher_to_replace_role.to_vec()
}

pub fn byte_at_a_time_ecb_harder_decryption<O>(oracle: O) -> Vec<u8> where O: Fn(&Vec<u8>) -> Vec<u8> {
    let placeholder_byte = 'A' as u8;
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
    prefix: &Vec<u8>,
) -> Vec<u8> where O: Fn(&Vec<u8>) -> Vec<u8> {
    let placeholder_byte = 'A' as u8;

    let block_size = detect_oracle_block_size(&oracle, placeholder_byte);

    let repeated_bytes = vec![placeholder_byte; block_size * 8];
    confirm_oracle_mode(&oracle, &repeated_bytes, &BlockCipherMode::ECB);

    // brute-force cipher characters one-by-one by using crafted input
    let mut known_characters = Vec::new();
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

    known_characters
}

pub fn build_byte_at_a_time_harder_oracle<'a>(
    random_prefix: &'a Vec<u8>,
    unknown_string: &'a Vec<u8>,
    key: &'a Vec<u8>) -> impl Fn(&Vec<u8>) -> Vec<u8> + 'a {
    move |crafted_input: &Vec<u8>| -> Vec<u8> {
        let input = &[
            &random_prefix[..],
            &crafted_input[..],
            &unknown_string[..]
        ].concat();

        aes::encrypt_aes_128(&input, &key, &aes::BlockCipherMode::ECB)
    }
}

pub fn cbc_bitflip<O, P>(
    oracle: O,
    raw_oracle: P,
    key: &Vec<u8>,
    iv: &Vec<Vec<u8>>) -> Vec<u8>
    where O: Fn(&Vec<u8>) -> Vec<u8>, P: Fn(&Vec<u8>) -> Vec<u8> {
    let block_size = 16;

    let trigger = &vec![0x01; block_size];
    let sought_for = &[
        &[0xff][..],
        &vs!("admin")[..],
        &[0xff][..],
        &vs!("true")[..],
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
    let mut substitutions: Vec<(usize, u8)> = vec![];
    let mut current_cipher = vec![];
    for (pos, change) in letter_changes.iter() {
        for i in 0..=255 {
            let manipulated_byte = ((xor_block[*pos as usize] as u32 + i as u32) % 256u32) as u8;
            current_cipher = [
                &result[..2 * block_size + *pos],
                &[manipulated_byte][..],
                &result[(2 * block_size) + *pos + 1..],
            ].concat();

            let text = aes::decrypt_aes_128(&current_cipher, &key, &BlockCipherMode::CBC(iv.to_vec()));

            let as_string = String::from_utf8_lossy(&text);
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
    key: &'a Vec<u8>,
    mode: &'a BlockCipherMode,
) -> impl Fn(&Vec<u8>) -> Vec<u8> + 'a {
    move |crafted_input: &Vec<u8>| -> Vec<u8> {
        let encoded_input = prepend_and_append(&crafted_input);

        aes::encrypt_aes_128(&encoded_input, &key, &mode)
    }
}

pub fn build_cbc_bitflip_raw_oracle<'a>(
    key: &'a Vec<u8>,
    mode: &'a BlockCipherMode,
) -> impl Fn(&Vec<u8>) -> Vec<u8> + 'a {
    move |crafted_input: &Vec<u8>| -> Vec<u8> {
        aes::encrypt_aes_128(&crafted_input, &key, &mode)
    }
}

fn prepend_and_append(input: &Vec<u8>) -> Vec<u8> {
    let prefix = vs!("comment1=cooking%20MCs;userdata=");
    let suffix = vs!(";comment2=%20like%20a%20pound%20of%20bacon");

    let mut sanitized_input = Vec::with_capacity(input.len());

    for byte in input {
        if [';' as u8, '=' as u8].contains(byte) {
            sanitized_input.push('\\' as u8);
        }
        sanitized_input.push(*byte);
    }

    [&prefix[..], &sanitized_input[..], &suffix[..]].concat()
}
