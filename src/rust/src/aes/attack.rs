use aes::BlockCipherMode;
use std::collections::{HashSet, HashMap};
use std::ops::Range;
use ::{human, aes};

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
            let mut last_byte_map = populate_last_byte_map(
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

pub fn build_oracle<'a>(unknown_string: &'a Vec<u8>, key: &'a Vec<u8>) -> impl Fn(&Vec<u8>) ->
Vec<u8> + 'a {
    move |crafted_input: &Vec<u8>| -> Vec<u8> {
        let input = &[&crafted_input[..], &unknown_string[..]].concat();

        aes::encrypt_aes_128(&input, &key, &aes::BlockCipherMode::ECB)
    }
}