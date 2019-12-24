use ::vs;
use rand::{RngCore, Rng};
use aes;
use aes::BlockCipherMode;
use human;
use std::collections::{HashSet, HashMap};
use std::ops::Range;

pub fn generate_aes_key() -> Vec<u8> {
    generate_bytes_for_length(16)
}

fn generate_bytes_for_length(length: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; length as usize];
    rand::thread_rng().fill_bytes(&mut bytes);

    bytes
}

pub fn encrypt_under_random_key(content: &Vec<u8>) -> (Vec<u8>, BlockCipherMode) {
    let key = generate_aes_key();
    let prefix = generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));
    let suffix = generate_bytes_for_length(rand::thread_rng().gen_range(5, 11));

    let padded_content: Vec<u8> = [prefix.clone(), content.clone(), suffix.clone()].concat();

    let mode = match rand::random() {
        true => aes::BlockCipherMode::ECB,
        false => {
            // TODO(nich): Generate random iv
            let iv = vec![vec![1u8; 4]; 4];
            aes::BlockCipherMode::CBC(iv)
        }
    };

    let cipher = aes::encrypt_aes_128(&padded_content, &key, &mode);

    (cipher, mode)
}

fn detect_block_cipher_mode(cipher: &Vec<u8>) -> BlockCipherMode {
    let chunks = cipher.chunks(16);
    let chunks_count = chunks.len();

    if chunks_count < 2 {
        panic!("Can't detect block cipher mode when cipher is less than 2 blocks long.");
    }

    let unique_chunks = &chunks.into_iter().collect::<HashSet<&[u8]>>();

    if unique_chunks.len() < chunks_count { BlockCipherMode::ECB } else { BlockCipherMode::CBC(vec![vec![0; 4]; 4]) }
}

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

fn craft_short_block(block_size: usize, placeholder_byte: &u8, known_characters: &Vec<u8>)
                     -> Vec<u8> {
    vec![*placeholder_byte; block_size - (known_characters.len() % block_size) - 1]
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use aes;
    use file_util;
    use aes::BlockCipherMode;

    #[test]
    fn challenge9() {
        let message = vs!("YELLOW SUBMARINE");
        let expected_result = [message.as_slice(), &[0x04, 0x04, 0x04, 0x04]].concat();

        let actual_result = aes::pkcs7_pad(&message, 20);

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn challenge9_no_padding_needed() {
        let message = vs!("YELLOW SUBMARINE");
        let expected_result = message.as_slice();

        let actual_result = aes::pkcs7_pad(&message, 16);

        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn challenge10() {
        let cbc_cipher = file_util::read_base64_file_bytes("./resources/10.txt");
        let key = vs!("YELLOW SUBMARINE");
        let iv = vec![vec![0x00; 4]; 4];
        let mode = BlockCipherMode::CBC(iv);

        let deciphered = aes::decrypt_aes_128(&cbc_cipher, &key, &mode);

        assert!(deciphered.starts_with(&vs!("I'm back and I'm ringin' the bell")));
    }

    #[test]
    fn generate_aes_key_test() {
        let key = generate_aes_key();

        assert!(!key.is_empty());
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn challenge11() {
        for _i in 0..100 {
            let repeated_bytes = generate_bytes_for_length(16);
            let mut input = Vec::with_capacity(16 * 8);
            for j in 0..(16 * 8) {
                // the input repeats the repeated bytes, in order
                // (i.e.: 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 , ...)
                input.push(repeated_bytes[(j % repeated_bytes.len()) as usize]);
            }
            let (cipher, expected_mode) = &encrypt_under_random_key(&input);

            let found_mode = &detect_block_cipher_mode(&cipher);

            assert_eq!(std::mem::discriminant(found_mode), std::mem::discriminant(expected_mode))
        }
    }

    #[test]
    fn challenge12() {
        let unknown_string = file_util::read_base64_file_bytes("./resources/12.txt");
        let key = generate_aes_key();
        let oracle = |crafted_input: &Vec<u8>| -> Vec<u8> {
            let input = &[&crafted_input[..], &unknown_string[..]].concat();

            aes::encrypt_aes_128(&input, &key, &aes::BlockCipherMode::ECB)
        };
        let deciphered = byte_at_a_time_ecb_decryption(oracle);

        assert!(deciphered.starts_with(&vs!("Rollin' in my 5.0\nWith")));
        assert!(deciphered.ends_with(&vs!("No, I just drove by\n")));
    }

    /*#[test]
    fn populate_last_byte_map_test() {
        let block_size = 16;
        let short_crafted_block = vec!['A' as u8; block_size - 1];
        let key = vec![0; block_size];

        let expected_cipher = aes::encrypt_aes_128(&vec!['A' as u8; block_size], &key,
                                                   &BlockCipherMode::ECB);
        let expected_cipher_byte = 'A';

        let map = populate_last_byte_map(&short_crafted_block, &key);

        assert_eq!(map.len(), human::ALPHABET.len());
        assert_eq!(*map.get(&expected_cipher).unwrap() as char, expected_cipher_byte);
    }*/

    /*#[test]
    fn craft_short_block_no_known_characters() {
        let block_size: usize = 16;
        let placeholder_byte = 'A' as u8;
        let known_characters = vec![];

        let expected_crafted_block = vec!['A' as u8; block_size - 1];

        let actual_crafted_short_block = craft_short_block(block_size, &placeholder_byte,
                                                           &known_characters);

        assert_eq!(actual_crafted_short_block, expected_crafted_block);
        assert_eq!(actual_crafted_short_block.len(), 15);
    }

    #[test]
    fn craft_short_block_some_known_characters() {
        let block_size: usize = 16;
        let placeholder_byte = 'A' as u8;
        let known_characters: Vec<u8> = (0..(block_size / 2) as u8).collect();

        let expected_crafted_block = vec![
            vec![placeholder_byte; block_size / 2 - 1].as_slice(),
            &known_characters
        ].concat();

        let actual_crafted_short_block = craft_short_block(block_size, &placeholder_byte,
                                                           &known_characters);

        assert_eq!(actual_crafted_short_block, expected_crafted_block);
        assert_eq!(actual_crafted_short_block.len(), 15);
    }

    #[test]
    fn craft_short_block_block_size_amount_of_known_characters() {
        let block_size: usize = 16;
        let placeholder_byte = 'A' as u8;
        let known_characters: Vec<u8> = (0..block_size as u8).collect();

        let expected_crafted_block = &known_characters;

        let actual_crafted_short_block = craft_short_block(block_size, &placeholder_byte,
                                                           &known_characters);

        assert_eq!(&actual_crafted_short_block, expected_crafted_block);
        assert_eq!(actual_crafted_short_block.len(), 15);
    }*/
}
