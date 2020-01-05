use std::char;
use std::f32;

use rustc_serialize::base64::{STANDARD, ToBase64};

use human;
use xor;
use file_util;
use aes;
use hex;
use std::collections::HashSet;

pub fn hex_fixed_xor(hex_input: &[u8], hex_key: &[u8]) -> Vec<u8> {
    assert_eq!(hex_input.len(), hex_key.len());

    let input = hex::hex_to_bytes(&hex_input);
    let key = hex::hex_to_bytes(&hex_key);

    xor::fixed_xor(&input, &key)
}

pub fn find_single_byte_xor(input: &[u8]) -> (char, f32, Vec<u8>) {
    let perfect_score = 1f32;
    let mut best = ('a', -1f32, vec![]);

    for character in human::ALPHABET.iter() {
        let (_, best_score, _) = best;

        let xored = xor::single_byte_xor(&input, *character as u8);
        let score = calculate_human_resemblance_score(&xored);

        if score > best_score {
            best = (*character, score, xored);

            if score == perfect_score {
                break;
            }
        }
    }

    best
}

pub fn hex_find_single_byte_xor(hex_input: &[u8]) -> (char, f32, Vec<u8>) {
    find_single_byte_xor(&hex::hex_to_bytes(&hex_input))
}

fn calculate_human_resemblance_score(input: &[u8]) -> f32 {
    let human_characters_count = input.iter()
        .filter(|byte| human::ALPHABET.contains(&(**byte as char)))
        .count();

    human_characters_count as f32 / input.len() as f32
}

fn find_most_human(candidates: &Vec<Vec<u8>>) -> (char, f32, Vec<u8>, Vec<u8>) {
    let mut most_human = ('a', -1f32, vec![], vec![]);

    for candidate in candidates.iter() {
        let (_, best_score, _, _) = most_human;
        let (character, score, xored) = hex_find_single_byte_xor(&candidate);

        if score > best_score {
            most_human = (character, score, xored, candidate.to_vec());
        }
    }

    most_human
}

fn break_repeating_key_xor(cipher: &[u8], min_key_size: i32, max_key_size: i32) -> (Vec<u8>, Vec<u8>) {
    let mut best_key_size = 0;
    let mut best_normalized_hamming_distance = std::f32::MAX;

    for key_size in min_key_size..max_key_size {
        let mut i: i32 = 0;
        let mut normalized_hamming_distances: Vec<f32> = Vec::new();

        loop {
            let first: Vec<u8> = cipher[i as usize..(i + key_size) as usize].to_vec();
            let second: Vec<u8> = cipher[(i + key_size) as usize..(i + (key_size * 2)) as
                usize].to_vec();

            normalized_hamming_distances.push(
                normalized_hamming_distance_in_bits(&first.to_vec(), &second.to_vec()));

            i += key_size * 2;

            if (i + key_size * 2) as usize >= cipher.len() {
                break;
            }
        }

        let normalized_hamming_distance_sum: f32 = normalized_hamming_distances
            .iter()
            .fold(0f32, |acc, v| acc + *v);
        let normalized_hamming_distance = normalized_hamming_distance_sum /
            normalized_hamming_distances.len() as f32;

        if normalized_hamming_distance < best_normalized_hamming_distance {
            best_key_size = key_size;
            best_normalized_hamming_distance = normalized_hamming_distance;
        }
    }

    let mut rows = vec![vec![]; best_key_size as usize];

    let rows_length = (cipher.len() as f32 / best_key_size as f32).ceil() as usize;

    for j in 0..best_key_size {
        for i in 0..rows_length {
            if (i as i32 * best_key_size + j) as usize >= cipher.len() {
                break;
            }

            rows[j as usize].push(cipher[(i as i32 * best_key_size + j) as usize]);
        }
    }

    let mut key = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let (best_key, _best_score, _best_result) = find_single_byte_xor(row);
        key.push(best_key as u8);
    }

    let deciphered = xor::fixed_key_xor(&cipher, &key);

    (key, deciphered)
}

fn normalized_hamming_distance_in_bits(from: &[u8], to: &[u8]) -> f32 {
    hamming_distance_in_bits(from, to) as f32 / to.len() as f32
}

fn hamming_distance_in_bits(from: &[u8], to: &[u8]) -> u32 {
    assert_eq!(from.len(), to.len());

    from.iter().zip(to)
        .map(|(from, to)| bits_difference_count(*from, *to))
        .fold(0u32, |acc, difference| acc + difference as u32)
}

fn bits_difference_count(from: u8, to: u8) -> u8 {
    let mut count: u8 = 0;
    let mut i = from ^ to;

    loop {
        if i <= 0 {
            break;
        }

        if i & 1 == 1 {
            count += 1;
        }

        i >>= 1;
    }

    count
}

fn detect_aes_in_ecb_mode(cipher_candidates: Vec<Vec<u8>>) -> Vec<u8> {
    let block_size = 16;
    let mut ciphers_as_blocks: Vec<Vec<Vec<u8>>> = vec![];

    for (i, cipher) in cipher_candidates.iter().enumerate() {
        ciphers_as_blocks.push(vec![vec![0; block_size]; cipher.len() / block_size]);
        for (j, byte) in cipher.iter().enumerate() {
            ciphers_as_blocks[i][(j as f32 / block_size as f32).floor() as usize][j % block_size] =
                *byte;
        }

        let unique_cipher_parts = ciphers_as_blocks[i].iter().cloned()
            .collect::<HashSet<Vec<u8>>>();

        if unique_cipher_parts.len() < ciphers_as_blocks[i].len() {
            return ciphers_as_blocks[i].iter()
                .fold(vec![], |acc, val| [&acc[..], &val[..]].concat());
        }
    }

    panic!("Unable to detect aes in ecb mode.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::BlockCipherMode;

    #[test]
    fn challenge1() {
        let input =
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".as_bytes();
        let expected: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(hex::hex_to_bytes(input).to_base64(STANDARD), expected)
    }

    #[test]
    fn challenge2() {
        let input = "1c0111001f010100061a024b53535009181c".as_bytes();
        let key = "686974207468652062756c6c277320657965".as_bytes();
        let expected = "746865206b696420646f6e277420706c6179".as_bytes();

        assert_eq!(hex_fixed_xor(input, key), hex::hex_to_bytes(expected))
    }

    #[test]
    fn challenge3() {
        let input =
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".as_bytes();
        let expected = "Cooking MC's like a pound of bacon".as_bytes();

        let (_, _, xored_result) = hex_find_single_byte_xor(input);

        assert_eq!(&xored_result[..], expected);
    }

    #[test]
    fn challenge4() {
        let lines = file_util::read_file_lines("./resources/4.txt");
        let expected = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f".as_bytes();

        let (_, _, _, candidate) = find_most_human(&lines);

        assert_eq!(candidate, expected);
    }

    #[test]
    fn challenge5() {
        let content =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
        let key = "ICE".as_bytes();
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".as_bytes();

        assert_eq!(xor::fixed_key_xor(content, key), hex::hex_to_bytes(expected));
    }

    #[test]
    fn hamming_distance_test() {
        let test_cases = &[
            // wikipedia examples
            ("karolin", "kathrin", 9),
            ("karolin", "kerstin", 6),
            ("1011101", "1001001", 2),
            ("2173896", "2233796", 7),
            // cryptopals test case
            ("this is a test", "wokka wokka!!!", 37)
        ][..];

        for (from, to, expected_distance) in test_cases {
            assert_eq!(
                hamming_distance_in_bits(from.as_bytes(), to.as_bytes()),
                *expected_distance
            );
        }
    }

    #[test]
    fn normalized_hamming_distance_test() {
        let test_cases = &[
            // wikipedia examples
            ("karolin", "kathrin", 9),
            ("karolin", "kerstin", 6),
            ("1011101", "1001001", 2),
            ("2173896", "2233796", 7),
            // cryptopals test case
            ("this is a test", "wokka wokka!!!", 37)
        ][..];

        for (from, to, expected_hamming_distance) in test_cases {
            let expected_normalized_hamming_distance =
                *expected_hamming_distance as f32 / to.len() as f32;
            assert_eq!(normalized_hamming_distance_in_bits(from.as_bytes(), to.as_bytes()),
                       expected_normalized_hamming_distance);
        }
    }

    #[test]
    fn challenge6() {
        let cipher = &file_util::read_base64_file_bytes("./resources/6.txt");

        let (_, deciphered) = &break_repeating_key_xor(&cipher, 2, 40);

        assert!(deciphered.starts_with("I'm back and I'm ringin' the bell".as_bytes()));
    }

    #[test]
    fn challenge7() {
        let cipher = &file_util::read_base64_file_bytes("./resources/7.txt");
        let key = aes::Key::new_from_string("YELLOW SUBMARINE");

        let deciphered = aes::decrypt_aes_128(&cipher, &key, &BlockCipherMode::ECB);

        assert!(deciphered.starts_with("I'm back and I'm ringin' the bell".as_bytes()));
    }

    #[test]
    fn challenge8() {
        let lines = file_util::read_hex_file_lines("./resources/8.txt");
        let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a".as_bytes();

        let actual_found = detect_aes_in_ecb_mode(lines);

        assert_eq!(actual_found, hex::hex_to_bytes(expected));
    }
}