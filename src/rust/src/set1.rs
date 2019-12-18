extern crate hex;

use std::char;
use std::fs;
use std::str;
use std::f32;

use rustc_serialize::base64::{STANDARD, ToBase64};

use xor;

static ALPHABET: [char; 74] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ',', ';', ':', '.', ' ', '\'', '\n', '\\', '/', '"', '\r', '-',
];

pub fn hex_string_to_bytes(hex_input: &str) -> Vec<u8> {
    hex::decode(hex_input).unwrap()
}

pub fn hex_to_bytes(hex_input: &Vec<u8>) -> Vec<u8> {
    hex_string_to_bytes(String::from_utf8(hex_input.as_slice().to_vec()).unwrap().as_str())
}

pub fn hex_fixed_xor(hex_input: &Vec<u8>, hex_key: &Vec<u8>) -> Vec<u8> {
    assert_eq!(hex_input.len(), hex_key.len());

    let input: Vec<u8> = hex_to_bytes(hex_input);
    let key: Vec<u8> = hex_to_bytes(hex_key);

    return xor::fixed_xor(&input, &key);
}

pub fn find_single_byte_xor(input: &Vec<u8>) -> (char, f32, Vec<u8>) {
    let mut best_key: char = 'a';
    let mut best_score: f32 = -1_f32;
    let mut best_result: Vec<u8> = vec![];

    for character in ALPHABET.iter() {
        let result: Vec<u8> = xor::single_byte_xor(&input, (*character as u32) as u8);

        let score = calculate_human_resemblance_score(&result);

        if score > best_score {
            best_key = *character;
            best_score = score;
            best_result = result.clone();
        }

        if best_score == 1f32 {
            break;
        }
    }

    return (best_key, best_score, best_result);
}

pub fn hex_find_single_byte_xor(hex_input: &Vec<u8>) -> (char, f32, Vec<u8>) {
    find_single_byte_xor(&hex_to_bytes(hex_input))
}

fn calculate_human_resemblance_score(input: &Vec<u8>) -> f32 {
    let mut human_characters_count = 0;

    for letter in input.iter() {
        if ALPHABET.contains(&char::from_u32(*letter as u32).unwrap()) {
            human_characters_count += 1;
        }
    }

    return human_characters_count as f32 / input.len() as f32;
}

fn find_most_human(candidates: Vec<Vec<u8>>) -> (char, f32, Vec<u8>, Vec<u8>) {
    let mut best_key: char = 'a';
    let mut best_score: f32 = -1_f32;
    let mut best_result: Vec<u8> = vec![];
    let mut best_candidate: Vec<u8> = vec![];

    for candidate in candidates {
        let (character, score, xored) = hex_find_single_byte_xor(&candidate);

        if score > best_score {
            best_key = character;
            best_score = score;
            best_result = xored.clone();
            best_candidate = candidate.clone();
        }
    }

    return (best_key, best_score, best_result, best_candidate);
}

fn break_repeating_key_xor(cipher: &Vec<u8>,
                           key_alphabet: Vec<u8>, // TODO: Make use of this
                           min_key_size: i32,
                           max_key_size: i32,
                           max_blocks_average: u8,  // TODO: Make use of this
                           best_guesses_count: u8,  // TODO: Make use of this
) -> (Vec<u8>, Vec<u8>) {
    let mut key: Vec<u8> = vec![];
    let mut best_key_size = 0;
    let mut best_normalized_hamming_distance = std::f32::MAX;

    for key_size in min_key_size..max_key_size {
        let mut i: i32 = 0;
        let mut normalized_hamming_distances: Vec<f32> = Vec::new();

        loop {
            let mut first: Vec<u8> = cipher[i as usize..(i + key_size) as usize].to_vec();
            let mut second: Vec<u8> = cipher[(i + key_size) as usize..(i + (key_size * 2)) as
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

    let mut rows = Vec::new();
    for _i in 0..best_key_size {
        rows.push(Vec::new());
    }

    let rows_length = (cipher.len() as f32 / best_key_size as f32).ceil() as i32;

    for j in 0..best_key_size {
        for i in 0..rows_length {
            if (i * best_key_size + j as i32) as usize >= cipher.len() {
                break;
            }

            rows[j as usize].push(cipher[(i * best_key_size + j as i32) as usize]);
        }
    }

    let mut key = Vec::with_capacity(rows.len());
    for row in rows.iter() {
        let (best_key, best_score, best_result) = find_single_byte_xor(row);
        key.push(best_key as u8);
    }

    let mut deciphered: Vec<u8> = xor::fixed_key_xor(&cipher, &key);

    return (key, deciphered);
}

fn normalized_hamming_distance_in_bits(from: &Vec<u8>, to: &Vec<u8>) -> f32 {
    (hamming_distance_in_bits(from, to) as f32) / (to.len() as f32)
}

fn hamming_distance_in_bits(from: &Vec<u8>, to: &Vec<u8>) -> u32 {
    assert_eq!(from.len(), to.len());
    let mut distance: u32 = 0;

    for (i, character) in from.iter().enumerate() {
        distance += bits_difference_count(*character, to[i]) as u32;
    }

    return distance;
}

fn bits_difference_count(from: u8, to: u8) -> u8 {
    let mut distance: u8 = 0;
    let mut i = from ^ to;

    loop {
        if i <= 0 {
            break;
        }

        if i & 1 == 1 {
            distance += 1;
        }

        i >>= 1;
    }

    return distance;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Converts a string to a vector of its bytes
    macro_rules! vs {
( $ x: expr) => ( $ x.as_bytes().to_vec());
}

    #[test]
    fn challenge1() {
        let input: &Vec<u8> =
            &vs!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(hex_to_bytes(input).to_base64(STANDARD), expected)
    }

    #[test]
    fn challenge2() {
        let input: &Vec<u8> = &vs!("1c0111001f010100061a024b53535009181c");
        let key: &Vec<u8> = &vs!("686974207468652062756c6c277320657965");
        let expected: &Vec<u8> = &vs!("746865206b696420646f6e277420706c6179");

        assert_eq!(hex_fixed_xor(input, key), hex_to_bytes(expected))
    }

    #[test]
    fn challenge3() {
        let input: &Vec<u8> =
            &vs!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let expected = &vs!("Cooking MC's like a pound of bacon");

        let (key, score, xored_result) = hex_find_single_byte_xor(input);

        assert_eq!(xored_result, *expected);
    }

    #[test]
    fn challenge4() {
        let content = fs::read_to_string("./resources/4.txt").expect("Can't read file.");
        let lines = content
            .split("\n")
            .map(|line| vs!(line))
            .collect::<Vec<Vec<u8>>>();
        let expected = vs!("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f");

        let (key, score, xored_result, candidate) = find_most_human(lines);

        assert_eq!(candidate, expected);
    }

    #[test]
    fn challenge5() {
        let content =
            &vs!("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
        let key = &vs!("ICE");
        let expected = &vs!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

        assert_eq!(xor::fixed_key_xor(content, key), hex_to_bytes(expected));
    }

    #[test]
    fn hamming_distance_test() {
        let test_cases = vec![
            // wikipedia examples
            ("karolin", "kathrin", 9),
            ("karolin", "kerstin", 6),
            ("1011101", "1001001", 2),
            ("2173896", "2233796", 7),
            // cryptopals test case
            ("this is a test", "wokka wokka!!!", 37)
        ];

        for (from, to, expected_distance) in test_cases {
            assert_eq!(hamming_distance_in_bits(&vs!(from), &vs!(to)), expected_distance);
        }
    }

    #[test]
    fn normalized_hamming_distance_test() {
        let test_cases = vec![
            // wikipedia examples
            ("karolin", "kathrin", 9),
            ("karolin", "kerstin", 6),
            ("1011101", "1001001", 2),
            ("2173896", "2233796", 7),
            // cryptopals test case
            ("this is a test", "wokka wokka!!!", 37)
        ];

        for (from, to, expected_hamming_distance) in test_cases {
            let expected_normalized_hamming_distance =
                expected_hamming_distance as f32 / to.len() as f32;
            assert_eq!(normalized_hamming_distance_in_bits(&vs!(from), &vs!(to)),
                       expected_normalized_hamming_distance);
        }
    }

    #[test]
    fn challenge6() {
        let content = fs::read_to_string("./resources/6.txt").expect("Can't read file.");
        let decoded_content: &Vec<u8> = &content
            .split("\n")
            .map(|line| base64::decode(line).unwrap())
            .collect::<Vec<Vec<u8>>>()
            .iter()
            .fold(Vec::new(), |acc, line| [acc.as_slice(), line.as_slice()].concat());

        let (key, deciphered) = break_repeating_key_xor(decoded_content, vec![], 2, 40,
                                                        4, 3);

        println!("{:?}", String::from_utf8(key));
        println!("{:?}", String::from_utf8(deciphered));
    }
}