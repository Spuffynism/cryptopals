extern crate hex;

use std::char;
use std::fs;
use std::str;

use rustc_serialize::base64::{STANDARD, ToBase64};

static ALPHABET: [char; 68] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ',', ';', ':', '.', ' ', '\''
];

pub fn hex_string_to_bytes(hex_input: &str) -> Vec<u8> {
    hex::decode(hex_input).unwrap()
}

pub fn hex_to_bytes(hex_input: Vec<u8>) -> Vec<u8> {
    hex_string_to_bytes(String::from_utf8(hex_input).unwrap().as_str())
}

pub fn hex_fixed_xor(hex_input: Vec<u8>, hex_key: Vec<u8>) -> Vec<u8> {
    assert_eq!(hex_input.len(), hex_key.len());

    let input: Vec<u8> = hex_to_bytes(hex_input);
    let key: Vec<u8> = hex_to_bytes(hex_key);

    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for (i, item) in input.iter().enumerate() {
        result.push(item ^ key[i]);
    }

    return result;
}

pub fn find_single_byte_xor(hex_input: Vec<u8>) -> (char, f32, Vec<u8>) {
    let mut input: Vec<u8> = hex_to_bytes(hex_input);
    let mut best_key: char = 'a';
    let mut best_score: f32 = -1_f32;
    let mut best_result: Vec<u8> = vec![];

    for character in ALPHABET.iter() {
        let result: Vec<u8> = single_byte_xor(&input, *character as u32);

        let score = human_resemblance_score(&result);

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

pub fn single_byte_xor(input: &Vec<u8>, key: u32) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for item in input.iter() {
        result.push(((*item as u32) ^ key) as u8);
    }

    return result;
}

fn human_resemblance_score(input: &Vec<u8>) -> f32 {
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
        let (character, score, xored) = find_single_byte_xor(candidate.clone());

        if score > best_score {
            best_key = character;
            best_score = score;
            best_result = xored.clone();
            best_candidate = candidate.clone();
        }
    }

    return (best_key, best_score, best_result, best_candidate);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Converts a string to a vector of its bytes
    macro_rules! vs {
        ($x:expr) => ($x.as_bytes().to_vec());
    }

    #[test]
    fn challenge1() {
        let input: Vec<u8> =
            vs!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(hex_to_bytes(input).to_base64(STANDARD), expected)
    }

    #[test]
    fn challenge2() {
        let input: Vec<u8> = vs!("1c0111001f010100061a024b53535009181c");
        let key: Vec<u8> = vs!("686974207468652062756c6c277320657965");
        let expected: Vec<u8> = vs!("746865206b696420646f6e277420706c6179");

        assert_eq!(hex_fixed_xor(input, key), hex_to_bytes(expected))
    }

    #[test]
    fn challenge3() {
        let input: Vec<u8> =
            vs!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let expected = vs!("Cooking MC's like a pound of bacon");

        let (key, score, xored_result) = find_single_byte_xor(input);

        assert_eq!(xored_result, expected);
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
}