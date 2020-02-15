use aes::Key;
use human;
use std::sync::mpsc::channel;

pub fn break_fixed_nonce_ctr_mode_using_substitutions(ciphers: &Vec<Vec<u8>>) -> Key {
    struct Best {
        score: f32,
        character: char,
    }

    let mut humanest_keystream_bytes: Vec<Best> = vec![];
    for _ in 0..16 {
        humanest_keystream_bytes.push(Best { score: 0f32, character: 0x00 as char })
    }

    for &possible_keystream_byte in human::ALPHABET.iter() {
        let mut ciphers_nonce_parts = extract_nonce_length_from_ciphers(ciphers, possible_keystream_byte);

        // let mut to_analyse_for_human = vec![vec![0u8; ciphers.len()]; 8];
        let mut to_analyse_for_human: Vec<Vec<u8>> = vec![vec![]; 16];
        for (i, resultant_cipher) in ciphers_nonce_parts.iter().enumerate() {
            for j in 0..16 {
                to_analyse_for_human[j].push(ciphers_nonce_parts[i][j]);
            }
        }

        for (i, slice) in to_analyse_for_human.iter().enumerate() {
            let score = human::calculate_human_resemblance_score(&slice);

            dbg!(score);
            if humanest_keystream_bytes[i].score < score {
                dbg!("new best!");
                humanest_keystream_bytes[i] = Best { score, character: possible_keystream_byte };
            }
        }
    }

    dbg!(humanest_keystream_bytes.iter()
        .map(|best| best.character as u8)
        .collect::<Vec<u8>>());

    Key([0; 16])
}

fn extract_nonce_length_from_ciphers(ciphers: &Vec<Vec<u8>>, possible_keystream_byte: char) -> Vec<Vec<u8>> {
    let mut resultant_ciphers = vec![vec![0u8; 16]; ciphers.len()];

    for (i, cipher) in ciphers.iter().enumerate() {
        for j in 0..16 {
            resultant_ciphers[i][j] = cipher[j] ^ (
                if j == 8 {
                    1u8
                } else {
                    possible_keystream_byte as u8
                })
        }
    }

    resultant_ciphers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_resultant_ciphers_test() {
        let ciphers = vec![
            vec![0b00u8; 16],
            vec![0b01u8; 16],
            vec![0b10u8; 16],
        ];
        let expected_ciphers = vec![
            [vec![0b100u8; 8], vec![0b01u8], vec![0b100u8; 7]].concat(),
            [vec![0b101u8; 8], vec![0b00u8], vec![0b101u8; 7]].concat(),
            [vec![0b110u8; 8], vec![0b11u8], vec![0b110u8; 7]].concat(),
        ];
        let possible_keystream_byte = 0b100 as char;

        let resultant_ciphers = extract_nonce_length_from_ciphers(&ciphers, possible_keystream_byte);

        assert_eq!(resultant_ciphers, expected_ciphers);
    }
}