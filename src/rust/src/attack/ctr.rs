use aes::Key;
use human;
use std::sync::mpsc::channel;
use std::cmp::max;
use xor::single_byte_xor;

pub fn break_fixed_nonce_ctr_mode_using_substitutions(ciphers: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    #[derive(Copy, Clone)]
    struct Best {
        score: f32,
        character: char,
    }

    let longest_cipher_length = ciphers.iter()
        .fold(0, |acc, v| max(v.len(), acc));
    let mut best_keystream = vec![Best { score: -1f32, character: 0x00 as char }; longest_cipher_length];

    for possible_keystream_byte in 0..=255 {
        let xored_ciphers = xor_with_possible_keystream_byte(
            ciphers,
            possible_keystream_byte,
        );

        let normalized_xored_ciphers = xored_ciphers.iter()
            .map(|cipher| {
                cipher.iter().map(|&byte| Some(byte)).collect::<Vec<Option<u8>>>()
            })
            .map(|cipher| {
                [&cipher[..], &vec![None; longest_cipher_length - cipher.len()][..]].concat()
            })
            .collect::<Vec<Vec<Option<u8>>>>();

        let to_analyze_for_human: Vec<Vec<Option<u8>>> = transpose_matrix(&normalized_xored_ciphers);

        for (i, slice) in to_analyze_for_human.iter().enumerate() {
            let some_slice = slice.iter()
                .filter_map(|&v| v)
                .collect::<Vec<u8>>();
            let score = human::calculate_human_resemblance_score(&some_slice);

            if best_keystream[i].score < score {
                best_keystream[i] = Best { score, character: possible_keystream_byte as char };
            }
        }
    }

    let deciphered = &mut vec![vec![]; ciphers.len()];
    for (i, cipher) in ciphers.iter().enumerate() {
        for (j, &byte) in cipher.iter().enumerate() {
            deciphered[i].push(byte ^ best_keystream[j].character as u8);
        }
    }

    deciphered.to_vec()
}

fn transpose_matrix<T : Copy>(matrix: &Vec<Vec<T>>) -> Vec<Vec<T>> {
    let width = matrix[0].len();
    let height = matrix.len();
    let transposed = &mut vec![vec![]; width];

    for (i, row) in matrix.iter().enumerate() {
        for (j, _) in row.iter().enumerate() {
            transposed[j].push(matrix[i][j]);
        }
    }

    transposed.iter()
        .map(|v| v.to_vec())
        .collect::<Vec<Vec<T>>>()
}

fn xor_with_possible_keystream_byte(ciphers: &Vec<Vec<u8>>, possible_keystream_byte: u8)
                                    -> Vec<Vec<u8>> {
    ciphers.iter()
        .map(|v| single_byte_xor(v, possible_keystream_byte))
        .collect::<Vec<Vec<u8>>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_nonce_length_from_ciphers_test() {
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
        let possible_keystream_byte = 0b100u8;

        let resultant_ciphers = xor_with_possible_keystream_byte(&ciphers, possible_keystream_byte);

        assert_eq!(resultant_ciphers, expected_ciphers);
    }

    #[test]
    fn transpose_square_matrix_test() {
        let case = vec![
            vec![1u8, 2u8, 3u8],
            vec![4u8, 5u8, 6u8],
            vec![7u8, 8u8, 9u8],
        ];
        let expected = vec![
            vec![1u8, 4u8, 7u8],
            vec![2u8, 5u8, 8u8],
            vec![3u8, 6u8, 9u8],
        ];

        let actual = transpose_matrix(&case);

        assert_eq!(actual, expected);
    }

    #[test]
    fn transpose_higher_matrix_test() {
        let case = vec![
            vec![1u8, 2u8, 3u8],
            vec![4u8, 5u8, 6u8],
            vec![7u8, 8u8, 9u8],
            vec![10u8, 11u8, 12u8],
        ];
        let expected = vec![
            vec![1u8, 4u8, 7u8, 10u8],
            vec![2u8, 5u8, 8u8, 11u8],
            vec![3u8, 6u8, 9u8, 12u8],
        ];

        let actual = transpose_matrix(&case);

        assert_eq!(actual, expected);
    }

    #[test]
    fn transpose_wider_matrix_test() {
        let case = vec![
            vec![1u8, 2u8, 3u8, 4u8],
            vec![5u8, 6u8, 7u8, 8u8],
        ];
        let expected = vec![
            vec![1u8, 5u8],
            vec![2u8, 6u8],
            vec![3u8, 7u8],
            vec![4u8, 8u8],
        ];

        let actual = transpose_matrix(&case);

        assert_eq!(actual, expected);
    }
}