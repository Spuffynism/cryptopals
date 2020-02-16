use aes::Key;
use human;
use std::sync::mpsc::channel;

pub fn break_fixed_nonce_ctr_mode_using_substitutions(ciphers: &Vec<Vec<u8>>) -> Key {
    #[derive(Copy, Clone)]
    struct Best {
        score: f32,
        character: char,
    }

    let mut best_keystream = vec![Best { score: -1f32, character: 0x00 as char }; 16];

    for possible_keystream_byte in 0..=255 {
        // CIPHERTEXT ^ KEYSTREAM
        let ciphers_nonce_parts = extract_nonce_length_from_ciphers(
            ciphers,
            possible_keystream_byte,
        );

        let to_analyze_for_human: Vec<Vec<u8>> = transpose_matrix(&ciphers_nonce_parts);

        for (i, slice) in to_analyze_for_human.iter().enumerate() {
            let score = human::calculate_human_resemblance_score(&slice);

            if best_keystream[i].score < score {
                best_keystream[i] = Best { score, character: possible_keystream_byte as char };
            }
        }
    }

    let result = &mut vec![vec![0;16]; ciphers.len()];
    for (i, cipher) in ciphers.iter().enumerate() {
        for (j, &byte) in cipher[..16].iter().enumerate() {
            result[i][j] = byte ^ best_keystream[j].character as u8;
        }
    }

    dbg!(result);

    Key([0; 16])
}

fn transpose_matrix(matrix: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let width = matrix[0].len();
    let height = matrix.len();
    let transposed = &mut vec![vec![0u8; height]; width];

    for (i, row) in matrix.iter().enumerate() {
        for (j, _) in row.iter().enumerate() {
            transposed[j][i] = matrix[i][j];
        }
    }

    transposed.iter()
        .map(|v| v.to_vec())
        .collect::<Vec<Vec<u8>>>()
}

fn extract_nonce_length_from_ciphers(ciphers: &Vec<Vec<u8>>, possible_keystream_byte: u8)
                                     -> Vec<Vec<u8>> {
    ciphers.iter()
        .map(|v| {
            v[..16].iter()
                .map(|byte| byte ^ possible_keystream_byte)
                .collect::<Vec<u8>>()
        })
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

        let resultant_ciphers = extract_nonce_length_from_ciphers(&ciphers, possible_keystream_byte);

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