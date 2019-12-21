/// Resources used:
/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
/// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example

use xor;

/// Number of columns (32-bit words) comprising the State. For this standard, Nb = 4.
#[allow(non_upper_case_globals)]
static Nb: usize = 4;

/// Number of rounds, which is a function of Nk and Nb (which is fixed). For this implementation,
/// Nr = 10.
#[allow(non_upper_case_globals)]
static Nr: usize = 10;

/// Number of 32-bit words comprising the Cipher Key. For this implementation, Nk = 4.
#[allow(non_upper_case_globals)]
static Nk: usize = 4;

/// Non-linear substitution table used in several byte substitution transformations and in the
/// Key Expansion routine to perform a onefor-one substitution of a byte value.
static S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

/// Inverse of the S-BOX. Used in the InvSubBytes step to perform reverse one-for-one substitution
/// of a byte.
static INVERSE_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

/// The round constant word array.
#[allow(non_upper_case_globals)]
static Rcon: [[u8; 4]; 10] = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
];

/// At the start of the Cipher, the input is copied to the State array using the conventions
/// described in Sec. 3.4. After an initial Round Key addition, the State array is transformed by
/// implementing a round function 10, 12, or 14 times (depending on the key length), with the
/// final round differing slightly from the first Nr -1 rounds. The final State is then copied to
/// the output as described in Sec. 3.4.
pub fn encrypt_aes_128_in_ecb_mode(bytes: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let w = key_expansion(key);
    let mut blocks = bytes_to_blocks(bytes);
    let mut cipher_blocks: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());

    for block in blocks.iter() {
        let mut state = block_to_state(block);

        state = add_round_key(&state, &w[0..Nb].to_vec());

        for round in 1..Nr {
            state = sub_bytes(&state);
            state = shift_rows(&state);
            state = mix_columns(&state);
            state = add_round_key(&state, &w[round * Nb..(round + 1) * Nb].to_vec());
        }

        state = sub_bytes(&state);
        state = shift_rows(&state);
        state = add_round_key(&state, &w[Nr * Nb..(Nr + 1) * Nb].to_vec());

        cipher_blocks.push(state_to_block(&state));
    }

    cipher_blocks.iter()
        .fold(Vec::new(), |acc, line| [acc.as_slice(), line.as_slice()].concat())
}

/// The Cipher transformations in Sec. 5.1 can be inverted and then implemented in reverse order to
/// produce a straightforward Inverse Cipher for the AES algorithm. The individual transformations
/// used in the Inverse Cipher - InvShiftRows(), InvSubBytes(),InvMixColumns(),
/// and AddRoundKey() – process the State and are described in the following subsections.
pub fn decrypt_aes_128_in_ecb_mode(cipher: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let w = key_expansion(key);
    let mut blocks = bytes_to_blocks(cipher);
    let mut decrypted_blocks: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());

    for block in blocks.iter() {
        let mut state = block_to_state(block);

        state = add_round_key(&state, &w[Nr * Nb..(Nr + 1) * Nb].to_vec());

        for round in (1..Nr).rev() {
            state = inv_shift_rows(&state);
            state = inv_sub_bytes(&state);
            state = add_round_key(&state, &w[round * Nb..(round + 1) * Nb].to_vec());
            state = inv_mix_columns(&state);
        }

        state = inv_shift_rows(&state);
        state = inv_sub_bytes(&state);
        state = add_round_key(&state, &w[0..Nb].to_vec());

        decrypted_blocks.push(state_to_block(&state));
    }

    decrypted_blocks.iter()
        .fold(Vec::new(), |acc, line| [acc.as_slice(), line.as_slice()].concat())
}

fn bytes_to_blocks(bytes: &Vec<u8>) -> Vec<Vec<u8>> {
    let mut blocks = vec![vec![0; 16]; bytes.len() / 16];
    for (i, byte) in bytes.iter().enumerate() {
        blocks[(i as f32 / 16 as f32).floor() as usize][i % 16] = *byte;
    }

    blocks
}

fn block_to_state(block: &Vec<u8>) -> Vec<Vec<u8>> {
    let mut state: Vec<Vec<u8>> = vec![vec![0; 4]; 4];
    for r in 0..4 {
        for c in 0..Nb {
            state[c][r] = block[r + 4 * c];
        }
    }

    state
}

fn state_to_block(state: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0; 4 * Nb];
    for r in 0..4 {
        for c in 0..Nb {
            out[r + 4 * c] = state[c][r];
        }
    }

    out
}

/// Routine used to generate a series of Round Keys from the Cipher Key.
/// The Key Expansion generates a total of Nb (Nr + 1) words: the algorithm requires
/// an initial set of Nb words, and each of the Nr rounds requires Nb words of key data. The
/// resulting key schedule consists of a linear array of 4-byte words, denoted [wi ], with i in
/// the range 0 <= i < Nb(Nr + 1).
fn key_expansion(key: &[u8]) -> Vec<Vec<u8>> {
    let mut w: Vec<Vec<u8>> = vec![vec![0; Nk]; Nb * (Nr + 1)];

    for i in 0..Nk {
        w[i] = key[4 * i..4 * i + 4].to_vec();
    }

    #[allow(unused_assignments)]
        let mut temp: Vec<u8> = Vec::with_capacity(Nk);
    for i in Nk..(Nb * (Nr + 1)) {
        temp = w[i - 1].to_vec();
        if i % Nk == 0 {
            temp = xor::fixed_key_xor(
                &sub_word(&rot_word(temp.as_slice())),
                &Rcon[(i / Nk) - 1].to_vec(),
            ).to_vec();
        } else if Nk > 6 && i % Nk == 4 {
            temp = sub_word(temp.as_slice());
        }
        w[i] = xor::fixed_key_xor(&w[i - Nk], &temp).to_vec();
    }

    w.iter()
        .map(|v| v.to_vec())
        .collect()
}

/// Transformation in the Cipher and Inverse Cipher in which a Round
/// Key is added to the State using an XOR operation. The length of a
/// Round Key equals the size of the State (i.e., for Nb = 4, the Round
/// Key length equals 128 bits/16 bytes).
fn add_round_key(state: &Vec<Vec<u8>>, round_key: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut xored_state: Vec<Vec<u8>> = vec![vec![0; 4]; 4];
    for r in 0..4 {
        for c in 0..4 {
            xored_state[r][c] = state[r][c] ^ round_key[r][c];
        }
    }

    xored_state
}

/// Transformation in the Cipher that processes the State using a nonlinear byte
/// substitution table (S-box) that operates on each of the State bytes
/// independently.
fn sub_bytes(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    sub_bytes_with_box(&state, &S_BOX)
}

/// Transformation in the Inverse Cipher that is the inverse of
fn inv_sub_bytes(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    sub_bytes_with_box(&state, &INVERSE_S_BOX)
}

fn sub_bytes_with_box(state: &Vec<Vec<u8>>, substitution_box: &[u8; 256]) -> Vec<Vec<u8>> {
    let mut substituted_bytes: Vec<Vec<u8>> = vec![vec![0; 4]; 4];
    for (i, row) in state.iter().enumerate() {
        for (j, byte) in row.iter().enumerate() {
            substituted_bytes[i][j] = substitution_box[*byte as usize];
        }
    }

    substituted_bytes
}

/// Transformation in the Cipher that processes the State by cyclically
/// shifting the last three rows of the State by different offsets.
fn shift_rows(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    vec![
        vec![state[0][0], state[1][1], state[2][2], state[3][3]],
        vec![state[1][0], state[2][1], state[3][2], state[0][3]],
        vec![state[2][0], state[3][1], state[0][2], state[1][3]],
        vec![state[3][0], state[0][1], state[1][2], state[2][3]],
    ]
}

/// Transformation in the Inverse Cipher that is the inverse of inv_shift_rows
fn inv_shift_rows(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    vec![
        vec![state[0][0], state[3][1], state[2][2], state[1][3]],
        vec![state[1][0], state[0][1], state[3][2], state[2][3]],
        vec![state[2][0], state[1][1], state[0][2], state[3][3]],
        vec![state[3][0], state[2][1], state[1][2], state[0][3]],
    ]
}

/// Transformation in the Cipher that takes all of the columns of the
/// State and mixes their data (independently of one another) to
/// produce new columns.
fn mix_columns(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let fixed_polynomial = vec![
        vec![0x02, 0x03, 0x01, 0x01],
        vec![0x01, 0x02, 0x03, 0x01],
        vec![0x01, 0x01, 0x02, 0x03],
        vec![0x03, 0x01, 0x01, 0x02],
    ];
    mix_columns_using_substitution_matrix(&state, &fixed_polynomial)
}

/// Transformation in the Inverse Cipher that is the inverse of mix_columns()
fn inv_mix_columns(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let fixed_polynomial = vec![
        vec![0x0e, 0x0b, 0x0d, 0x09],
        vec![0x09, 0x0e, 0x0b, 0x0d],
        vec![0x0d, 0x09, 0x0e, 0x0b],
        vec![0x0b, 0x0d, 0x09, 0x0e],
    ];

    mix_columns_using_substitution_matrix(&state, &fixed_polynomial)
}

fn mix_columns_using_substitution_matrix(state: &Vec<Vec<u8>>, substitution_matrix: &Vec<Vec<u8>>)
                                         -> Vec<Vec<u8>> {
    let mut result = vec![vec![0; 4]; 4];
    for c in 0..4 {
        for r in 0..4 {
            let mut multiplications_xor = 0;
            for i in 0..4 {
                multiplications_xor ^= multiply_in_g(substitution_matrix[r][i], state[c][i])
            }
            result[c][r] = multiplications_xor
        }
    }

    result
}

/// Adapted from https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
/// In the polynomial representation, multiplication in GF(2^8) (denoted by •) corresponds with the
/// multiplication of polynomials modulo an irreducible polynomial of degree 8. A polynomial is
/// irreducible if its only divisors are one and itself
fn multiply_in_g(polynomial_value: u8, state_value: u8) -> u8 {
    let irreducible_polynomial = 0x1b;
    let mut a = polynomial_value;
    let mut b = state_value;
    let mut p = 0;

    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }

        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= irreducible_polynomial;
        }
        b >>= 1;
    }

    p
}

/// Function used in the Key Expansion routine that takes a four-byte
/// word and performs a cyclic permutation.
fn rot_word(word: &[u8]) -> Vec<u8> {
    assert_eq!(word.len(), 4);

    [&word[1..], &[word[0]]].concat()
}

/// Function used in the Key Expansion routine that takes a four-byte
/// input word and applies an S-box to each of the four bytes to
/// produce an output word.
fn sub_word(word: &[u8]) -> Vec<u8> {
    assert_eq!(word.len(), 4);

    word.iter().map(|word| S_BOX[*word as usize]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot_word_test() {
        let word: &[u8] = &[0, 1, 2, 3];
        let expected_word: &[u8] = &[1, 2, 3, 0];

        let given_word = rot_word(word);
        assert_eq!(given_word.as_slice(), expected_word);
    }

    #[test]
    fn sub_word_test() {
        let word: &[u8] = &[0, 1, 2, 3];
        let expected_word: &[u8] = &[0x63, 0x7c, 0x77, 0x7b];

        let given_word = sub_word(word);

        assert_eq!(given_word.as_slice(), expected_word);
    }

    #[test]
    fn add_round_key_test() {
        let key_schedule = vec![
            vec![0x13, 0x11, 0x1d, 0x7f],
            vec![0xe3, 0x94, 0x4a, 0x17],
            vec![0xf3, 0x07, 0xa7, 0x8b],
            vec![0x4d, 0x2b, 0x30, 0xc5]
        ];
        let state = vec![
            vec![0x69, 0xc4, 0xe0, 0xd8],
            vec![0x6a, 0x7b, 0x04, 0x30],
            vec![0xd8, 0xcd, 0xb7, 0x80],
            vec![0x70, 0xb4, 0xc5, 0x5a]
        ];
        let expected_state: Vec<Vec<u8>> = vec![
            vec![0x7a, 0xd5, 0xfd, 0xa7],
            vec![0x89, 0xef, 0x4e, 0x27],
            vec![0x2b, 0xca, 0x10, 0x0b],
            vec![0x3d, 0x9f, 0xf5, 0x9f]
        ];

        let actual_state = add_round_key(&state, &key_schedule);

        assert_eq!(actual_state, expected_state);
    }

    #[test]
    fn inv_mix_columns_test() {
        let test_cases: Vec<(Vec<Vec<u8>>, Vec<Vec<u8>>)> = vec![
            (vec![
                vec![0xbd, 0x6e, 0x7c, 0x3d],
                vec![0xf2, 0xb5, 0x77, 0x9e],
                vec![0x0b, 0x61, 0x21, 0x6e],
                vec![0x8b, 0x10, 0xb6, 0x89]
            ], vec![
                vec![0x47, 0x73, 0xb9, 0x1f],
                vec![0xf7, 0x2f, 0x35, 0x43],
                vec![0x61, 0xcb, 0x01, 0x8e],
                vec![0xa1, 0xe6, 0xcf, 0x2c]
            ]),
            (vec![
                vec![0xfd, 0xe3, 0xba, 0xd2],
                vec![0x05, 0xe5, 0xd0, 0xd7],
                vec![0x35, 0x47, 0x96, 0x4e],
                vec![0xf1, 0xfe, 0x37, 0xf1]
            ], vec![
                vec![0x2d, 0x7e, 0x86, 0xa3],
                vec![0x39, 0xd9, 0x39, 0x3e],
                vec![0xe6, 0x57, 0x0a, 0x11],
                vec![0x01, 0x90, 0x4e, 0x16]
            ])
        ];

        for (state, expected_state) in test_cases.iter() {
            let actual_state = inv_mix_columns(state);
            assert_eq!(actual_state, *expected_state);
        }
    }

    #[test]
    fn multiply_in_g_test() {
        let test_cases: Vec<(u8, u8, u8)> = vec![
            (0x57, 0x83, 0xc1),
            (0x57, 0x13, 0xfe),
            (0x57, 0x02, 0xae),
            (0x57, 0x04, 0x47),
            (0x57, 0x08, 0x8e),
            (0x57, 0x10, 0x07)
        ];

        for (a, b, expected) in test_cases.iter() {
            let actual_result = multiply_in_g(*a, *b);
            assert_eq!(actual_result, *expected);
        }
    }

    #[test]
    fn inv_shift_rows_test() {
        let state = vec![
            vec![0x7a, 0xd5, 0xfd, 0xa7],
            vec![0x89, 0xef, 0x4e, 0x27],
            vec![0x2b, 0xca, 0x10, 0x0b],
            vec![0x3d, 0x9f, 0xf5, 0x9f]
        ];
        let expected_state = vec![
            vec![0x7a, 0x9f, 0x10, 0x27],
            vec![0x89, 0xd5, 0xf5, 0x0b],
            vec![0x2b, 0xef, 0xfd, 0x9f],
            vec![0x3d, 0xca, 0x4e, 0xa7]
        ];

        let actual_state = inv_shift_rows(&state);

        assert_eq!(actual_state, expected_state);
    }

    #[test]
    fn inv_sub_bytes_test() {
        let state = vec![
            vec![0x7a, 0x9f, 0x10, 0x27],
            vec![0x89, 0xd5, 0xf5, 0x0b],
            vec![0x2b, 0xef, 0xfd, 0x9f],
            vec![0x3d, 0xca, 0x4e, 0xa7]
        ];
        let expected_state = vec![
            vec![0xbd, 0x6e, 0x7c, 0x3d],
            vec![0xf2, 0xb5, 0x77, 0x9e],
            vec![0x0b, 0x61, 0x21, 0x6e],
            vec![0x8b, 0x10, 0xb6, 0x89]
        ];

        let actual_state = inv_sub_bytes(&state);

        assert_eq!(actual_state, expected_state);
    }

    #[test]
    fn key_expansion_test() {
        // as provided in official paper
        let key: &[u8] = &[
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        ];
        // also known as w
        let expected_key_schedule = [
            // copy of key
            &[0x2b, 0x7e, 0x15, 0x16],
            &[0x28, 0xae, 0xd2, 0xa6],
            &[0xab, 0xf7, 0x15, 0x88],
            &[0x09, 0xcf, 0x4f, 0x3c],

            // rest of expansion
            &[0xa0, 0xfa, 0xfe, 0x17],
            &[0x88, 0x54, 0x2c, 0xb1],
            &[0x23, 0xa3, 0x39, 0x39],
            &[0x2a, 0x6c, 0x76, 0x05],
            &[0xf2, 0xc2, 0x95, 0xf2],
            &[0x7a, 0x96, 0xb9, 0x43],
            &[0x59, 0x35, 0x80, 0x7a],
            &[0x73, 0x59, 0xf6, 0x7f],
            &[0x3d, 0x80, 0x47, 0x7d],
            &[0x47, 0x16, 0xfe, 0x3e],
            &[0x1e, 0x23, 0x7e, 0x44],
            &[0x6d, 0x7a, 0x88, 0x3b],
            &[0xef, 0x44, 0xa5, 0x41],
            &[0xa8, 0x52, 0x5b, 0x7f],
            &[0xb6, 0x71, 0x25, 0x3b],
            &[0xdb, 0x0b, 0xad, 0x00],
            &[0xd4, 0xd1, 0xc6, 0xf8],
            &[0x7c, 0x83, 0x9d, 0x87],
            &[0xca, 0xf2, 0xb8, 0xbc],
            &[0x11, 0xf9, 0x15, 0xbc],
            &[0x6d, 0x88, 0xa3, 0x7a],
            &[0x11, 0x0b, 0x3e, 0xfd],
            &[0xdb, 0xf9, 0x86, 0x41],
            &[0xca, 0x00, 0x93, 0xfd],
            &[0x4e, 0x54, 0xf7, 0x0e],
            &[0x5f, 0x5f, 0xc9, 0xf3],
            &[0x84, 0xa6, 0x4f, 0xb2],
            &[0x4e, 0xa6, 0xdc, 0x4f],
            &[0xea, 0xd2, 0x73, 0x21],
            &[0xb5, 0x8d, 0xba, 0xd2],
            &[0x31, 0x2b, 0xf5, 0x60],
            &[0x7f, 0x8d, 0x29, 0x2f],
            &[0xac, 0x77, 0x66, 0xf3],
            &[0x19, 0xfa, 0xdc, 0x21],
            &[0x28, 0xd1, 0x29, 0x41],
            &[0x57, 0x5c, 0x00, 0x6e],
            &[0xd0, 0x14, 0xf9, 0xa8],
            &[0xc9, 0xee, 0x25, 0x89],
            &[0xe1, 0x3f, 0x0c, 0xc8],
            &[0xb6, 0x63, 0x0c, 0xa6]
        ];

        let given_key_schedule = key_expansion(key);

        assert_eq!(given_key_schedule.to_vec(), expected_key_schedule.to_vec());
    }

    #[test]
    fn decrypt_aes_128_in_ecb_mode_nist_test_case() {
        let cipher = vec![
            0x69, 0xc4, 0xe0, 0xd8,
            0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80,
            0x70, 0xb4, 0xc5, 0x5a
        ];
        let key = vec![
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        ];
        let expected_raw = vec![
            0x0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        ];
        let actual_raw = decrypt_aes_128_in_ecb_mode(&cipher, &key);

        assert_eq!(actual_raw, expected_raw);
    }

    #[test]
    fn encrypt_aes_128_in_ecb_mode_test_case() {
        let raw = vec![
            0x0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        ];
        let key = vec![
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        ];
        let expected_cipher = vec![
            0x69, 0xc4, 0xe0, 0xd8,
            0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80,
            0x70, 0xb4, 0xc5, 0x5a
        ];
        let actual_cipher = encrypt_aes_128_in_ecb_mode(&raw, &key);

        assert_eq!(actual_cipher, expected_cipher);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let raw = vec![
            0x0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        ];
        let key = vec![
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        ];
        let cipher = encrypt_aes_128_in_ecb_mode(&raw, &key);
        let actual_deciphered = decrypt_aes_128_in_ecb_mode(&cipher, &key);

        assert_eq!(raw, actual_deciphered);
    }
}