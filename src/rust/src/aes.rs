use xor;
use std::borrow::Borrow;

static AES_128_BLOCK_SIZE_IN_BYTES: i32 = 16;

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

static RCON: [[u8; 4]; 10] = [
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
//pub fn encrypt_aes_128_in_ecb_mode(cipher: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {}

pub fn decrypt_aes_128_in_ecb_mode<'a>(cipher: &[u8], key: &[u8]) -> &'a [u8] {
    let Nb = 4;
    let Nr = 10;
    let w = key_expansion(key);
    let blocks = cipher.windows(AES_128_BLOCK_SIZE_IN_BYTES as usize);
    let decrypted_blocks: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());

    for block in blocks {
        let state: &[&[u8]] = &[
            &[block[0], block[1], block[2], block[3]],
            &[block[4], block[5], block[6], block[7]],
            &[block[8], block[9], block[10], block[11]],
            &[block[12], block[13], block[14], block[15]]
        ];

        //state = add_round_key(state, &w[3]).as_ref();

        for round in 9..0 {
            println!("{}", round);
        }
        /*add_round_key();

        for i in 0..(10 - 1) {
            do_round();
        }

        do_final_round();*/
    }

    return &[];
}

fn key_expansion(key: &[u8]) -> Vec<Vec<u8>> {
    let Nk = 4;
    let Nb = 4;
    let Nr = 10;
    let mut w: Vec<Vec<u8>> = vec![vec![0; 4]; 44];

    for i in 0..Nk {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]].to_vec();
    }

    let mut temp: Vec<u8> = Vec::new();
    for i in Nk..(Nb * (Nr + 1)) {
        temp = w[i - 1].to_vec();
        if i % Nk == 0 {
            temp = xor::fixed_key_xor(&sub_word(&rot_word(temp.as_slice())), &RCON[(i / Nk) - 1]
                .to_vec())
                .to_vec();
        } else if Nk > 6 && i % Nk == 4 {
            temp = sub_word(temp.as_slice());
        }
        w[i] = xor::fixed_key_xor(&w[i - Nk], &temp).to_vec();
    }

    w.iter()
        .map(|v| v.to_vec())
        .collect()
}

fn do_round() {
    sub_bytes();
    shift_rows();
    mix_columns();
    //add_round_key();
}

fn do_final_round() {
    sub_bytes();
    mix_columns();
    //add_round_key();
}

/*fn calculate_round_key(key: &Vec<u8>) -> Vec<u8> {
    let mut w = key.windows((key.len() as f64).sqrt() as usize);
}*/

fn decrypt_block(block: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    ecb_encrypt(block, key)
}

fn ecb_encrypt(cipher: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    xor::fixed_key_xor(cipher, key)
}

// 1 time & last of n times

/// Transformation in the Cipher and Inverse Cipher in which a Round
/// Key is added to the State using an XOR operation. The length of a
/// Round Key equals the size of the State (i.e., for Nb = 4, the Round
/// Key length equals 128 bits/16 bytes).
fn add_round_key(state: &[&[u8]], key: &[u8]) -> Vec<Vec<u8>> {
    let mut xored_state: Vec<Vec<u8>> = vec![vec![0; 4]; 4];
    for (i, rows) in state.iter().enumerate() {
        for (j, _) in rows.iter().enumerate() {
            xored_state[i][j] = state[i][j] ^ key[i];
        }
    }

    return xored_state;
}

/// Transformation in the Cipher that processes the State using a nonlinear byte
/// substitution table (S-box) that operates on each of the State bytes
/// independently.
fn sub_bytes() {}

// Transformation in the Inverse Cipher that is the inverse of
fn inv_sub_bytes() {}

/// Transformation in the Cipher that processes the State by cyclically
/// shifting the last three rows of the State by different offsets.
fn shift_rows() {}

// Transformation in the Inverse Cipher that is the inverse of inv_shift_rows
fn inv_shift_rows() {}

/// Transformation in the Cipher that takes all of the columns of the
/// State and mixes their data (independently of one another) to
/// produce new columns.
fn mix_columns() {}

// Transformation in the Inverse Cipher that is the inverse of mix_columns()
fn inv_mix_columns() {}

/// Function used in the Key Expansion routine that takes a four-byte
/// word and performs a cyclic permutation.
fn rot_word(word: &[u8]) -> Vec<u8> {
    assert_eq!(word.len(), 4);

    [word[1], word[2], word[3], word[0]].to_vec()
}

/// Function used in the Key Expansion routine that takes a four-byte
/// input word and applies an S-box to each of the four bytes to
/// produce an output word.
fn sub_word(word: &[u8]) -> Vec<u8> {
    assert_eq!(word.len(), 4);

    [S_BOX[word[0] as usize], S_BOX[word[1] as usize], S_BOX[word[2] as usize], S_BOX[word[3] as
        usize]].to_vec()
}

fn multiplication_in_gf28(i: u8, j: u8) -> u8 {
    let irreducible_polynomial: u16 = 0x011b;
    println!("{}", irreducible_polynomial);
    ((i as u16 * j as u16) % irreducible_polynomial) as u8
}

#[cfg(test)]
mod tests {
    use aes::{multiplication_in_gf28, rot_word, sub_word, add_round_key, key_expansion};

    /// (x) - Multiplication of two polynomials (each with degree < 4) modulo x^4 + 1
    #[test]
    fn calculate_round_key_test() {}

    #[test]
    fn multiplication_in_gf28_test() {
        let first = 0x57;
        let second = 0x83;
        let expected_result: u8 = 0xc1;

        let given_result = multiplication_in_gf28(first, second);
        assert_eq!(given_result, expected_result);
    }

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
        let state: &[&[u8]] = &[
            &[0b0000, 0b0001, 0b0010, 0b0011],
            &[0b0100, 0b0101, 0b0110, 0b0111],
            &[0b1000, 0b1001, 0b1010, 0b1011],
            &[0b1100, 0b1101, 0b1110, 0b1111],
        ];
        let key: &[u8] = &[0b0000, 0b0001, 0b0010, 0b0100];
        let expected_state: &[&[u8]] = &[
            &[0b0000, 0b0001, 0b0010, 0b0011],
            &[0b0101, 0b0100, 0b0111, 0b0110],
            &[0b1010, 0b1011, 0b1000, 0b1001],
            &[0b1000, 0b1001, 0b1010, 0b1011],
        ];

        let given_state = add_round_key(state, key);

        assert_eq!(given_state, expected_state);
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
    fn repl() {}
}