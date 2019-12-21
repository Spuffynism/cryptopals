pub fn fixed_xor(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    assert_eq!(input.len(), key.len());

    return fixed_key_xor(input, key);
}

pub fn single_byte_xor(input: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for item in input.iter() {
        result.push(item ^ key);
    }

    return result;
}

pub fn fixed_key_xor(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for (i, item) in input.iter().enumerate() {
        result.push(item ^ key[i % key.len()]);
    }

    return result;
}

/*pub fn fixed_key_xor_slice(input: &[u8], key: &[u8]) -> Vec<u8> {
    let result: &mut [u8] = &mut vec![0; input.len()];

    for (i, _) in input.iter().enumerate() {
        result[i] = input[i] ^ key[i % key.len()];
    }

    result.to_vec()
}*/
