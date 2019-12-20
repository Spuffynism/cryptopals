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

pub fn fixed_key_xor_slice<'a>(input: &[u8], key: &[u8]) -> &'a [u8] {
    let mut result: &mut [u8] = &mut [];

    for (i, item) in input.iter().enumerate() {
        result[i] = item ^ key[i % key.len()];
    }

    return result;
}