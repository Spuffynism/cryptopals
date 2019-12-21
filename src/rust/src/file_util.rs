use std::fs;

use ::vs;

pub fn read_hex_file_lines(path: &str) -> Vec<Vec<u8>> {
    let content = fs::read_to_string("./resources/4.txt").expect("Can't read file.");

    content
        .split("\n")
        .map(|line| vs!(line))
        .collect::<Vec<Vec<u8>>>()
}

pub fn read_base64_file_bytes(path: &str) -> Vec<u8> {
    let content = fs::read_to_string(path).expect("Can't read file.");

    content
        .split("\n")
        .map(|line| base64::decode(line).unwrap())
        .collect::<Vec<Vec<u8>>>()
        .iter()
        .fold(Vec::new(), |acc, line| [acc.as_slice(), line.as_slice()].concat())
}