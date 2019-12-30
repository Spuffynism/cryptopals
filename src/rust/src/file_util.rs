use std::fs;

use ::vs;
use hex;

pub fn read_file_lines(path: &str) -> Vec<Vec<u8>> {
    read_resource_lines(path)
        .iter()
        .map(|line| vs!(line))
        .collect::<Vec<Vec<u8>>>()
}

pub fn read_file_bytes(path: &str) -> Vec<u8> {
    read_file_lines(path)
        .iter()
        .fold(Vec::new(), |acc, line| [acc.as_slice(), line.as_slice()].concat())
}

pub fn read_hex_file_lines(path: &str) -> Vec<Vec<u8>> {
    read_resource_lines(path)
        .iter()
        .map(|line| hex::hex_to_bytes(&vs!(line)))
        .collect::<Vec<Vec<u8>>>()
}

pub fn read_base64_file_lines(path: &str) -> Vec<Vec<u8>> {
    read_resource_lines(path)
        .iter()
        .map(|line| base64::decode(line).unwrap())
        .collect()
}

pub fn read_base64_file_bytes(path: &str) -> Vec<u8> {
    read_base64_file_lines(path)
        .iter()
        .fold(Vec::new(), |acc, line| [acc.as_slice(), line.as_slice()].concat())
}

fn read_resource_lines(path: &str) -> Vec<String> {
    let content = fs::read_to_string(path).expect("Can't read file.");

    content.split("\r\n")
        .flat_map(|s| s.split("\n"))
        .map(|str| String::from(str))
        .collect::<Vec<String>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_resource_lines_test() {
        let path = "./test_resources/test.txt";
        let expected_content: Vec<String> = vec![
            "3a36363a732e32ea3f0e430508204b332c382a19292d5b291122e123446a".to_string(),
            "2d3c230a1e5a300f6c3e26ed0d1709434950fd6f1e121335054129e4e4ec".to_string(),
            "".to_string()
        ];

        let actual_content = read_resource_lines(path);

        assert_eq!(actual_content, expected_content);
    }
}