pub static ALPHABET: [char; 84] = [
    '\n', '\r', '\t',
    ' ', '!', '"', '$', '%', '&', '\'', '(', ')', ',',
    '-', '.', '/', '=', '@',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ':', ';', '?',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '\\',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

pub fn calculate_human_resemblance_score(input: &[u8]) -> f32 {
    let human_characters_count = input.iter()
        .filter(|byte| ALPHABET.contains(&(**byte as char)))
        .count();

    human_characters_count as f32 / input.len() as f32
}