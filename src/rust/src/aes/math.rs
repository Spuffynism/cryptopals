/// Adapted from https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
/// In the polynomial representation, multiplication in GF(2^8) (denoted by •) corresponds with the
/// multiplication of polynomials modulo an irreducible polynomial of degree 8. A polynomial is
/// irreducible if its only divisors are one and itself
pub fn multiply_in_g(polynomial_value: u8, state_value: u8) -> u8 {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}