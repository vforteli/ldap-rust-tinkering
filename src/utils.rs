use byteorder::{BigEndian, ByteOrder};

pub struct BerLengthResult {
    value: i32,
    bytes_consumed: usize,
}

pub fn int_to_ber_length(value: i32) -> Vec<u8> {
    if value <= 127 {
        [value as u8].to_vec()
    } else {
        // wasting precious bytes when this could be represented with the 0 bytes truncated
        let mut bytes: [u8; 5] = [0; 5];
        bytes[0] = 4 + 128;
        BigEndian::write_i32(&mut bytes[1..5], value);

        bytes.to_vec()
    }
}

/// Convert ber length bytes to i32 and how many bytes were used
pub fn ber_length_to_i32(ber_length_bytes: Vec<u8>) -> BerLengthResult {
    let short_length = ber_length_bytes[0] & 127;

    match ber_length_bytes[0] >> 7 {
        1 => {
            let length_bytes = &ber_length_bytes[1..(short_length + 1).into()];
            let mut long_length_bytes: [u8; 4] = [0; 4];
            long_length_bytes[..short_length.into()].copy_from_slice(&length_bytes);

            BerLengthResult {
                bytes_consumed: (1 + short_length).into(),
                value: BigEndian::read_i32(&long_length_bytes),
            }
        }
        _ => BerLengthResult {
            bytes_consumed: 1,
            value: short_length.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ber_length_to_i32_short_01() {
        test_ber_length_to_i32("01", 1, 1)
    }

    #[test]
    fn test_ber_length_to_i32_short_02() {
        test_ber_length_to_i32("7f", 127, 1)
    }

    #[test]
    fn test_ber_length_to_i32_01() {
        test_ber_length_to_i32("8400000159", 345, 5)
    }

    #[test]
    fn test_ber_length_to_i32_02() {
        test_ber_length_to_i32("840000014f", 335, 5)
    }

    #[test]
    fn test_ber_length_to_i32_03() {
        test_ber_length_to_i32("840000012b", 299, 5)
    }
    #[test]
    fn test_ber_length_to_i32_04() {
        test_ber_length_to_i32("847fffffff", i32::MAX, 5)
    }

    fn test_ber_length_to_i32(hex_bytes: &str, expected_i32: i32, bytes_used: usize) {
        let actual = ber_length_to_i32(hex::decode(hex_bytes).unwrap());

        assert_eq!(actual.value, expected_i32);
        assert_eq!(actual.bytes_consumed, bytes_used);
    }

    #[test]
    fn test_int_to_ber_length_short_01() {
        test_int_to_ber_length(1, "01");
    }

    #[test]
    fn test_int_to_ber_length_short_02() {
        test_int_to_ber_length(127, "7f");
    }

    #[test]
    fn test_int_to_ber_length_long_01() {
        test_int_to_ber_length(128, "8400000080");
    }

    #[test]
    fn test_int_to_ber_length_long_02() {
        test_int_to_ber_length(345, "8400000159");
    }

    #[test]
    fn test_int_to_ber_length_long_03() {
        test_int_to_ber_length(335, "840000014f");
    }

    #[test]
    fn test_int_to_ber_length_long_04() {
        test_int_to_ber_length(299, "840000012b");
    }

    #[test]
    fn test_int_to_ber_length_long_05() {
        test_int_to_ber_length(i32::MAX, "847fffffff");
    }

    fn test_int_to_ber_length(int_value: i32, expected_hex_string: &str) {
        let actual = int_to_ber_length(int_value);
        let expected = hex::decode(expected_hex_string).unwrap();

        assert_eq!(actual, expected);
    }
}
