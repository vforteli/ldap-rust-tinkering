use byteorder::{BigEndian, ByteOrder};

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

/*

/// <summary>
        /// Convert integer length to a byte array with BER encoding
        /// https://en.wikipedia.org/wiki/X.690#BER_encoding
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] IntToBerLength(int length)
        {
            // Short notation
            if (length <= 127)
            {
                return new byte[] { (byte)length };
            }
            // Long notation
            else
            {
                var intbytes = BitConverter.GetBytes(length);
                Array.Reverse(intbytes);

                byte intbyteslength = (byte)intbytes.Length;


                var lengthByte = intbyteslength + 128;
                var berBytes = new byte[1 + intbyteslength];
                berBytes[0] = (byte)lengthByte;
                Buffer.BlockCopy(intbytes, 0, berBytes, 1, intbyteslength);
                return berBytes;
            }
        }


        /// <summary>
        /// Convert BER encoded length at offset to an integer
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <param name="offset">Offset where the BER encoded length is located</param>
        /// <param name="berByteCount">Number of bytes used to represent BER encoded length</param>
        /// <returns></returns>
        public static int BerLengthToInt(byte[] bytes, int offset, out int berByteCount)
        {
            var stream = new MemoryStream(bytes, offset, bytes.Length - offset, false);
            return BerLengthToInt(stream, out berByteCount);
        }


        /// <summary>
        /// Get a BER length from a stream
        /// </summary>
        /// <param name="stream">Stream at position where BER length should be found</param>
        /// <param name="berByteCount">Number of bytes used to represent BER encoded length</param>
        /// <returns></returns>
        public static int BerLengthToInt(Stream stream, out int berByteCount)
        {
            berByteCount = 1;   // The minimum length of a ber encoded length is 1 byte
            int attributeLength = 0;
            var berByte = new byte[1];
            stream.Read(berByte, 0, 1);
            if (berByte[0] >> 7 == 1)    // Long notation, first byte tells us how many bytes are used for the length
            {
                var lengthoflengthbytes = berByte[0] & 127;
                var lengthBytes = new byte[lengthoflengthbytes];
                stream.Read(lengthBytes, 0, lengthoflengthbytes);
                Array.Reverse(lengthBytes);
                Array.Resize(ref lengthBytes, 4);   // this will of course explode if length is larger than a 32 bit integer
                attributeLength = BitConverter.ToInt32(lengthBytes, 0);
                berByteCount += lengthoflengthbytes;
            }
            else // Short notation, length contained in the first byte
            {
                attributeLength = berByte[0] & 127;
            }

            return attributeLength;
        }*/

#[cfg(test)]
mod tests {
    use super::*;

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

    fn test_int_to_ber_length(int_value: i32, expected_hex_string: &str) {
        let actual = int_to_ber_length(int_value);
        let expected = hex::decode(expected_hex_string).unwrap();

        assert_eq!(actual, expected);
    }
}
