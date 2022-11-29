use crate::tag::Tag;

pub struct LdapAttribute {
    tag: Tag,
    value: Option<Vec<u8>>,
}

impl LdapAttribute {
    pub fn new(tag: Tag, value: Option<Vec<u8>>) -> Self {
        Self { tag, value }
    }

    pub fn get_bytes(self) -> Vec<u8> {
        // todo make this recursive

        let mut bytes: Vec<u8> = Vec::new();
        let tag_byte: u8 = self.tag.into();

        bytes.extend([tag_byte]);

        match self.value {
            Some(v) => {
                bytes.extend([v.len() as u8].to_vec());
                bytes.extend(v)
            }
            None => (),
        }

        bytes
    }
}

#[cfg(test)]
mod tests {

    use byteorder::{BigEndian, ByteOrder};

    use crate::{
        ldap_operation::LdapOperation, tag::TagValue, universal_data_type::UniversalDataType,
    };

    use super::*;

    #[test]
    fn test_create_bind_request_attribute() {
        let attribute = LdapAttribute::new(
            Tag::Application(TagValue {
                value: LdapOperation::BindRequest,
                is_constructed: false,
            }),
            None,
        );

        match attribute.tag {
            Tag::Application(t) => assert_eq!(t.value, LdapOperation::BindRequest),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_get_bytes_octet_string() {
        let expected_bytes = hex::decode("041364633d6b6172616b6f72756d2c64633d6e6574").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::OctetString,
                is_constructed: false,
            }),
            Some("dc=karakorum,dc=net".as_bytes().to_vec()),
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_boolean_true() {
        let expected_bytes = hex::decode("010101").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Boolean,
                is_constructed: false,
            }),
            Some([true as u8].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_boolean_false() {
        let expected_bytes = hex::decode("010100").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Boolean,
                is_constructed: false,
            }),
            Some([false as u8].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_integer_1() {
        let expected_bytes = hex::decode("020101").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Integer,
                is_constructed: false,
            }),
            Some([1].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_integer_2() {
        let expected_bytes = hex::decode("020102").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Integer,
                is_constructed: false,
            }),
            Some([2].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_integer_max() {
        let expected_bytes = hex::decode("02047fffffff").unwrap();

        let mut buffer: [u8; 4] = [0; 4];
        BigEndian::write_i32(&mut buffer, i32::MAX);

        let attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Integer,
                is_constructed: false,
            }),
            Some(buffer.to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }
}
