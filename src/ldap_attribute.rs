use byteorder::{BigEndian, ByteOrder};

use crate::{
    ldap_error, ldap_operation::LdapOperation, ldap_result::LdapResult, tag::Tag,
    universal_data_type::UniversalDataType, utils,
};

// todo convert all unwraps etc to something which checks for errors...

#[derive(Debug, PartialEq, Clone)]
pub enum LdapValue {
    Primitive(Vec<u8>),
    Constructed(Vec<LdapAttribute>),
}

#[derive(Debug, PartialEq, Clone)]
pub struct LdapAttribute {
    pub tag: Tag,
    pub value: LdapValue,
}

impl LdapAttribute {
    pub fn new(tag: Tag, value: LdapValue) -> Self {
        Self { tag, value }
    }

    /// the ldap packet is just a specific type of attribute with a message id
    pub fn new_packet(message_id: i32, attributes: Vec<LdapAttribute>) -> Self {
        let mut buffer: [u8; 4] = [0; 4];
        BigEndian::write_i32(&mut buffer, message_id);

        let message_id_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Integer,
                is_constructed: false,
            },
            LdapValue::Primitive(buffer.to_vec()),
        );

        let mut packet_attributes = vec![message_id_attribute];
        packet_attributes.extend(attributes);

        Self {
            tag: Tag::Universal {
                data_type: UniversalDataType::Sequence,
                is_constructed: true,
            },
            value: LdapValue::Constructed(packet_attributes),
        }
    }

    // shortcut for creating eg a bind response
    pub fn new_result_attribute(operation: LdapOperation, result: LdapResult) -> Self {
        let result_code_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Enumerated,
                is_constructed: false,
            },
            LdapValue::Primitive([result as u8].to_vec()),
        );

        let matched_dn_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::OctetString,
                is_constructed: false,
            },
            LdapValue::Primitive(Vec::new()), // eeh..
        );

        let diagnostic_message_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::OctetString,
                is_constructed: false,
            },
            LdapValue::Primitive(Vec::new()), // eeh..
        );

        LdapAttribute::new(
            Tag::Application {
                operation: operation,
                is_constructed: true,
            },
            LdapValue::Constructed(vec![
                result_code_attribute,
                matched_dn_attribute,
                diagnostic_message_attribute,
            ]),
        )
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut attribute_bytes: Vec<u8> = Vec::new();

        self.get_bytes_recursive(&mut attribute_bytes);

        attribute_bytes
    }

    fn get_bytes_recursive(&self, attribute_bytes: &mut Vec<u8>) {
        attribute_bytes.extend([u8::from(self.tag.clone())]);

        match &self.value {
            LdapValue::Primitive(value) => {
                attribute_bytes.extend(utils::int_to_ber_length(value.len() as i32));
                attribute_bytes.extend(value)
            }
            LdapValue::Constructed(attributes) => {
                let content_bytes = attributes.iter().fold(Vec::new(), |mut bytes, attribute| {
                    bytes.extend(attribute.get_bytes());
                    bytes
                });

                attribute_bytes.extend(utils::int_to_ber_length(content_bytes.len() as i32));
                attribute_bytes.extend(content_bytes)
            }
        }
    }

    pub fn parse(packet_bytes: &[u8]) -> Result<Self, ldap_error::LdapError> {
        let tag: Tag = packet_bytes[0].into();
        println!("got tag! {:?}", tag);

        let length = utils::ber_length_to_i32(&packet_bytes[1..]);
        println!("length stuff! {:?}", length);

        let value_bytes = &packet_bytes
            [(1 + length.bytes_consumed)..(1 + length.bytes_consumed + length.value as usize)];

        if length.value > value_bytes.len().try_into().unwrap() {
            return Err(ldap_error::LdapError::InvalidLength);
        }

        println!("packet length {}", value_bytes.len());

        Ok(LdapAttribute {
            tag,
            value: LdapValue::Constructed(Self::parse_attributes(&value_bytes).unwrap()),
        })
    }

    fn parse_attributes(attribute_bytes: &[u8]) -> Result<Vec<Self>, ldap_error::LdapError> {
        let mut attributes: Vec<LdapAttribute> = Vec::new();

        let mut position: usize = 0;

        while position < attribute_bytes.len() {
            let tag: Tag = attribute_bytes[position].into();
            println!("got tag! {:?}", tag);
            position += 1;

            let length = utils::ber_length_to_i32(&attribute_bytes[position..]);
            position += length.bytes_consumed;

            let attribute_value_length = length.value;

            // todo ugh...
            let is_constructed = match tag {
                Tag::Universal {
                    data_type: _,
                    is_constructed,
                } => is_constructed,
                Tag::Application {
                    operation: _,
                    is_constructed,
                } => is_constructed,
                Tag::Context {
                    value: _,
                    is_constructed,
                } => is_constructed,
                Tag::Private => todo!(),
            };

            let value = if is_constructed {
                let foo = Self::parse_attributes(
                    &attribute_bytes[position..(position + attribute_value_length as usize)]
                        .to_vec(),
                )
                .unwrap();
                LdapValue::Constructed(foo)
            } else {
                let value_bytes =
                    &attribute_bytes[position..(position + attribute_value_length as usize)];

                println!("value: {:?}", value_bytes);
                LdapValue::Primitive(
                    attribute_bytes[position..(position + attribute_value_length as usize)]
                        .to_vec(),
                )
            };

            let attribute = LdapAttribute::new(tag, value);
            attributes.push(attribute);

            position += attribute_value_length as usize;
        }

        Ok(attributes)
    }
}

#[cfg(test)]
mod tests {

    use byteorder::{BigEndian, ByteOrder};

    use crate::{
        ldap_operation::LdapOperation, ldap_result::LdapResult,
        universal_data_type::UniversalDataType,
    };

    use super::*;

    #[test]
    fn test_create_bind_request_attribute() {
        let attribute = LdapAttribute::new(
            Tag::Application {
                operation: LdapOperation::BindRequest,
                is_constructed: false,
            },
            LdapValue::Primitive(Vec::new()),
        );

        match attribute.tag {
            Tag::Application {
                operation,
                is_constructed: _,
            } => assert_eq!(operation, LdapOperation::BindRequest),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_get_bytes_octet_string() {
        let expected_bytes = hex::decode("041364633d6b6172616b6f72756d2c64633d6e6574").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::OctetString,
                is_constructed: false,
            },
            LdapValue::Primitive("dc=karakorum,dc=net".as_bytes().to_vec()),
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_boolean_true() {
        let expected_bytes = hex::decode("010101").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Boolean,
                is_constructed: false,
            },
            LdapValue::Primitive([true as u8].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_boolean_false() {
        let expected_bytes = hex::decode("010100").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Boolean,
                is_constructed: false,
            },
            LdapValue::Primitive([false as u8].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_integer_1() {
        let expected_bytes = hex::decode("020101").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Integer,
                is_constructed: false,
            },
            LdapValue::Primitive([1].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_integer_2() {
        let expected_bytes = hex::decode("020102").unwrap();

        let attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Integer,
                is_constructed: false,
            },
            LdapValue::Primitive([2].to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_integer_max() {
        let expected_bytes = hex::decode("02047fffffff").unwrap();

        let mut buffer: [u8; 4] = [0; 4];
        BigEndian::write_i32(&mut buffer, i32::MAX);

        let attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Integer,
                is_constructed: false,
            },
            LdapValue::Primitive(buffer.to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_parse_bind_request_and_get_bytes() {
        let bind_request_bytes = hex::decode("304c0204000000016044020103042d636e3d62696e64557365722c636e3d55736572732c64633d6465762c64633d636f6d70616e792c64633d636f6d801062696e645573657250617373776f7264").unwrap();

        let packet = LdapAttribute::parse(&bind_request_bytes).unwrap();

        match packet.tag {
            Tag::Universal {
                data_type,
                is_constructed,
            } => {
                assert_eq!(is_constructed, true);
                assert_eq!(data_type, UniversalDataType::Sequence);
            }
            _ => assert!(false),
        }

        match &packet.value {
            LdapValue::Primitive(_) => assert!(false),
            LdapValue::Constructed(attributes) => {
                assert_eq!(attributes.len(), 2);
            }
        }

        let bytes = packet.get_bytes();

        assert_eq!(bytes, bind_request_bytes);
    }

    #[test]
    fn test_get_bytes_bind_request() {
        let expected_bytes = hex::decode("304c0204000000016044020103042d636e3d62696e64557365722c636e3d55736572732c64633d6465762c64633d636f6d70616e792c64633d636f6d801062696e645573657250617373776f7264").unwrap();

        let some_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Integer,
                is_constructed: false,
            },
            LdapValue::Primitive([3].to_vec()), // eeh..
        );

        let bind_username_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::OctetString,
                is_constructed: false,
            },
            LdapValue::Primitive(
                "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com"
                    .as_bytes()
                    .to_vec(),
            ), // eeh..
        );

        let bind_password_attribute = LdapAttribute::new(
            Tag::Context {
                value: 0,
                is_constructed: false,
            },
            LdapValue::Primitive("bindUserPassword".as_bytes().to_vec()), // eeh..
        );

        let bind_request_attribute = LdapAttribute::new(
            Tag::Application {
                operation: LdapOperation::BindRequest,
                is_constructed: true,
            },
            LdapValue::Constructed(vec![
                some_attribute,
                bind_username_attribute,
                bind_password_attribute,
            ]),
        );

        let packet = LdapAttribute::new_packet(1, vec![bind_request_attribute]);

        assert_eq!(packet.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_get_bytes_bind_response() {
        let expected_bytes = hex::decode("300f02040000000161070a010004000400").unwrap();

        let bind_response_attribute =
            LdapAttribute::new_result_attribute(LdapOperation::BindResponse, LdapResult::Success);

        let packet = LdapAttribute::new_packet(1, vec![bind_response_attribute]);

        assert_eq!(packet.get_bytes(), expected_bytes)
    }
}
