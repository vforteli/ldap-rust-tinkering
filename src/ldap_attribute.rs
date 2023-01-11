use tokio::{
    io::{AsyncReadExt, BufReader},
    net::TcpStream,
};

use crate::{
    ldap_error::LdapError, ldap_operation::LdapOperation, ldap_result::LdapResult, tag::Tag,
    universal_data_type::UniversalDataType, utils,
};

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
        let message_id_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Integer,
                is_constructed: false,
            },
            LdapValue::Primitive(i32::to_be_bytes(message_id).to_vec()),
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
    pub fn new_result_attribute(
        operation: LdapOperation,
        result: LdapResult,
        matched_dn: &str,
        diagnostic_message: &str,
    ) -> Self {
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
            LdapValue::Primitive(matched_dn.as_bytes().to_vec()),
        );

        let diagnostic_message_attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::OctetString,
                is_constructed: false,
            },
            LdapValue::Primitive(diagnostic_message.as_bytes().to_vec()),
        );

        LdapAttribute::new(
            Tag::Application {
                operation,
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

    pub async fn parse_packet_from_stream(
        stream: &mut TcpStream,
    ) -> Result<Option<Self>, LdapError> {
        let mut reader = BufReader::new(stream);

        return match reader.read_u8().await {
            Ok(tag_byte) => {
                let tag: Tag = tag_byte.into();

                let length: usize = match utils::parse_ber_length_first_byte(
                    reader.read_u8().await.map_err(|e| {
                        LdapError::ParseError(format!("Failed parsing length from packet: {}", e))
                    })?,
                ) {
                    utils::LengthFormat::Long(long_length_bytes_count) => {
                        let mut length_bytes = vec![0; long_length_bytes_count as usize];
                        reader.read_exact(&mut length_bytes).await.map_err(|e| {
                            LdapError::ParseError(format!(
                                "Failed parsing long length from packet: {}",
                                e
                            ))
                        })?;
                        utils::parse_ber_length(&length_bytes)
                    }
                    utils::LengthFormat::Short(short_length) => short_length,
                } as usize;

                let mut packet_value_bytes = vec![0; length];
                reader
                    .read_exact(&mut packet_value_bytes)
                    .await
                    .map_err(|e| {
                        LdapError::ParseError(format!(
                            "Failed reading value bytes from packet: {}",
                            e
                        ))
                    })?;

                Ok(Some(LdapAttribute {
                    tag,
                    value: LdapValue::Constructed(Self::parse_attributes(&packet_value_bytes)?),
                }))
            }
            Err(_) => Ok(None),
        };
    }

    pub fn parse_packet(packet_bytes: &[u8]) -> Result<Self, LdapError> {
        let tag: Tag = packet_bytes[0].into();

        let length = utils::ber_length_to_i32(&packet_bytes[1..]);

        let value_bytes = &packet_bytes
            [(1 + length.bytes_consumed)..(1 + length.bytes_consumed + length.value as usize)];

        Ok(LdapAttribute {
            tag,
            value: LdapValue::Constructed(Self::parse_attributes(&value_bytes)?),
        })
    }

    fn parse_attributes(attribute_bytes: &[u8]) -> Result<Vec<Self>, LdapError> {
        let mut attributes: Vec<LdapAttribute> = Vec::new();

        let mut position: usize = 0;

        while position < attribute_bytes.len() {
            let tag: Tag = attribute_bytes[position].into();

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

            let value_bytes =
                &attribute_bytes[position..(position + attribute_value_length as usize)];

            let value = if is_constructed {
                LdapValue::Constructed(Self::parse_attributes(&value_bytes.to_vec())?)
            } else {
                LdapValue::Primitive(value_bytes.to_vec())
            };

            attributes.push(LdapAttribute::new(tag, value));

            position += attribute_value_length as usize;
        }

        Ok(attributes)
    }
}

#[cfg(test)]
mod tests {

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

        let attribute = LdapAttribute::new(
            Tag::Universal {
                data_type: UniversalDataType::Integer,
                is_constructed: false,
            },
            LdapValue::Primitive(i32::MAX.to_be_bytes().to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_parse_bind_request_and_get_bytes() {
        let bind_request_bytes = hex::decode("304c0204000000016044020103042d636e3d62696e64557365722c636e3d55736572732c64633d6465762c64633d636f6d70616e792c64633d636f6d801062696e645573657250617373776f7264").unwrap();

        let packet = LdapAttribute::parse_packet(&bind_request_bytes).unwrap();

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

        let bind_response_attribute = LdapAttribute::new_result_attribute(
            LdapOperation::BindResponse,
            LdapResult::Success,
            "",
            "",
        );

        let packet = LdapAttribute::new_packet(1, vec![bind_response_attribute]);

        assert_eq!(packet.get_bytes(), expected_bytes)
    }
}
