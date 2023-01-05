use byteorder::{BigEndian, ByteOrder};

use crate::{
    ldap_error,
    tag::{Tag, TagValue},
    universal_data_type::UniversalDataType,
    utils,
};

pub enum LdapValue {
    Primitive(Vec<u8>),
    Constructed(Vec<LdapAttribute>),
}

pub struct LdapAttribute {
    tag: Tag,
    value: LdapValue,
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
            Tag::Universal(TagValue {
                value: UniversalDataType::Integer,
                is_constructed: false,
            }),
            LdapValue::Primitive(buffer.to_vec()),
        );

        let mut packet_attributes = vec![message_id_attribute];
        packet_attributes.extend(attributes);

        Self {
            tag: Tag::Universal(TagValue {
                value: UniversalDataType::Sequence,
                is_constructed: true,
            }),
            value: LdapValue::Constructed(packet_attributes),
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut attribute_bytes: Vec<u8> = Vec::new();

        self.get_bytes_recursive(&mut attribute_bytes);

        attribute_bytes
    }

    fn get_bytes_recursive(&self, attribute_bytes: &mut Vec<u8>) {
        let tag_byte: u8 = self.tag.clone().into();

        attribute_bytes.extend([tag_byte]);

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

        let value_bytes = &packet_bytes[(1 + length.bytes_consumed)..];
        if length.value > value_bytes.len().try_into().unwrap() {
            return Err(ldap_error::LdapError::InvalidLength);
        }

        println!("packet length {}", value_bytes.len());

        // match tag {
        //     Tag::Universal(v) => v.is_constructed,
        //     Tag::Application(_) => todo!(),
        //     Tag::Context(_) => todo!(),
        //     Tag::Private => todo!(),
        // }

        // var packet = new LdapPacket(Tag.Parse(bytes[0]));
        // var contentLength = Utils.BerLengthToInt(bytes, 1, out var lengthBytesCount);
        // packet.ChildAttributes.AddRange(ParseAttributes(bytes, 1 + lengthBytesCount, contentLength));
        // return packet;
        // todo!("whoops, kinda forgot parsing :D")
        // let length_from_packet = BigEndian::read_u16(&packet_bytes[2..4]) as usize;
        Ok(LdapAttribute {
            tag,
            value: LdapValue::Primitive(vec![]),
        })
    }

    fn parse_attribute(attribute_bytes: &[u8]) -> Result<Self, ldap_error::LdapError> {
        let tag: Tag = attribute_bytes[0].into();
        // todo!("whoops, kinda forgot parsing :D")
        // let length_from_packet = BigEndian::read_u16(&packet_bytes[2..4]) as usize;
        Ok(LdapAttribute {
            tag,
            value: LdapValue::Primitive(vec![]),
        })
    }
}

#[cfg(test)]
mod tests {

    use byteorder::{BigEndian, ByteOrder};

    use crate::{
        ldap_operation::LdapOperation, ldap_result::LdapResult, tag::TagValue,
        universal_data_type::UniversalDataType,
    };

    use super::*;

    #[test]
    fn test_create_bind_request_attribute() {
        let attribute = LdapAttribute::new(
            Tag::Application(TagValue {
                value: LdapOperation::BindRequest,
                is_constructed: false,
            }),
            LdapValue::Primitive(Vec::new()),
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
            LdapValue::Primitive("dc=karakorum,dc=net".as_bytes().to_vec()),
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
            LdapValue::Primitive([true as u8].to_vec()), // eeh..
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
            LdapValue::Primitive([false as u8].to_vec()), // eeh..
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
            LdapValue::Primitive([1].to_vec()), // eeh..
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
            Tag::Universal(TagValue {
                value: UniversalDataType::Integer,
                is_constructed: false,
            }),
            LdapValue::Primitive(buffer.to_vec()), // eeh..
        );

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    #[test]
    fn test_parse_bind_request() {
        let bind_request_bytes = hex::decode("304c0204000000016044020103042d636e3d62696e64557365722c636e3d55736572732c64633d6465762c64633d636f6d70616e792c64633d636f6d801062696e645573657250617373776f7264").unwrap();

        let packet = LdapAttribute::parse(&bind_request_bytes).unwrap();

        match packet.tag {
            Tag::Universal(value) => {
                assert_eq!(value.is_constructed, true)
            }
            _ => assert!(false),
        }

        // let response_packet = match packet.packetcode {
        //     PacketCode::AccessRequest => {
        //         // yes yes, this should be done in one go...
        //         let username = packet.attributes.iter().find_map(|a| match a {
        //             RfcAttributeType::UserName(u) => Some(u),
        //             _ => None,
        //         });

        //         let password = packet.attributes.iter().find_map(|a| match a {
        //             RfcAttributeType::UserPassword(u) => {
        //                 Some(decrypt(secret_bytes, &packet.authenticator, u))
        //             }
        //             _ => None,
        //         });
    }

    #[test]
    fn test_get_bytes_bind_request() {
        let expected_bytes = hex::decode("304c0204000000016044020103042d636e3d62696e64557365722c636e3d55736572732c64633d6465762c64633d636f6d70616e792c64633d636f6d801062696e645573657250617373776f7264").unwrap();

        let some_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Integer,
                is_constructed: false,
            }),
            LdapValue::Primitive([3].to_vec()), // eeh..
        );

        let bind_username_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::OctetString,
                is_constructed: false,
            }),
            LdapValue::Primitive(
                "cn=bindUser,cn=Users,dc=dev,dc=company,dc=com"
                    .as_bytes()
                    .to_vec(),
            ), // eeh..
        );

        let bind_password_attribute = LdapAttribute::new(
            Tag::Context(TagValue {
                value: 0,
                is_constructed: false,
            }),
            LdapValue::Primitive("bindUserPassword".as_bytes().to_vec()), // eeh..
        );

        let bind_request_attribute = LdapAttribute::new(
            Tag::Application(TagValue {
                value: LdapOperation::BindRequest,
                is_constructed: true,
            }),
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

        let result_code_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Enumerated,
                is_constructed: false,
            }),
            LdapValue::Primitive([LdapResult::Success as u8].to_vec()), // eeh..
        );

        let matched_dn_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::OctetString,
                is_constructed: false,
            }),
            LdapValue::Primitive(Vec::new()), // eeh..
        );

        let diagnostic_message_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::OctetString,
                is_constructed: false,
            }),
            LdapValue::Primitive(Vec::new()), // eeh..
        );

        let bind_response_attribute = LdapAttribute::new(
            Tag::Application(TagValue {
                value: LdapOperation::BindResponse,
                is_constructed: true,
            }),
            LdapValue::Constructed(vec![
                result_code_attribute,
                matched_dn_attribute,
                diagnostic_message_attribute,
            ]), // eeh..
        );

        let packet = LdapAttribute::new_packet(1, vec![bind_response_attribute]);

        assert_eq!(packet.get_bytes(), expected_bytes)
    }
}
