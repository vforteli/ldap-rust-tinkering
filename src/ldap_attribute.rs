use crate::{tag::Tag, utils};

pub struct LdapAttribute {
    tag: Tag,
    value: Option<Vec<u8>>,
    child_attributes: Vec<LdapAttribute>,
}

impl LdapAttribute {
    pub fn new(tag: Tag, value: Option<Vec<u8>>) -> Self {
        Self {
            tag,
            value,
            child_attributes: Vec::new(),
        }
    }

    pub fn get_bytes(self) -> Vec<u8> {
        let mut attribute_bytes: Vec<u8> = Vec::new();

        self.get_bytes_recursive(&mut attribute_bytes);

        attribute_bytes
    }

    fn get_bytes_recursive(self, attribute_bytes: &mut Vec<u8>) {
        // argh, probably need to make this safer, ie typed tag types etc, ensuring only constructed attributes can have child attributes etc
        let tag_byte: u8 = self.tag.into();
        let mut content_bytes: Vec<u8> = Vec::new();

        attribute_bytes.extend([tag_byte]);

        if self.child_attributes.len() > 0 {
            for child_attribute in self.child_attributes {
                content_bytes.extend(child_attribute.get_bytes());
            }

            attribute_bytes.extend(utils::int_to_ber_length(content_bytes.len() as i32));
            attribute_bytes.extend(content_bytes)
        } else {
            match self.value {
                Some(v) => {
                    attribute_bytes.extend(utils::int_to_ber_length(v.len() as i32));
                    attribute_bytes.extend(v)
                }
                None => attribute_bytes.extend([0].to_vec()),
            }
        }
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

    #[test]
    fn test_get_bytes_bind_response() {
        let expected_bytes = hex::decode("61070a010004000400").unwrap();

        let result_code_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::Enumerated,
                is_constructed: false,
            }),
            Some([LdapResult::Success as u8].to_vec()), // eeh..
        );

        let matched_dn_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::OctetString,
                is_constructed: false,
            }),
            None, // eeh..
        );

        let diagnostic_message_attribute = LdapAttribute::new(
            Tag::Universal(TagValue {
                value: UniversalDataType::OctetString,
                is_constructed: false,
            }),
            None, // eeh..
        );

        let mut bind_response_attribute = LdapAttribute::new(
            Tag::Application(TagValue {
                value: LdapOperation::BindResponse,
                is_constructed: true,
            }),
            None, // eeh..
        );

        bind_response_attribute
            .child_attributes
            .push(result_code_attribute);

        bind_response_attribute
            .child_attributes
            .push(matched_dn_attribute);

        bind_response_attribute
            .child_attributes
            .push(diagnostic_message_attribute);

        assert_eq!(bind_response_attribute.get_bytes(), expected_bytes)
    }

    // todo this should test the whole packet, not just the attribute
    /*

    [TestCase]
       public void TestLdapAttributeSequenceGetBytes2()
       {
           var packet = new LdapPacket(1);

           var bindresponse = new LdapAttribute(LdapOperation.BindResponse);

           var resultCode = new LdapAttribute(UniversalDataType.Enumerated, (byte)LdapResult.success);
           bindresponse.ChildAttributes.Add(resultCode);

           var matchedDn = new LdapAttribute(UniversalDataType.OctetString);
           var diagnosticMessage = new LdapAttribute(UniversalDataType.OctetString);

           bindresponse.ChildAttributes.Add(matchedDn);
           bindresponse.ChildAttributes.Add(diagnosticMessage);

           packet.ChildAttributes.Add(bindresponse);

           var expected = "300f02040000000161070a010004000400"; // "300c02010161070a010004000400";
           Assert.AreEqual(expected, Utils.ByteArrayToString(packet.GetBytes()));
       }*/
}
