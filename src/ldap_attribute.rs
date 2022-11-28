use crate::tag::Tag;

pub struct LdapAttribute {
    tag: Tag,
}

impl LdapAttribute {
    pub fn new(tag: Tag) -> Self {
        Self { tag }
    }

    pub fn get_bytes(self) -> Vec<u8> {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        ldap_operation::LdapOperation, tag::TagValue, universal_data_type::UniversalDataType,
    };

    use super::*;

    #[test]
    fn test_create_bind_request_attribute() {
        let attribute = LdapAttribute::new(Tag::Application(TagValue {
            value: LdapOperation::BindRequest,
            is_constructed: false,
        }));

        match attribute.tag {
            Tag::Application(t) => assert_eq!(t.value, LdapOperation::BindRequest),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_get_bytes() {
        let expected_bytes = hex::decode("041364633d6b6172616b6f72756d2c64633d6e6574").unwrap();

        let attribute = LdapAttribute::new(Tag::Universal(TagValue {
            value: UniversalDataType::OctetString,
            is_constructed: false,
        }));

        assert_eq!(attribute.get_bytes(), expected_bytes)
    }

    /*

    [TestCase]
      public void TestLdapAttributeGetBytesString()
      {
          var attribute = new LdapAttribute(UniversalDataType.OctetString, "dc=karakorum,dc=net");
          Assert.AreEqual("041364633d6b6172616b6f72756d2c64633d6e6574", Utils.ByteArrayToString(attribute.GetBytes()));
      }*/
}
