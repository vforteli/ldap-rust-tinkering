use crate::{
    ldap_operation::LdapOperation, tag_class::TagClass, universal_data_type::UniversalDataType,
};

#[derive(Debug, PartialEq, Clone)]
pub struct TagValue<T> {
    pub value: T,
    pub is_constructed: bool,
}

#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum Tag {
    Universal(TagValue<UniversalDataType>),
    Application(TagValue<LdapOperation>),
    Context(TagValue<u8>),
    Private,
}

impl Into<u8> for Tag {
    fn into(self) -> u8 {
        match self {
            Self::Universal(value) => {
                value.value as u8
                    + ((TagClass::Universal as u8) << 6)
                    + ((value.is_constructed as u8) << 5)
            }
            Self::Application(value) => {
                value.value as u8
                    + ((TagClass::Application as u8) << 6)
                    + ((value.is_constructed as u8) << 5)
            }
            Self::Context(value) => {
                value.value as u8
                    + ((TagClass::Context as u8) << 6)
                    + ((value.is_constructed as u8) << 5)
            }
            Self::Private => 3 << 6,
        }
    }
}

impl From<u8> for Tag {
    fn from(tag_byte: u8) -> Self {
        let tag_class: TagClass = (tag_byte >> 6).into();
        match tag_class {
            TagClass::Universal => Self::Universal(TagValue {
                value: (tag_byte & 31).into(),
                is_constructed: (tag_byte & (1 << 5)) != 0,
            }),
            TagClass::Application => Self::Application(TagValue {
                value: (tag_byte & 31).into(),
                is_constructed: (tag_byte & (1 << 5)) != 0,
            }),
            TagClass::Context => Self::Context(TagValue {
                value: (tag_byte & 31).into(),
                is_constructed: (tag_byte & (1 << 5)) != 0,
            }),
            TagClass::Private => Self::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_universal_tag() {
        let tag = Tag::Universal(TagValue {
            value: UniversalDataType::Integer,
            is_constructed: false,
        });

        let tag_byte: u8 = tag.into();

        println!("{:#010b}", tag_byte);
        assert_eq!(tag_byte, 2);
    }

    #[test]
    fn test_create_universal_sequence_tag() {
        let tag = Tag::Universal(TagValue {
            value: UniversalDataType::Sequence,
            is_constructed: true,
        });

        let tag_byte: u8 = tag.into();

        println!("{:#010b}", tag_byte);
        assert_eq!(tag_byte, 48);
    }

    #[test]
    fn test_parse_universal_constructed_sequence() {
        let tag_byte = hex::decode("30").unwrap();

        let tag: Tag = tag_byte[0].into();

        match tag {
            Tag::Universal(t) => {
                assert!(t.is_constructed);
                assert_eq!(t.value, UniversalDataType::Sequence);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_search_request_constructed() {
        let tag_byte = hex::decode("63").unwrap();

        let tag: Tag = tag_byte[0].into();

        match tag {
            Tag::Application(t) => {
                assert!(t.is_constructed);
                assert_eq!(t.value, LdapOperation::SearchRequest);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_universal_integer() {
        let tag_byte = hex::decode("02").unwrap();

        let tag: Tag = tag_byte[0].into();

        match tag {
            Tag::Universal(t) => {
                assert!(!t.is_constructed);
                assert_eq!(t.value, UniversalDataType::Integer);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_create_search_request_tag() {
        let tag = Tag::Application(TagValue {
            value: LdapOperation::SearchRequest,
            is_constructed: true,
        });

        let tag_byte: u8 = tag.into();

        println!("{:#b}", tag_byte);
        let tag_hex = hex::encode(&[tag_byte]);
        assert_eq!(tag_hex, "63");
    }
}
