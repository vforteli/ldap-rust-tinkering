use crate::{ldap_operation::LdapOperation, universal_data_type::UniversalDataType};

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
enum TagClass {
    Universal = 0,
    Application = 1,
    Context = 2,
    Private = 3,
}

impl From<u8> for TagClass {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Universal,
            1 => Self::Application,
            2 => Self::Context,
            3 => Self::Private,
            _ => panic!("lulz"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum Tag {
    Universal {
        data_type: UniversalDataType,
        is_constructed: bool,
    },
    Application {
        operation: LdapOperation,
        is_constructed: bool,
    },
    Context {
        value: u8,
        is_constructed: bool,
    },
    Private,
}

impl From<Tag> for u8 {
    fn from(value: Tag) -> Self {
        match value {
            Tag::Universal {
                data_type,
                is_constructed,
            } => {
                data_type as u8 + ((TagClass::Universal as u8) << 6) + ((is_constructed as u8) << 5)
            }
            Tag::Application {
                operation,
                is_constructed,
            } => {
                operation as u8
                    + ((TagClass::Application as u8) << 6)
                    + ((is_constructed as u8) << 5)
            }
            Tag::Context {
                value,
                is_constructed,
            } => value as u8 + ((TagClass::Context as u8) << 6) + ((is_constructed as u8) << 5),
            Tag::Private => 3 << 6,
        }
    }
}

impl From<u8> for Tag {
    fn from(tag_byte: u8) -> Self {
        let tag_class: TagClass = (tag_byte >> 6).into();
        match tag_class {
            TagClass::Universal => Self::Universal {
                data_type: (tag_byte & 31).into(),
                is_constructed: (tag_byte & (1 << 5)) != 0,
            },
            TagClass::Application => Self::Application {
                operation: (tag_byte & 31).into(),
                is_constructed: (tag_byte & (1 << 5)) != 0,
            },
            TagClass::Context => Self::Context {
                value: (tag_byte & 31).into(),
                is_constructed: (tag_byte & (1 << 5)) != 0,
            },
            TagClass::Private => Self::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_universal_tag() {
        let tag = Tag::Universal {
            data_type: UniversalDataType::Integer,
            is_constructed: false,
        };

        let tag_byte: u8 = tag.into();

        println!("{:#010b}", tag_byte);
        assert_eq!(tag_byte, 2);
    }

    #[test]
    fn test_create_universal_sequence_tag() {
        let tag = Tag::Universal {
            data_type: UniversalDataType::Sequence,
            is_constructed: true,
        };

        let tag_byte: u8 = tag.into();

        println!("{:#010b}", tag_byte);
        assert_eq!(tag_byte, 48);
    }

    #[test]
    fn test_parse_universal_constructed_sequence() {
        let tag_byte = hex::decode("30").unwrap();

        let tag: Tag = tag_byte[0].into();

        match tag {
            Tag::Universal {
                data_type,
                is_constructed,
            } => {
                assert!(is_constructed);
                assert_eq!(data_type, UniversalDataType::Sequence);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_search_request_constructed() {
        let tag_byte = hex::decode("63").unwrap();

        let tag: Tag = tag_byte[0].into();

        match tag {
            Tag::Application {
                operation,
                is_constructed,
            } => {
                assert!(is_constructed);
                assert_eq!(operation, LdapOperation::SearchRequest);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_universal_integer() {
        let tag_byte = hex::decode("02").unwrap();

        let tag: Tag = tag_byte[0].into();

        match tag {
            Tag::Universal {
                data_type,
                is_constructed,
            } => {
                assert!(!is_constructed);
                assert_eq!(data_type, UniversalDataType::Integer);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_create_search_request_tag() {
        let tag = Tag::Application {
            operation: LdapOperation::SearchRequest,
            is_constructed: true,
        };

        let tag_byte: u8 = tag.into();

        println!("{:#b}", tag_byte);
        let tag_hex = hex::encode(&[tag_byte]);
        assert_eq!(tag_hex, "63");
    }
}
