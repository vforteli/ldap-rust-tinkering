use crate::{
    ldap_operation::LdapOperation, tag_class::TagClass, universal_data_type::UniversalDataType,
};

#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum Tag {
    Universal(UniversalDataType),
    Application(LdapOperation),
    Context(u8),
    Private,
}

impl Into<u8> for Tag {
    fn into(self) -> u8 {
        match self {
            Self::Universal(value) => value as u8 + ((TagClass::Universal as u8) << 6),
            Self::Application(value) => value as u8 + ((TagClass::Application as u8) << 6),
            Self::Context(value) => value as u8 + ((TagClass::Context as u8) << 6),
            Self::Private => 3 << 6,
        }
    }
}

impl From<u8> for Tag {
    fn from(tag_byte: u8) -> Self {
        let tag_class: TagClass = (tag_byte >> 6).into();
        match tag_class {
            TagClass::Universal => Self::Universal((tag_byte & 31).into()),
            TagClass::Application => Self::Application((tag_byte & 31).into()),
            TagClass::Context => Self::Context(tag_byte & 31),
            TagClass::Private => Self::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_universal_tag() {
        let tag = Tag::Universal(UniversalDataType::Integer);

        let tag_byte: u8 = tag.into();

        println!("{:#010b}", tag_byte);
        assert_eq!(tag_byte, 0);
    }

    #[test]
    fn test_parse_universal_constructed_sequence() {
        let tag_byte = hex::decode("30").unwrap();

        let tag: Tag = tag_byte[0].into();

        assert_eq!(tag, Tag::Universal(UniversalDataType::Sequence));

        // todo this should also ensure it is constructired
        assert!(false)
    }
}
