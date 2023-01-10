use std::fmt;

// todo.. convert this into something sensible... should at least be able to convert to Error.. maybe
#[derive(Debug, Clone)]
pub enum LdapError {
    InvalidLength,
    UnexpectedPacket,
    NotImplementedYet,
    MalformedPacket,
}

impl fmt::Display for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LdapError::InvalidLength => write!(f, "Packed length mismatch"),
            LdapError::UnexpectedPacket => write!(f, "Unexpected packet format?!"),
            LdapError::NotImplementedYet => write!(
                f,
                "Someone has been lazy and this operation has not been implemented yet..."
            ),
            LdapError::MalformedPacket => write!(
                f,
                "Malformed packet, expected some attribute which didnt exist :/"
            ),
        }
    }
}
