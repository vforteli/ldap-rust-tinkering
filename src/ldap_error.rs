use std::fmt;

#[derive(Debug, Clone)]
pub enum LdapError {
    InvalidLength,
    UnexpectedPacket,
    NotImplementedYet,
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
        }
    }
}
