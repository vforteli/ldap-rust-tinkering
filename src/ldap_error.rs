use std::{error::Error, fmt};

// todo.. convert this into something sensible... should at least be able to convert to Error.. maybe
#[derive(Debug, Clone)]
pub enum LdapError {
    InvalidLength,
    UnexpectedPacket,
    NotImplementedYet,
    MalformedPacket(String),
    ParseError(String),
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
            LdapError::MalformedPacket(message) => write!(f, "Malformed packet: {}", message),
            LdapError::ParseError(message) => write!(f, "Packet parsing failed: {}", message),
        }
    }
}

impl Error for LdapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}
