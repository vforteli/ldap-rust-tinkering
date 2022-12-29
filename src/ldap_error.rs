use std::fmt;

#[derive(Debug, Clone)]
pub enum LdapError {
    InvalidLength,
}

impl fmt::Display for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LdapError::InvalidLength => write!(f, "Packed length mismatch"),
        }
    }
}
