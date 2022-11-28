#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum LdapFilterChoice {
    And = 0,
    Or = 1,
    Not = 2,
    EqualityMatch = 3,
    Substrings = 4,
    GreaterOrEqual = 5,
    LessOrEqual = 6,
    Present = 7,
    ApproxMatch = 8,
    ExtensibleMatch = 9,
}
