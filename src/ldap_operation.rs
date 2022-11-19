// Ldap operations from https://tools.ietf.org/html/rfc4511#section-4.2
#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum LdapOperation {
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
    ModifyRequest = 6,
    ModifyResponse = 7,
    AddRequest = 8,
    AddResponse = 9,
    DelRequest = 10,
    DelResponse = 11,
    ModifyDNRequest = 12,
    ModifyDNResponse = 13,
    CompareRequest = 14,
    CompareResponse = 15,
    AbandonRequest = 16,
    SearchResultReference = 19,
    ExtendedRequest = 23,
    ExtendedResponse = 24,
    IntermediateResponse = 25,
}

impl From<u8> for LdapOperation {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::BindRequest,
            1 => Self::BindResponse,
            2 => Self::UnbindRequest,
            3 => Self::SearchRequest,
            4 => Self::SearchResultEntry,
            5 => Self::SearchResultDone,
            6 => Self::ModifyRequest,
            7 => Self::ModifyResponse,
            8 => Self::AddRequest,
            9 => Self::AddResponse,
            10 => Self::DelRequest,
            11 => Self::DelResponse,
            12 => Self::ModifyDNRequest,
            13 => Self::ModifyDNResponse,
            14 => Self::CompareRequest,
            15 => Self::CompareResponse,
            16 => Self::AbandonRequest,
            19 => Self::SearchResultReference,
            23 => Self::ExtendedRequest,
            24 => Self::ExtendedResponse,
            25 => Self::IntermediateResponse,
            _ => panic!("lulz"),
        }
    }
}
