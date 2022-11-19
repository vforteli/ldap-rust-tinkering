/// https://tools.ietf.org/html/rfc4511
#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum LdapResult {
    Success = 0,
    OperationError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    // 9 reserved --
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    // 22-31 unused --
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDnsyntax = 34,
    // 35 reserved for undefined isLeaf --
    AliasDereferencingProblem = 36,
    // 37-47 unused --
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    // 55-63 unused --
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotAllowedOnRdn = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    // 70 reserved for CLDAP --
    AffectsMultipleDsas = 71,
    // 72-79 unused --
    Other = 80,
}
