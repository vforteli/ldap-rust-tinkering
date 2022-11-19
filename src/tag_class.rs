#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum TagClass {
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
