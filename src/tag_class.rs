#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    Context = 2,
    Private = 3,
}
