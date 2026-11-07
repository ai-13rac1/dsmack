/// A failed check. The text matches the Solidity revert string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);

pub type Result<T> = core::result::Result<T, Error>;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

macro_rules! require {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            return Err($crate::error::Error($msg));
        }
    };
}
pub(crate) use require;
