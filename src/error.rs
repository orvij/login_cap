/// Error type for login_cap
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Utf8(std::str::Utf8Error),
    LoginGetClass,
    LoginGetStyle,
    LoginGetCapBool,
    LoginGetCapErr(i64),
    LoginGetCapErrStr(String),
    LoginSetUserContext,
    NullPtr,
    SetClassContext,
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf8(e)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(_e: std::ffi::NulError) -> Self {
        Self::NullPtr
    }
}
