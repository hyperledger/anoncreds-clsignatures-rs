use std::borrow::Cow;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidState,
    ProofRejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(ErrorKind, Cow<'static, str>);

impl Error {
    pub fn new<M>(kind: ErrorKind, msg: M) -> Self
    where
        M: Into<Cow<'static, str>>,
    {
        Self(kind, msg.into())
    }

    pub fn kind(&self) -> ErrorKind {
        self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.1.as_ref())
    }
}

pub type Result<T> = ::core::result::Result<T, Error>;

#[macro_export]
macro_rules! err_msg {
    ($type:ident, $msg:expr, $($args:tt)+) => {
        $crate::error::Error::new($crate::error::ErrorKind::$type, format!($msg, $($args)+))
    };
    ($type:ident, $msg:expr) => {{
        $crate::error::Error::new($crate::error::ErrorKind::$type, $msg)
    }};
    ($msg:expr) => {{
        $crate::err_msg!(InvalidState, $msg)
    }};
    ($msg:expr, $($args:tt)+) => {
        $crate::err_msg!(InvalidState, $msg, $($args)+)
    };
}
