//! Crate-wide error type.
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("value out of range")]
    OutOfRange,
    #[error("element is not invertible")]
    NotInvertible,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("invalid modulus")]
    InvalidModulus,
    #[error("verification failed")]
    VerificationFailed,
    #[error("parameter sampling failed")]
    Sampling,
    #[error("session timed out")]
    Timeout,
}

impl From<crate::rsa::tough::ToughError> for Error {
    fn from(_: crate::rsa::tough::ToughError) -> Self {
        Self::Sampling
    }
}

pub type Result<T> = core::result::Result<T, Error>;
