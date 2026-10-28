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
}

pub type Result<T> = core::result::Result<T, Error>;
