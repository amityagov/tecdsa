//! Big-number arithmetic used by the protocols.
//!
//! Secret exponents go through the `*_ct` functions; operations on public data use `*_vartime`.

pub mod fixed_base;
pub mod monty;
pub mod multiexp;
pub mod sbig;

pub use monty::Modulus;
pub use sbig::SBig;
