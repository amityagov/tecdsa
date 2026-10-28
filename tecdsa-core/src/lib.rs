//! Two-round 2PC ECDSA at the cost of one OLE (secp256k1).
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod params;

/// Wire protocol version, written into every message envelope.
pub const PROTOCOL_VERSION: u16 = 1;
