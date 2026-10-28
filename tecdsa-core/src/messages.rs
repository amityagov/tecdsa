//! Wire envelope and message bodies (spec §10.5).
//!
//! Envelope: `u16be version ‖ u8 params_id ‖ u8 msg_type ‖ body`. Bodies are `postcard` structs
//! whose fields are byte vectors; their exact lengths are validated by the protocol code that
//! consumes them (every number is fixed-width big-endian, spec §10.2).
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::{
    PROTOCOL_VERSION,
    error::{Error, Result},
    params::Params,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    KgMsg1 = 1,
    KgMsg2 = 2,
    KgMsg3 = 3,
    SignMsg1 = 4,
    SignMsg2 = 5,
    SignMsg3 = 6,
    SetupData = 7,
}

impl MsgType {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::KgMsg1,
            2 => Self::KgMsg2,
            3 => Self::KgMsg3,
            4 => Self::SignMsg1,
            5 => Self::SignMsg2,
            6 => Self::SignMsg3,
            7 => Self::SetupData,
            _ => return Err(Error::InvalidEncoding),
        })
    }

    /// Upper bound on the whole envelope, checked before parsing anything.
    pub fn max_len(self, params: &Params) -> usize {
        let n = params.n_rsa as usize / 8;
        let c = params.n_client as usize / 8;
        let ell = params.ell as usize;
        let overhead = 4 + 64;
        overhead
            + match self {
                Self::KgMsg1 => 2 * 32 + 8,
                Self::KgMsg2 => 33 + 4 * c + 4 * (c * 2) + 64 * ell + 4096,
                Self::KgMsg3 => 33 + 2 * n + 2 * c + 4 * n + 4096,
                Self::SignMsg1 => 2 * 33 + 8,
                Self::SignMsg2 => 2 * 33 + 2 * n + 8 * n + 4096,
                Self::SignMsg3 => 2 * 32 + 1 + 8,
                Self::SetupData => (40 * n + 1_000 * ell) + (1 << 12),
            }
    }
}

/// Wraps a serialized body into an envelope.
pub fn wrap(params: &Params, ty: MsgType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.push(params.id as u8);
    out.push(ty as u8);
    out.extend_from_slice(body);
    out
}

/// Checks size, version, profile and type; returns the body.
pub fn unwrap<'a>(params: &Params, expected: MsgType, bytes: &'a [u8]) -> Result<&'a [u8]> {
    if bytes.len() < 4 || bytes.len() > expected.max_len(params) {
        return Err(Error::InvalidEncoding);
    }
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version != PROTOCOL_VERSION || bytes[2] != params.id as u8 {
        return Err(Error::InvalidEncoding);
    }
    if MsgType::from_u8(bytes[3])? != expected {
        return Err(Error::InvalidEncoding);
    }
    Ok(&bytes[4..])
}

fn to_body<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(v).map_err(|_| Error::InvalidEncoding)
}

fn from_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    // Trailing bytes would make messages malleable: reject them.
    let (v, rest) = postcard::take_from_bytes(body).map_err(|_| Error::InvalidEncoding)?;
    if !rest.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    Ok(v)
}

/// S → C: keygen nonce and commitment `B = RO(ssid, S, X₂)`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KgMsg1 {
    pub kg_nonce: Vec<u8>,
    pub b: Vec<u8>,
}

/// C → S: `X₁`, the ephemeral DF tuple and the two proofs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KgMsg2 {
    pub x1: Vec<u8>,
    pub m_hat: Vec<u8>,
    pub v: Vec<u8>,
    pub u1: Vec<u8>,
    pub u2: Vec<u8>,
    pub psi_df_star: Vec<u8>,
    pub psi_dlog: Vec<u8>,
}

/// S → C: `X₂`, `E` and `ψ_dlenc`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KgMsg3 {
    pub x2: Vec<u8>,
    pub e: Vec<u8>,
    pub psi_dlenc: Vec<u8>,
}

/// S → C: `R₂` and `Y = X₁^{k₂}`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignMsg1 {
    pub r2: Vec<u8>,
    pub y: Vec<u8>,
}

/// C → S: `R₁`, `R`, the ciphertext `S` and `ψ_sig`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignMsg2 {
    pub r1: Vec<u8>,
    pub r: Vec<u8>,
    pub s_ct: Vec<u8>,
    pub psi_sig: Vec<u8>,
}

/// S → C (optional): the final signature `(r, s, recid)`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignMsg3 {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub recid: u8,
}

macro_rules! codec {
    ($t:ty, $ty:expr) => {
        impl $t {
            pub fn encode(&self, params: &Params) -> Result<Vec<u8>> {
                Ok(wrap(params, $ty, &to_body(self)?))
            }
            pub fn decode(bytes: &[u8], params: &Params) -> Result<Self> {
                from_body(unwrap(params, $ty, bytes)?)
            }
        }
    };
}
codec!(KgMsg1, MsgType::KgMsg1);
codec!(KgMsg2, MsgType::KgMsg2);
codec!(KgMsg3, MsgType::KgMsg3);
codec!(SignMsg1, MsgType::SignMsg1);
codec!(SignMsg2, MsgType::SignMsg2);
codec!(SignMsg3, MsgType::SignMsg3);
