//! Session identifiers (spec §10.4): always the first item of every transcript and RO.
use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Longest accepted `server_id` / `client_id`.
pub const MAX_ID_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionKind {
    Keygen = 0x01,
    Sign = 0x02,
}

/// `(sid, server_id, client_id, kind, tail)`, canonically encoded by [`Ssid::encode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssid {
    sid: [u8; 32],
    server_id: Vec<u8>,
    client_id: Vec<u8>,
    kind: SessionKind,
    tail: Vec<u8>,
}

impl Ssid {
    fn new(
        sid: [u8; 32],
        server_id: &[u8],
        client_id: &[u8],
        kind: SessionKind,
        tail: Vec<u8>,
    ) -> Result<Self> {
        if server_id.len() > MAX_ID_LEN || client_id.len() > MAX_ID_LEN {
            return Err(Error::OutOfRange);
        }
        Ok(Self {
            sid,
            server_id: server_id.to_vec(),
            client_id: client_id.to_vec(),
            kind,
            tail,
        })
    }

    /// Keygen: `kg_nonce` is the 32 random bytes the server puts into KgMsg1.
    pub fn keygen(
        sid: [u8; 32],
        server_id: &[u8],
        client_id: &[u8],
        kg_nonce: &[u8; 32],
    ) -> Result<Self> {
        Self::new(
            sid,
            server_id,
            client_id,
            SessionKind::Keygen,
            kg_nonce.to_vec(),
        )
    }

    /// Sign: `key_id = SHA-256(X ‖ E)`, `digest = m`, and the fresh `R₂` as the session id.
    pub fn sign(
        sid: [u8; 32],
        server_id: &[u8],
        client_id: &[u8],
        key_id: &[u8; 32],
        digest: &[u8; 32],
        r2: &[u8; 33],
    ) -> Result<Self> {
        let mut tail = Vec::with_capacity(32 + 32 + 33);
        tail.extend_from_slice(key_id);
        tail.extend_from_slice(digest);
        tail.extend_from_slice(r2);
        Self::new(sid, server_id, client_id, SessionKind::Sign, tail)
    }

    pub fn kind(&self) -> SessionKind {
        self.kind
    }
    pub fn server_id(&self) -> &[u8] {
        &self.server_id
    }
    pub fn client_id(&self) -> &[u8] {
        &self.client_id
    }

    /// `sid ‖ u32be(len S) ‖ S ‖ u32be(len C) ‖ C ‖ kind ‖ tail`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            32 + 8 + self.server_id.len() + self.client_id.len() + 1 + self.tail.len(),
        );
        out.extend_from_slice(&self.sid);
        out.extend_from_slice(&(self.server_id.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.server_id);
        out.extend_from_slice(&(self.client_id.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.client_id);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.tail);
        out
    }
}
