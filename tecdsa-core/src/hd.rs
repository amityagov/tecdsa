//! BIP32 non-hardened public derivation for the 2-of-2 key (the same scheme as the reference
//! implementation): the client adds `δ` to its share, so `X' = X + δ·G` and the server share
//! stays unchanged. `δ` is the sum of the BIP32 tweaks along the path and is computed from the
//! public key and the chain code only, so both parties get the same value.
use alloc::vec::Vec;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha512};

use crate::{
    curve::{decode_scalar, encode_point},
    error::{Error, Result},
};

/// Deepest path accepted (BIP44 needs 5).
pub const MAX_PATH_DEPTH: usize = 16;

const HARDENED: u32 = 1 << 31;

/// Chain code and a path of non-hardened child indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HdPath {
    chain_code: [u8; 32],
    path: Vec<u32>,
}

/// Child public key `X + δ·G` (33-byte compressed) for the compressed master key `x_pub`.
pub fn derive_child_public_key(
    x_pub: &[u8],
    chain_code: [u8; 32],
    path: Vec<u32>,
) -> Result<[u8; 33]> {
    let x = crate::curve::decode_point(x_pub)?;
    let delta = HdPath::new(chain_code, path)?.delta(&x)?;
    Ok(encode_point(&(x + ProjectivePoint::GENERATOR * delta)))
}

impl HdPath {
    /// Hardened indices cannot be derived without the private key and are rejected.
    pub fn new(chain_code: [u8; 32], path: Vec<u32>) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_PATH_DEPTH || path.iter().any(|i| i & HARDENED != 0)
        {
            return Err(Error::OutOfRange);
        }
        Ok(Self { chain_code, path })
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn path(&self) -> &[u32] {
        &self.path
    }

    /// `δ` such that the child key is `X + δ·G`.
    pub fn delta(&self, x_pub: &ProjectivePoint) -> Result<Scalar> {
        let mut chain = self.chain_code;
        let mut parent = *x_pub;
        let mut delta = Scalar::ZERO;
        for index in &self.path {
            let mut data = [0u8; 37];
            data[..33].copy_from_slice(&encode_point(&parent));
            data[33..].copy_from_slice(&index.to_be_bytes());
            let i = hmac_sha512(&chain, &data);
            let tweak = decode_scalar(&i[..32])?; // IL ≥ q: BIP32 says "invalid child"
            let child = parent + ProjectivePoint::GENERATOR * tweak;
            if child == ProjectivePoint::IDENTITY {
                return Err(Error::OutOfRange);
            }
            delta += tweak;
            chain.copy_from_slice(&i[32..]);
            parent = child;
        }
        Ok(delta)
    }
}

fn hmac_sha512(key: &[u8; 32], data: &[u8]) -> [u8; 64] {
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::decode_point;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn child_public_key_matches_delta() {
        let x = ProjectivePoint::GENERATOR * Scalar::from(5u64);
        let chain = [3u8; 32];
        let child = derive_child_public_key(&encode_point(&x), chain, alloc::vec![7, 9]).unwrap();
        let delta = HdPath::new(chain, alloc::vec![7, 9])
            .unwrap()
            .delta(&x)
            .unwrap();
        assert_eq!(
            child,
            encode_point(&(x + ProjectivePoint::GENERATOR * delta))
        );
        assert!(derive_child_public_key(&encode_point(&x), chain, alloc::vec![1 << 31]).is_err());
        assert!(derive_child_public_key(&[2u8; 5], chain, alloc::vec![1]).is_err());
    }

    /// BIP32 test vector 2: m → m/0 (non-hardened).
    #[test]
    fn bip32_vector_2_first_level() {
        let master = decode_point(&hex(
            "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
        ))
        .unwrap();
        let chain: [u8; 32] =
            hex("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689")
                .try_into()
                .unwrap();
        let hd = HdPath::new(chain, alloc::vec![0]).unwrap();
        let child = master + ProjectivePoint::GENERATOR * hd.delta(&master).unwrap();
        assert_eq!(
            encode_point(&child).to_vec(),
            hex("02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea")
        );
    }

    #[test]
    fn rejects_hardened_empty_and_deep_paths() {
        assert!(HdPath::new([0; 32], alloc::vec![]).is_err());
        assert!(HdPath::new([0; 32], alloc::vec![HARDENED]).is_err());
        assert!(HdPath::new([0; 32], alloc::vec![1, HARDENED + 5]).is_err());
        assert!(HdPath::new([0; 32], alloc::vec![0; MAX_PATH_DEPTH + 1]).is_err());
        assert!(HdPath::new([0; 32], alloc::vec![44, 0, 0, 0, 7]).is_ok());
    }

    #[test]
    fn path_order_and_chain_code_matter() {
        let x = ProjectivePoint::GENERATOR * Scalar::from(12345u64);
        let a = HdPath::new([1; 32], alloc::vec![1, 2])
            .unwrap()
            .delta(&x)
            .unwrap();
        let b = HdPath::new([1; 32], alloc::vec![2, 1])
            .unwrap()
            .delta(&x)
            .unwrap();
        let c = HdPath::new([2; 32], alloc::vec![1, 2])
            .unwrap()
            .delta(&x)
            .unwrap();
        assert!(a != b && a != c);
    }
}
