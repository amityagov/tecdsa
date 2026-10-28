//! Modular arithmetic over an odd modulus with Montgomery parameters computed once.
use crypto_bigint::{
    BoxedUint, NonZero, Odd,
    ctutils::CtSelect,
    modular::{BoxedMontyForm, BoxedMontyParams},
};

use crypto_bigint::Resize;

use super::sbig::{SBig, resized};
use crate::error::{Error, Result};

/// Residue ring `Z_M` for an odd `M`; parameters are shared (`Arc`) across clones.
#[derive(Clone, Debug)]
pub struct Modulus {
    params: BoxedMontyParams,
    nz: NonZero<BoxedUint>,
}

pub type Residue = BoxedMontyForm;

impl Modulus {
    pub fn new(m: BoxedUint) -> Result<Self> {
        let odd = Option::<Odd<BoxedUint>>::from(m.to_odd()).ok_or(Error::InvalidModulus)?;
        let nz = Option::<NonZero<BoxedUint>>::from(m.to_nz()).ok_or(Error::InvalidModulus)?;
        Ok(Self {
            params: BoxedMontyParams::new_vartime(odd),
            nz,
        })
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        let bits = (bytes.len() as u32 * 8).max(64);
        let m = BoxedUint::from_be_slice(bytes, bits).map_err(|_| Error::InvalidEncoding)?;
        Self::new(m)
    }

    pub fn modulus(&self) -> &NonZero<BoxedUint> {
        &self.nz
    }

    pub fn bits_precision(&self) -> u32 {
        self.params.bits_precision()
    }

    /// Residue of `x mod M` (any width).
    pub fn residue(&self, x: &BoxedUint) -> Residue {
        let prec = self.bits_precision();
        let x = if x.bits_precision() > prec {
            let wide = Option::<NonZero<BoxedUint>>::from(
                resized(self.nz.as_ref(), x.bits_precision()).to_nz(),
            )
            .unwrap_or_else(|| self.nz.clone());
            x.rem(&wide).resize(prec)
        } else {
            resized(x, prec)
        };
        BoxedMontyForm::new(x, &self.params)
    }

    pub fn residue_signed(&self, x: &SBig) -> Residue {
        let r = self.residue(x.mag());
        let n = r.neg();
        Residue::from_montgomery(
            r.as_montgomery().ct_select(n.as_montgomery(), x.is_neg()),
            &self.params,
        )
    }

    pub fn one(&self) -> Residue {
        BoxedMontyForm::one(&self.params)
    }

    pub fn invert(&self, a: &Residue) -> Result<Residue> {
        Option::from(a.invert()).ok_or(Error::NotInvertible)
    }

    /// `base^exp` with a secret exponent whose magnitude fits in `exp_bits` bits (leaked).
    /// Negative exponents invert the base; invertibility of the base is public.
    pub fn pow_ct(&self, base: &Residue, exp: &SBig, exp_bits: u32) -> Result<Residue> {
        let inv = self.invert(base)?;
        let b = Residue::from_montgomery(
            base.as_montgomery()
                .ct_select(inv.as_montgomery(), exp.is_neg()),
            &self.params,
        );
        Ok(b.pow_bounded_exp(exp.mag(), exp_bits.min(exp.mag().bits_precision())))
    }

    /// `base^exp` for public exponents.
    pub fn pow_vartime(&self, base: &Residue, exp: &SBig) -> Result<Residue> {
        let bits = exp.mag().bits_vartime();
        let b = if bool::from(exp.is_neg()) {
            self.invert(base)?
        } else {
            base.clone()
        };
        if bits == 0 {
            return Ok(self.one());
        }
        Ok(b.pow_bounded_exp(exp.mag(), bits))
    }

    /// Jacobi symbol `(a/M)` for public `a` (binary algorithm, variable time): −1, 0 or 1.
    pub fn jacobi_vartime(&self, a: &BoxedUint) -> i8 {
        jacobi_vartime(a, self.nz.as_ref())
    }
}

/// Jacobi symbol `(a/n)` for odd `n`, variable time.
pub fn jacobi_vartime(a: &BoxedUint, n: &BoxedUint) -> i8 {
    let bits = a.bits_precision().max(n.bits_precision());
    let mut n = resized(n, bits);
    let mut a = match NonZero::new(n.clone()).into_option() {
        Some(nz) => resized(a, bits).rem_vartime(&nz),
        None => return 0,
    };
    let mut t: i8 = 1;
    while !bool::from(a.is_zero()) {
        let tz = a.trailing_zeros_vartime();
        a = a
            .shr_vartime(tz)
            .unwrap_or_else(|| BoxedUint::zero_with_precision(bits));
        let n_mod8 = n.as_words()[0] & 7;
        if tz % 2 == 1 && (n_mod8 == 3 || n_mod8 == 5) {
            t = -t;
        }
        core::mem::swap(&mut a, &mut n);
        if a.as_words()[0] & 3 == 3 && n.as_words()[0] & 3 == 3 {
            t = -t;
        }
        if let Some(nz) = NonZero::new(n.clone()).into_option() {
            a = a.rem_vartime(&nz);
        }
    }
    if n.is_one().into() { t } else { 0 }
}
