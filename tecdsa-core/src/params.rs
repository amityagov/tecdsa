//! Security parameters (spec §5). Every size used by the protocols comes from here.

/// Identifier of a parameter profile, carried in the message envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ParamsId {
    P128 = 128,
    P112 = 112,
}

/// Parameter profile. All sizes are in bits unless noted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub id: ParamsId,
    /// Group order size κ.
    pub kappa: u32,
    /// Soundness ℓ.
    pub ell: u32,
    /// Statistical noise ν.
    pub nu: u32,
    /// Noise against subgroup leakage ν_leak.
    pub nu_leak: u32,
    /// Paillier / DF modulus size of the server.
    pub n_rsa: u32,
    /// Ephemeral DF modulus size of the client.
    pub n_client: u32,
    /// Repetitions of Π_mod.
    pub r_mod: u32,
    /// Repetitions of Π_df.
    pub r_df: u32,
    /// Repetitions of Π_df*.
    pub r_df_star: u32,
    /// Challenge size of Π_df* in bits (open question, spec §5).
    pub ell0: u32,
    /// Randomness range of a DF commitment, n_tρ.
    pub n_t_rho: u32,
    /// Number of small primes in (p−1)/2 for tough primes.
    pub tough_count: u32,
    /// Bit size of each small prime in tough primes.
    pub tough_bits: u32,
}

impl Params {
    /// Slack ε = ℓ + ν.
    pub const fn eps(&self) -> u32 {
        self.ell + self.nu
    }
    /// Range of x₂′: κ + ν_leak.
    pub const fn n_x(&self) -> u32 {
        self.kappa + self.nu_leak
    }
    /// Range of β: 2ℓ + ν_leak.
    pub const fn n_lambda(&self) -> u32 {
        2 * self.ell + self.nu_leak
    }
    /// Range of v: κ + ℓ + ν.
    pub const fn n_b(&self) -> u32 {
        self.kappa + self.ell + self.nu
    }
    /// Range of u: n_x + ε + n_b + ν.
    pub const fn n_a(&self) -> u32 {
        self.n_x() + self.eps() + self.n_b() + self.nu
    }
    /// Range of λ₀: n_λ + ε + n_b + ν.
    pub const fn n_lambda0(&self) -> u32 {
        self.n_lambda() + self.eps() + self.n_b() + self.nu
    }

    /// Checks internal consistency of a profile.
    pub const fn is_consistent(&self) -> bool {
        self.kappa == 256
            && self.ell > 0
            && self.r_df == self.ell
            && self.r_mod == self.ell / 2
            && self.r_df_star * self.ell0 >= self.ell
            && self.n_rsa % 8 == 0
            && self.n_client % 8 == 0
    }
}

/// Main profile: 128-bit security.
pub const PARAMS_128: Params = Params {
    id: ParamsId::P128,
    kappa: 256,
    ell: 128,
    nu: 64,
    nu_leak: 64,
    n_rsa: 3072,
    n_client: 2048,
    r_mod: 64,
    r_df: 128,
    r_df_star: 16,
    ell0: 8,
    n_t_rho: 1408,
    tough_count: 6,
    tough_bits: 256,
};

/// Benchmark-only profile: 112-bit security.
// Tough primes are 1024 bits here (n_rsa / 2), so the factors of (p−1)/2 are sized to fit:
// 5 factors of about 205 bits (the 128-bit profile uses 6 × 256 = 1536).
pub const PARAMS_112: Params = Params {
    id: ParamsId::P112,
    kappa: 256,
    ell: 112,
    nu: 64,
    nu_leak: 64,
    n_rsa: 2048,
    n_client: 2048,
    r_mod: 56,
    r_df: 112,
    r_df_star: 16,
    ell0: 8,
    n_t_rho: 1344,
    tough_count: 5,
    tough_bits: 205,
};

const _: () = assert!(PARAMS_128.is_consistent());
const _: () = assert!(PARAMS_112.is_consistent());
const _: () = assert!(PARAMS_128.eps() == 192 && PARAMS_112.eps() == 176);
const _: () = assert!(PARAMS_128.n_x() == 320 && PARAMS_112.n_x() == 320);
const _: () = assert!(PARAMS_128.n_lambda() == 320 && PARAMS_112.n_lambda() == 288);
const _: () = assert!(PARAMS_128.n_b() == 448 && PARAMS_112.n_b() == 432);
const _: () = assert!(PARAMS_128.n_a() == 1024 && PARAMS_112.n_a() == 992);
const _: () = assert!(PARAMS_128.n_lambda0() == 1024 && PARAMS_112.n_lambda0() == 960);
