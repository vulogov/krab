//! Deterministic PRNG.
//!
//! xoshiro256++ (Blackman & Vigna, public domain) seeded via SplitMix64.
//! Chosen over an external crate so SIM-0 has no dependencies: results must be
//! reproducible byte-for-byte by anyone re-running the simulation to check a
//! claim in the RFC series, on any toolchain, offline.
//!
//! Not cryptographic. Nothing here is used by the Krab protocol itself.

pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        // SplitMix64 to expand a single seed into the xoshiro state.
        let mut z = seed;
        let mut next = || -> u64 {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^ (x >> 31)
        };
        Rng {
            s: [next(), next(), next(), next()],
        }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let r = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        r
    }

    /// Uniform in [0, 1).
    #[inline]
    pub fn f64(&mut self) -> f64 {
        // 53 significant bits, the full mantissa.
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Uniform integer in [0, n). Debiased by rejection.
    #[inline]
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }

    /// Uniform in [lo, hi).
    #[inline]
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo)
    }

    /// Exponential with the given mean. Used for Poisson arrival processes:
    /// sync scheduling, message injection, and online/offline session lengths.
    #[inline]
    pub fn exp(&mut self, mean: f64) -> f64 {
        let u = 1.0 - self.f64(); // avoid ln(0)
        -mean * u.ln()
    }

    #[inline]
    pub fn chance(&mut self, p: f64) -> bool {
        self.f64() < p
    }

    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        if v.len() < 2 {
            return;
        }
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}
