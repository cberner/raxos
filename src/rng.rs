/// Small deterministic PRNG (xoshiro256++), seeded via splitmix64.
///
/// Used for proposal priorities. Determinism given a seed is part of the
/// crate's contract: it makes whole-protocol simulation tests reproducible.
/// The network adversary in QuePaxa's model is content-oblivious, so the
/// generator does not need to be cryptographically strong; callers provide
/// entropy through the seed in production.
pub(crate) struct Rng {
    state: [u64; 4],
}

impl Rng {
    pub(crate) fn new(seed: u64) -> Rng {
        // splitmix64 expansion, as recommended by the xoshiro authors.
        let mut sm = seed;
        let mut next = || {
            sm = sm.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = sm;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        };
        Rng {
            state: [next(), next(), next(), next()],
        }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = self.state;
        let result = s0.wrapping_add(s3).rotate_left(23).wrapping_add(s0);
        let t = s1 << 17;
        let mut s2 = s2 ^ s0;
        let mut s3 = s3 ^ s1;
        let s1 = s1 ^ s2;
        let s0 = s0 ^ s3;
        s2 ^= t;
        s3 = s3.rotate_left(45);
        self.state = [s0, s1, s2, s3];
        result
    }

    /// Uniform draw from `[low, high]` (inclusive). Modulo bias is
    /// irrelevant for priority draws against a content-oblivious adversary.
    pub(crate) fn range_inclusive(&mut self, low: u64, high: u64) -> u64 {
        debug_assert!(low <= high);
        low + self.next_u64() % (high - low + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(43);
        assert_ne!(Rng::new(42).next_u64(), c.next_u64());
    }

    #[test]
    fn range_stays_in_bounds() {
        let mut rng = Rng::new(7);
        for _ in 0..1000 {
            let x = rng.range_inclusive(1, u32::MAX as u64 - 1);
            assert!((1..=u32::MAX as u64 - 1).contains(&x));
        }
        assert_eq!(rng.range_inclusive(5, 5), 5);
    }

    #[test]
    fn spreads_over_range() {
        // Sanity: draws from [1, H-1] should not collide for small samples.
        let mut rng = Rng::new(1);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            seen.insert(rng.range_inclusive(1, u32::MAX as u64 - 1));
        }
        assert!(seen.len() >= 63);
    }
}
