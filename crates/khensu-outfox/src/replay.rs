// SPDX-License-Identifier: Apache-2.0
//! Replay protection (PROTOCOL.md 8.5): one Bloom filter per mix-key epoch,
//! kept for the current and previous epoch only.

#[derive(Clone)]
pub struct Bloom {
    bits: Vec<u64>,
    m: u64,
    k: u32,
}

impl Bloom {
    /// Sized for `expected` insertions at false-positive rate `fp`.
    pub fn new(expected: u64, fp: f64) -> Self {
        let n = expected.max(1) as f64;
        let ln2 = core::f64::consts::LN_2;
        let m = ((-n * fp.ln()) / (ln2 * ln2)).ceil().max(64.0) as u64;
        let k = ((m as f64 / n) * ln2).round().clamp(1.0, 32.0) as u32;
        Self { bits: vec![0; m.div_ceil(64) as usize], m, k }
    }

    pub fn size_bytes(&self) -> usize {
        self.bits.len() * 8
    }

    /// Inserts `tag`; returns `false` if it was (probably) already present.
    /// Tags are KDF outputs, so their halves serve directly as the two hashes.
    pub fn insert(&mut self, tag: &[u8; 16]) -> bool {
        let h1 = u64::from_be_bytes(tag[..8].try_into().expect("8 bytes"));
        let h2 = u64::from_be_bytes(tag[8..].try_into().expect("8 bytes")) | 1;
        let mut fresh = false;
        for i in 0..self.k as u64 {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) % self.m;
            let (w, b) = ((bit / 64) as usize, 1u64 << (bit % 64));
            if self.bits[w] & b == 0 {
                fresh = true;
                self.bits[w] |= b;
            }
        }
        fresh
    }
}

pub struct ReplayFilter {
    expected: u64,
    fp: f64,
    filters: Vec<(u64, Bloom)>,
}

impl ReplayFilter {
    pub fn new(expected_per_epoch: u64, fp: f64) -> Self {
        Self { expected: expected_per_epoch, fp, filters: Vec::with_capacity(2) }
    }

    /// Records `tag` for the epoch whose key opened the packet. Returns `true`
    /// if the packet is fresh. Packets for epochs older than the previous one
    /// are refused outright.
    pub fn check(&mut self, epoch: u64, tag: &[u8; 16]) -> bool {
        let newest = self.filters.iter().map(|f| f.0).max().unwrap_or(epoch).max(epoch);
        self.filters.retain(|(e, _)| *e + 1 >= newest);
        if epoch + 1 < newest {
            return false;
        }
        if let Some((_, f)) = self.filters.iter_mut().find(|(e, _)| *e == epoch) {
            return f.insert(tag);
        }
        let mut f = Bloom::new(self.expected, self.fp);
        f.insert(tag);
        self.filters.push((epoch, f));
        true
    }

    pub fn size_bytes(&self) -> usize {
        self.filters.iter().map(|(_, f)| f.size_bytes()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi5_sizing_matches_protocol() {
        // 2,000 packets/s for an hour at 1e-6: about 25 MB.
        let b = Bloom::new(7_200_000, 1e-6);
        let mb = b.size_bytes() as f64 / 1e6;
        assert!((24.0..27.0).contains(&mb), "{mb} MB");
    }

    #[test]
    fn replays_and_epochs() {
        let mut f = ReplayFilter::new(1000, 1e-6);
        assert!(f.check(10, &[1; 16]));
        assert!(!f.check(10, &[1; 16]));
        assert!(f.check(11, &[1; 16]));
        assert!(!f.check(10, &[1; 16]));
        assert!(f.check(12, &[2; 16]));
        assert!(!f.check(10, &[3; 16]), "two epochs back is refused");
        assert_eq!(f.filters.len(), 2);
    }

    #[test]
    fn false_positive_rate() {
        let mut b = Bloom::new(10_000, 1e-3);
        let tag = |i: u64| {
            let h = khensu_crypto::sym::h256("t", &[&i.to_be_bytes()]);
            <[u8; 16]>::try_from(&h[..16]).unwrap()
        };
        for i in 0..10_000 {
            b.insert(&tag(i));
        }
        let fps = (10_000..30_000).filter(|&i| !b.clone().insert(&tag(i))).count();
        assert!(fps < 60, "{fps} false positives in 20,000");
    }
}
