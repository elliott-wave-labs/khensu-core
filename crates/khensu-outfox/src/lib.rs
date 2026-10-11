// SPDX-License-Identifier: Apache-2.0
//! Outfox mix packets, extended (PROTOCOL.md section 8).
//!
//! A packet is a fixed 8,200-byte header (five 1,640-byte hop slots, each an
//! ML-KEM-1024 ciphertext plus AEAD-sealed routing info) followed by a
//! Lioness-encrypted payload of the lane's size. See `README.md` for the exact
//! layering and the decisions taken where the spec is open.

pub mod delivery;
pub mod epoch;
pub mod lioness;
pub mod packet;
pub mod replay;
pub mod routing;
pub mod surb;

pub use packet::{Hop, Packet, Processed, forward, process};
pub use routing::RoutingInfo;
pub use surb::{Surb, SurbKeys};

use khensu_crypto::kem;

pub const MAX_HOPS: usize = 5;
pub const ROUTING_LEN: usize = 56;
pub const ROUTING_CT_LEN: usize = ROUTING_LEN + 16;
pub const HOP_HEADER_LEN: usize = kem::CIPHERTEXT_LEN + ROUTING_CT_LEN;
pub const HEADER_LEN: usize = MAX_HOPS * HOP_HEADER_LEN;
pub const SMALL_PAYLOAD: usize = 2048;
pub const BULK_PAYLOAD: usize = 65_536;
pub const SMALL_PACKET: usize = HEADER_LEN + SMALL_PAYLOAD;
pub const BULK_PACKET: usize = HEADER_LEN + BULK_PAYLOAD;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Lane {
    Small = 0,
    Bulk = 1,
}

impl Lane {
    pub fn payload_len(self) -> usize {
        match self {
            Lane::Small => SMALL_PAYLOAD,
            Lane::Bulk => BULK_PAYLOAD,
        }
    }

    pub fn packet_len(self) -> usize {
        HEADER_LEN + self.payload_len()
    }

    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Lane::Small),
            1 => Ok(Lane::Bulk),
            _ => Err(Error::Decode),
        }
    }

    pub fn for_payload_len(len: usize) -> Result<Self> {
        match len {
            SMALL_PAYLOAD => Ok(Lane::Small),
            BULK_PAYLOAD => Ok(Lane::Bulk),
            _ => Err(Error::Length),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid length")]
    Length,
    #[error("decode error")]
    Decode,
    #[error("routing info failed to decrypt")]
    Decrypt,
    #[error("payload failed its integrity check")]
    Integrity,
    #[error("route must have 1 to 5 hops")]
    Hops,
    #[error("lane does not match the packet size")]
    Lane,
    #[error("does not fit the lane payload")]
    TooLarge,
    #[error("signature verification failed")]
    BadSignature,
    #[error("crypto error")]
    Crypto,
}

impl From<khensu_crypto::Error> for Error {
    fn from(e: khensu_crypto::Error) -> Self {
        match e {
            khensu_crypto::Error::Length => Error::Length,
            khensu_crypto::Error::BadSignature => Error::BadSignature,
            khensu_crypto::Error::Decrypt => Error::Decrypt,
            _ => Error::Crypto,
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Samples an exponential delay with the given mean, as the per-mix Poisson
/// delay of 8.2.
pub fn sample_delay_ms(rng: &mut impl rand::RngCore, mean_ms: u32) -> u32 {
    if mean_ms == 0 {
        return 0;
    }
    // Uniform in (0, 1]; avoids ln(0).
    let u = ((rng.next_u64() >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
    let d = -u.ln() * mean_ms as f64;
    d.min(60.0 * mean_ms as f64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn sizes_match_protocol() {
        assert_eq!(HOP_HEADER_LEN, 1640);
        assert_eq!(HEADER_LEN, 8200);
        assert_eq!(SMALL_PACKET, 10_248);
        assert_eq!(BULK_PACKET, 73_736);
    }

    #[test]
    fn delay_mean() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let n = 20_000;
        let sum: u64 = (0..n).map(|_| sample_delay_ms(&mut rng, 250) as u64).sum();
        let mean = sum as f64 / n as f64;
        assert!((mean - 250.0).abs() < 10.0, "mean {mean}");
    }
}
