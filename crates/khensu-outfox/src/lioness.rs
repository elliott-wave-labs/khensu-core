// SPDX-License-Identifier: Apache-2.0
//! `WBC`: Lioness with AES-256-CTR and HMAC-SHA-512 (PROTOCOL.md section 1).
//!
//! The block is split into `L` (32 bytes, the AES-256 key size) and `R`.
//! Encryption: `R ^= S(L ^ K1); L ^= H(K2, R); R ^= S(L ^ K3); L ^= H(K4, R)`,
//! with `S` the AES-256-CTR keystream (zero IV) and `H` HMAC-SHA-512
//! truncated to 32 bytes.

use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

pub const KEY_LEN: usize = 192;
const L_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LionessKey([u8; KEY_LEN]);

impl LionessKey {
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn k1(&self) -> &[u8] {
        &self.0[..32]
    }
    fn k2(&self) -> &[u8] {
        &self.0[32..96]
    }
    fn k3(&self) -> &[u8] {
        &self.0[96..128]
    }
    fn k4(&self) -> &[u8] {
        &self.0[128..]
    }

    pub fn encrypt(&self, block: &mut [u8]) -> Result<()> {
        let (l, r) = split(block)?;
        stream(self.k1(), l, r);
        mac(self.k2(), r, l);
        stream(self.k3(), l, r);
        mac(self.k4(), r, l);
        Ok(())
    }

    pub fn decrypt(&self, block: &mut [u8]) -> Result<()> {
        let (l, r) = split(block)?;
        mac(self.k4(), r, l);
        stream(self.k3(), l, r);
        mac(self.k2(), r, l);
        stream(self.k1(), l, r);
        Ok(())
    }
}

fn split(block: &mut [u8]) -> Result<(&mut [u8], &mut [u8])> {
    if block.len() <= L_LEN {
        return Err(Error::Length);
    }
    Ok(block.split_at_mut(L_LEN))
}

fn stream(k: &[u8], l: &[u8], r: &mut [u8]) {
    let mut key = [0u8; 32];
    for (o, (a, b)) in key.iter_mut().zip(k.iter().zip(l)) {
        *o = a ^ b;
    }
    Ctr128BE::<Aes256>::new(&key.into(), &[0u8; 16].into()).apply_keystream(r);
    key.zeroize();
}

fn mac(k: &[u8], r: &[u8], l: &mut [u8]) {
    let mut m = Hmac::<Sha512>::new_from_slice(k).expect("HMAC takes any key length");
    m.update(r);
    let tag = m.finalize().into_bytes();
    for (o, t) in l.iter_mut().zip(tag.iter()) {
        *o ^= t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_diffusion() {
        let key = LionessKey::new(core::array::from_fn(|i| i as u8));
        let plain: Vec<u8> = (0..2048u32).map(|i| (i * 31) as u8).collect();
        let mut block = plain.clone();
        key.encrypt(&mut block).unwrap();
        assert_ne!(block, plain);
        let mut flipped = block.clone();
        flipped[1500] ^= 1;
        key.decrypt(&mut block).unwrap();
        assert_eq!(block, plain);
        key.decrypt(&mut flipped).unwrap();
        let differing = flipped.iter().zip(&plain).filter(|(a, b)| a != b).count();
        assert!(differing > 1900, "one flipped bit should scramble the block, got {differing}");
    }

    #[test]
    fn rejects_short_blocks() {
        let key = LionessKey::new([0; KEY_LEN]);
        assert_eq!(key.encrypt(&mut [0u8; 32]), Err(Error::Length));
    }
}
