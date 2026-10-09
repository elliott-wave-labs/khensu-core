// SPDX-License-Identifier: Apache-2.0
//! ML-KEM-1024 (FIPS 203). Private keys are held as the 64-byte (d, z) seed.

use libcrux_ml_kem::mlkem1024::{self, MlKem1024Ciphertext, MlKem1024PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, random};

pub const PUBLIC_KEY_LEN: usize = 1568;
pub const CIPHERTEXT_LEN: usize = 1568;
pub const SHARED_SECRET_LEN: usize = 32;
pub const SEED_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KemPublicKey(pub [u8; PUBLIC_KEY_LEN]);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KemCiphertext(pub [u8; CIPHERTEXT_LEN]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemKeyPair {
    seed: [u8; SEED_LEN],
    #[zeroize(skip)]
    public: KemPublicKey,
}

impl KemKeyPair {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(random()?))
    }

    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        let kp = mlkem1024::generate_key_pair(seed);
        Self { seed, public: KemPublicKey(*kp.pk()) }
    }

    pub fn public(&self) -> &KemPublicKey {
        &self.public
    }

    pub fn decapsulate(&self, ct: &KemCiphertext) -> [u8; SHARED_SECRET_LEN] {
        let kp = mlkem1024::generate_key_pair(self.seed);
        let ct = MlKem1024Ciphertext::from(ct.0);
        mlkem1024::decapsulate(kp.private_key(), &ct)
    }
}

impl KemPublicKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::Length)?;
        if !mlkem1024::validate_public_key(&MlKem1024PublicKey::from(arr)) {
            return Err(Error::PublicKey);
        }
        Ok(Self(arr))
    }

    pub fn encapsulate(&self) -> Result<(KemCiphertext, [u8; SHARED_SECRET_LEN])> {
        let pk = MlKem1024PublicKey::from(self.0);
        let (ct, ss) = mlkem1024::encapsulate(&pk, random()?);
        Ok((KemCiphertext(*ct.as_slice()), ss))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kp = KemKeyPair::generate().unwrap();
        let pk = KemPublicKey::from_slice(&kp.public().0).unwrap();
        let (ct, ss) = pk.encapsulate().unwrap();
        assert_eq!(kp.decapsulate(&ct), ss);
        let other = KemKeyPair::generate().unwrap();
        assert_ne!(other.decapsulate(&ct), ss);
    }
}
