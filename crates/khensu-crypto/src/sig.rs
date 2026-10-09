// SPDX-License-Identifier: Apache-2.0
//! ML-DSA-87 (FIPS 204), pure mode.
//!
//! Private keys are stored as the 32-byte key-generation seed, as in
//! draft-ietf-mls-pq-ciphersuites; the expanded key is rebuilt for each signature.

use libcrux_ml_dsa::ml_dsa_87::{self, MLDSA87Signature, MLDSA87VerificationKey};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, MLDSASignature, MLDSAVerificationKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, label, random, write_vec};

pub const PUBLIC_KEY_LEN: usize = 2592;
pub const SIGNATURE_LEN: usize = 4627;
pub const SEED_LEN: usize = KEY_GENERATION_RANDOMNESS_SIZE;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigPublicKey(pub Vec<u8>);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(pub Vec<u8>);

/// A signing key held as its seed. Erased on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigKeyPair {
    seed: [u8; SEED_LEN],
    #[zeroize(skip)]
    public: SigPublicKey,
}

impl SigKeyPair {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(random()?))
    }

    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        let kp = ml_dsa_87::generate_key_pair(seed);
        let public = SigPublicKey(kp.verification_key.as_ref().to_vec());
        Self { seed, public }
    }

    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    pub fn public(&self) -> &SigPublicKey {
        &self.public
    }

    /// Raw FIPS 204 signature with an explicit context string.
    pub fn sign_raw(&self, message: &[u8], context: &[u8]) -> Result<Signature> {
        let kp = ml_dsa_87::generate_key_pair(self.seed);
        let sig = ml_dsa_87::sign(&kp.signing_key, message, context, random()?)
            .map_err(|_| Error::Signing)?;
        Ok(Signature(sig.as_ref().to_vec()))
    }

    /// `Sign(sk, label, content)` from PROTOCOL.md section 1.
    pub fn sign(&self, sig_label: &str, content: &[u8]) -> Result<Signature> {
        self.sign_raw(&sign_content(sig_label, content), &[])
    }
}

impl SigPublicKey {
    pub fn verify_raw(&self, message: &[u8], context: &[u8], sig: &[u8]) -> Result<()> {
        let pk: [u8; PUBLIC_KEY_LEN] = self.0.as_slice().try_into().map_err(|_| Error::PublicKey)?;
        let sig: [u8; SIGNATURE_LEN] = sig.try_into().map_err(|_| Error::BadSignature)?;
        let pk: MLDSA87VerificationKey = MLDSAVerificationKey::new(pk);
        let sig: MLDSA87Signature = MLDSASignature::new(sig);
        ml_dsa_87::verify(&pk, message, context, &sig).map_err(|_| Error::BadSignature)
    }

    pub fn verify(&self, sig_label: &str, content: &[u8], sig: &Signature) -> Result<()> {
        self.verify_raw(&sign_content(sig_label, content), &[], &sig.0)
    }
}

/// `struct { opaque label<V>; opaque content<V>; } SignContent;`
pub fn sign_content(sig_label: &str, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 64);
    write_vec(&mut out, &label(sig_label));
    write_vec(&mut out, content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_roundtrip() {
        let kp = SigKeyPair::generate().unwrap();
        assert_eq!(kp.public().0.len(), PUBLIC_KEY_LEN);
        let sig = kp.sign("test", b"hello").unwrap();
        assert_eq!(sig.0.len(), SIGNATURE_LEN);
        kp.public().verify("test", b"hello", &sig).unwrap();
        assert_eq!(kp.public().verify("other", b"hello", &sig), Err(Error::BadSignature));
        assert_eq!(kp.public().verify("test", b"hellp", &sig), Err(Error::BadSignature));
    }

    #[test]
    fn deterministic_from_seed() {
        let a = SigKeyPair::from_seed([7; 32]);
        let b = SigKeyPair::from_seed([7; 32]);
        assert_eq!(a.public(), b.public());
    }
}
