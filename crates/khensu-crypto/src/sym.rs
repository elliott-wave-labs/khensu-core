//! Hashes, HKDF-SHA-512 and AES-256-GCM, all with khensu labels.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha512, Sha512_256};

use crate::{Error, Result, label};

/// `H(Label(l) || parts...)` with SHA-512.
pub fn h(l: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut d = Sha512::new();
    d.update(label(l));
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// `H256(Label(l) || parts...)` with SHA-512/256.
pub fn h256(l: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha512_256::new();
    d.update(label(l));
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// SHA3-256 over the label and parts (used for addresses).
pub fn sha3_256(l: &str, parts: &[&[u8]]) -> [u8; 32] {
    use sha3::Sha3_256;
    let mut d = Sha3_256::new();
    d.update(label(l));
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// HKDF-SHA-512: extract with `salt`, expand with `Label(l)` as info.
pub fn kdf<const N: usize>(ikm: &[u8], salt: &[u8], l: &str) -> [u8; N] {
    let hk = hkdf::Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut out = [0u8; N];
    hk.expand(&label(l), &mut out).expect("output length within HKDF limit");
    out
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("AES-GCM encryption does not fail for in-range inputs")
}

pub fn open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_separate_domains() {
        assert_ne!(h256("a", &[b"x"]), h256("b", &[b"x"]));
        assert_ne!(kdf::<32>(b"k", b"", "a"), kdf::<32>(b"k", b"", "b"));
    }

    #[test]
    fn aead_roundtrip() {
        let ct = seal(&[1; 32], &[2; 12], b"msg", b"aad");
        assert_eq!(open(&[1; 32], &[2; 12], &ct, b"aad").unwrap(), b"msg");
        assert!(open(&[1; 32], &[2; 12], &ct, b"bad").is_err());
    }
}
