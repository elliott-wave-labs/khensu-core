// SPDX-License-Identifier: Apache-2.0
//! Client-to-client structures that ride inside fragments. v0.1 additions to
//! PROTOCOL.md, listed in `ffi/SWIFT-API.md`:
//!
//! ```text
//! enum { mls(1), chunked(2), intro(3), (255) } EnvelopeType;
//! struct {
//!   EnvelopeType type;
//!   select (type) {
//!     case mls:     opaque mls_message<V>;            // MlsMessageOut, PrivateMessage only
//!     case chunked: TreeManifest manifest;            // an mls_message too large for bucket 8, in content-addressed chunks
//!     case intro:   opaque kem_ct[1568]; opaque sealed<V>;   // to the contact card's intro key
//!   };
//! } Envelope;
//!
//! struct { opaque welcome<V>; opaque tree_key[32]; opaque manifest<V>; opaque title<V>; } IntroBundle;
//! sealed = AEAD(KDF(ss, Label("intro bundle")), zero_nonce, IntroBundle, aad = kp_ref)
//!
//! struct {
//!   uint8  version;            // 1
//!   opaque key_package<V>;     // one-time MLS KeyPackage
//!   opaque intro_ek[1568];     // ML-KEM-1024 key for the IntroBundle
//!   opaque display_name<V>;
//!   opaque signature<V>;       // Sign(leaf signature key, "contact card", fields above)
//! } ContactCard;
//! ```

use khensu_crypto::kem::CIPHERTEXT_LEN;
use khensu_crypto::{Reader, SigKeyPair, SigPublicKey, Signature, write_vec};
use khensu_mls::tree::TreeManifest;

use crate::KhensuError;

fn dec(_: impl core::fmt::Debug) -> KhensuError {
    KhensuError::Invalid { msg: "malformed message".into() }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope {
    Mls(Vec<u8>),
    Chunked(TreeManifest),
    Intro { kem_ct: Vec<u8>, sealed: Vec<u8> },
}

impl Envelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Envelope::Mls(m) => {
                out.push(1);
                write_vec(&mut out, m);
            }
            Envelope::Chunked(m) => {
                out.push(2);
                out.extend_from_slice(&m.encode());
            }
            Envelope::Intro { kem_ct, sealed } => {
                out.push(3);
                out.extend_from_slice(kem_ct);
                write_vec(&mut out, sealed);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KhensuError> {
        let mut r = Reader::new(bytes);
        let env = match r.u8().map_err(dec)? {
            1 => Envelope::Mls(r.vec().map_err(dec)?.to_vec()),
            2 => return TreeManifest::decode(r.take(r.remaining()).map_err(dec)?).map(Envelope::Chunked).map_err(dec),
            3 => Envelope::Intro {
                kem_ct: r.take(CIPHERTEXT_LEN).map_err(dec)?.to_vec(),
                sealed: r.vec().map_err(dec)?.to_vec(),
            },
            _ => return Err(dec(())),
        };
        r.finish().map_err(dec)?;
        Ok(env)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntroBundle {
    pub welcome: Vec<u8>,
    pub tree_key: [u8; 32],
    pub manifest: TreeManifest,
    pub title: String,
}

impl IntroBundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_vec(&mut out, &self.welcome);
        out.extend_from_slice(&self.tree_key);
        write_vec(&mut out, &self.manifest.encode());
        write_vec(&mut out, self.title.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KhensuError> {
        let mut r = Reader::new(bytes);
        let welcome = r.vec().map_err(dec)?.to_vec();
        let tree_key = r.array().map_err(dec)?;
        let manifest = TreeManifest::decode(r.vec().map_err(dec)?).map_err(dec)?;
        let title = String::from_utf8(r.vec().map_err(dec)?.to_vec()).map_err(dec)?;
        r.finish().map_err(dec)?;
        Ok(Self { welcome, tree_key, manifest, title })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCard {
    pub key_package: Vec<u8>,
    pub intro_ek: Vec<u8>,
    pub display_name: String,
    pub signature: Vec<u8>,
}

impl ContactCard {
    fn tbs(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        write_vec(&mut out, &self.key_package);
        out.extend_from_slice(&self.intro_ek);
        write_vec(&mut out, self.display_name.as_bytes());
        out
    }

    pub fn signed(key_package: Vec<u8>, intro_ek: Vec<u8>, display_name: String, leaf_key: &SigKeyPair) -> Result<Self, KhensuError> {
        let mut c = Self { key_package, intro_ek, display_name, signature: Vec::new() };
        c.signature = leaf_key.sign("contact card", &c.tbs())?.0;
        Ok(c)
    }

    pub fn verify(&self, leaf_signature_key: &[u8]) -> Result<(), KhensuError> {
        SigPublicKey(leaf_signature_key.to_vec())
            .verify("contact card", &self.tbs(), &Signature(self.signature.clone()))
            .map_err(|_| KhensuError::Invalid { msg: "contact card signature".into() })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        write_vec(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KhensuError> {
        let mut r = Reader::new(bytes);
        if r.u8().map_err(dec)? != 1 {
            return Err(KhensuError::Invalid { msg: "contact card version".into() });
        }
        let c = Self {
            key_package: r.vec().map_err(dec)?.to_vec(),
            intro_ek: r.take(khensu_crypto::kem::PUBLIC_KEY_LEN).map_err(dec)?.to_vec(),
            display_name: String::from_utf8(r.vec().map_err(dec)?.to_vec()).map_err(dec)?,
            signature: r.vec().map_err(dec)?.to_vec(),
        };
        r.finish().map_err(dec)?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs() {
        let m = TreeManifest { tree_hash: [1; 64], chunk_hashes: vec![[2; 32], [3; 32]] };
        for e in [
            Envelope::Mls(vec![1, 2, 3]),
            Envelope::Chunked(m.clone()),
            Envelope::Intro { kem_ct: vec![4; CIPHERTEXT_LEN], sealed: vec![5; 99] },
        ] {
            assert_eq!(Envelope::decode(&e.encode()).unwrap(), e);
        }
        let b = IntroBundle { welcome: vec![6; 10], tree_key: [7; 32], manifest: m, title: "t".into() };
        assert_eq!(IntroBundle::decode(&b.encode()).unwrap(), b);

        let key = SigKeyPair::from_seed([8; 32]);
        let card = ContactCard::signed(vec![9; 40], vec![1; 1568], "Ana".into(), &key).unwrap();
        let back = ContactCard::decode(&card.encode()).unwrap();
        back.verify(&key.public().0).unwrap();
        let mut forged = back;
        forged.display_name = "Eve".into();
        assert!(forged.verify(&key.public().0).is_err());
    }
}
