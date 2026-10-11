// SPDX-License-Identifier: Apache-2.0
//! Account identity (PROTOCOL.md 3.1-3.3): an identity key, its inception log
//! entry and the address derived from it.

use bech32::{Bech32m, Hrp};
use khensu_crypto::sym::{h, sha3_256};
use khensu_crypto::{SigKeyPair, write_vec};

use crate::KhensuError;

pub struct Identity {
    pub key: SigKeyPair,
    pub inception: Vec<u8>,
    pub address: [u8; 32],
}

impl Identity {
    /// Creates an identity key and its signed inception `LogEntry`. The
    /// recovery key only contributes its commitment; v0.1 has no recovery
    /// phrase, so it is discarded.
    pub fn create(network_epoch: u64) -> Result<Self, KhensuError> {
        let key = SigKeyPair::generate()?;
        let recovery = SigKeyPair::generate()?;
        let next_key_commitment = h("next key", &[&recovery.public().0]);
        drop(recovery);

        let mut e = vec![1u8];
        e.extend_from_slice(&[0; 32]);
        e.extend_from_slice(&0u64.to_be_bytes());
        e.extend_from_slice(&[0; 64]);
        e.extend_from_slice(&network_epoch.to_be_bytes());
        write_vec(&mut e, &key.public().0);
        e.extend_from_slice(&next_key_commitment);
        e.extend_from_slice(&0u16.to_be_bytes());
        let sig = key.sign("log entry", &e)?;
        write_vec(&mut e, &sig.0);
        Ok(Self::from_parts(key, e))
    }

    pub fn from_parts(key: SigKeyPair, inception: Vec<u8>) -> Self {
        let address = sha3_256("address", &[&inception]);
        Self { key, inception, address }
    }
}

/// `khensu1...` (bech32m).
pub fn display_address(address: &[u8; 32]) -> String {
    bech32::encode::<Bech32m>(Hrp::parse("khensu").expect("valid HRP"), address).expect("32 bytes fit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_stable_and_bech32m() {
        let id = Identity::create(5).unwrap();
        let again = Identity::from_parts(id.key.clone(), id.inception.clone());
        assert_eq!(id.address, again.address);
        let s = display_address(&id.address);
        assert!(s.starts_with("khensu1"), "{s}");
        let (hrp, data) = bech32::decode(&s).unwrap();
        assert_eq!(hrp.as_str(), "khensu");
        assert_eq!(data, id.address);
    }
}
