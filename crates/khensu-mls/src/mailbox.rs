//! Mailbox IDs (PROTOCOL.md 6.1).

use khensu_crypto::sym::h256;
use openmls::prelude::MlsGroup;
use openmls_traits::crypto::OpenMlsCrypto;

use crate::Error;

pub const EXPORTER_MAILBOX: &str = "khensu mailbox";

pub fn mailbox_id(seed: &[u8; 32], leaf_index: u32, network_epoch: u64) -> [u8; 32] {
    h256("mailbox", &[seed, &leaf_index.to_be_bytes(), &network_epoch.to_be_bytes()])
}

pub fn intro_mailbox(key_package_ref: &[u8], network_epoch: u64) -> [u8; 32] {
    h256("intro", &[key_package_ref, &network_epoch.to_be_bytes()])
}

pub fn mailbox_seed(group: &MlsGroup, crypto: &impl OpenMlsCrypto) -> Result<[u8; 32], Error> {
    let s = group.export_secret(crypto, EXPORTER_MAILBOX, &[], 32).map_err(|_| Error::Mls)?;
    Ok(s.try_into().expect("requested 32 bytes"))
}

/// The four IDs a device watches for one group: current and previous group
/// epoch seeds, for the current and previous network epoch.
pub fn watched(current_seed: &[u8; 32], previous_seed: Option<&[u8; 32]>, leaf: u32, n_epoch: u64) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(4);
    for seed in std::iter::once(current_seed).chain(previous_seed) {
        out.push(mailbox_id(seed, leaf, n_epoch));
        if n_epoch > 0 {
            out.push(mailbox_id(seed, leaf, n_epoch - 1));
        }
    }
    out
}
