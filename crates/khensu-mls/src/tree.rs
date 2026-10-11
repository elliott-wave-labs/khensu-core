// SPDX-License-Identifier: Apache-2.0
//! Ratchet-tree delivery by content address (PROTOCOL.md 6.5).
//!
//! The Welcome carries a `TreeManifest`; the joiner fetches each 64 KiB chunk
//! from the mailbox replicas with `tree_get` and checks it by hash.

use khensu_crypto::sym::{h, h256};
use khensu_crypto::{Reader, write_vec};

use crate::Error;

/// 64 KiB minus the `tree_put` / `tree_get` framing, so a chunk fits one bulk
/// payload in both directions (khensu-outfox `TREE_CHUNK_MAX`).
pub const CHUNK_SIZE: usize = 64 * 1024 - 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeManifest {
    /// H over the whole serialized tree.
    pub tree_hash: [u8; 64],
    pub chunk_hashes: Vec<[u8; 32]>,
}

pub fn chunk_address(chunk: &[u8]) -> [u8; 32] {
    h256("tree chunk", &[chunk])
}

/// Splits a serialized ratchet tree into chunks and their manifest.
pub fn chunk_tree(tree: &[u8]) -> (TreeManifest, Vec<Vec<u8>>) {
    let chunks: Vec<Vec<u8>> = tree.chunks(CHUNK_SIZE).map(<[u8]>::to_vec).collect();
    let manifest = TreeManifest {
        tree_hash: h("tree", &[tree]),
        chunk_hashes: chunks.iter().map(|c| chunk_address(c)).collect(),
    };
    (manifest, chunks)
}

/// Reassembles chunks fetched by address; any substituted chunk fails.
pub fn assemble(manifest: &TreeManifest, mut fetch: impl FnMut(&[u8; 32]) -> Option<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let mut tree = Vec::with_capacity(manifest.chunk_hashes.len() * CHUNK_SIZE);
    for addr in &manifest.chunk_hashes {
        let chunk = fetch(addr).ok_or(Error::NotInLog)?;
        if &chunk_address(&chunk) != addr || chunk.len() > CHUNK_SIZE {
            return Err(Error::Decode);
        }
        tree.extend_from_slice(&chunk);
    }
    if h("tree", &[&tree]) != manifest.tree_hash {
        return Err(Error::Decode);
    }
    Ok(tree)
}

impl TreeManifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.tree_hash);
        write_vec(&mut out, &self.chunk_hashes.concat());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let tree_hash = r.array()?;
        let hashes = r.vec()?;
        r.finish()?;
        if hashes.len() % 32 != 0 {
            return Err(Error::Decode);
        }
        Ok(Self {
            tree_hash,
            chunk_hashes: hashes.chunks(32).map(|c| c.try_into().expect("32 bytes")).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn roundtrip_and_tamper() {
        let tree: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
        let (m, chunks) = chunk_tree(&tree);
        assert_eq!(m.chunk_hashes.len(), 4);
        let m = TreeManifest::decode(&m.encode()).unwrap();
        let mut store: HashMap<[u8; 32], Vec<u8>> =
            chunks.into_iter().map(|c| (chunk_address(&c), c)).collect();
        assert_eq!(assemble(&m, |a| store.get(a).cloned()).unwrap(), tree);
        let first = m.chunk_hashes[0];
        store.get_mut(&first).unwrap()[0] ^= 1;
        assert_eq!(assemble(&m, |a| store.get(a).cloned()), Err(Error::Decode));
    }
}
