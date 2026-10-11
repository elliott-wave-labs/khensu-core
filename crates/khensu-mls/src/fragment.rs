// SPDX-License-Identifier: Apache-2.0
//! Splitting a serialized PrivateMessage into small-lane fragments (PROTOCOL.md 5.3).

use std::collections::HashMap;

use khensu_crypto::{Reader, random, write_vec};

use crate::Error;

/// Payload bytes of one small mix packet.
pub const SMALL_PAYLOAD: usize = 2048;
/// An encoded fragment travels as the `sealed` field of a small-lane mailbox
/// `store`, whose framing takes 40 bytes of the payload (khensu-outfox
/// `SMALL_STORE_MAX_SEALED`).
pub const FRAGMENT_LEN: usize = SMALL_PAYLOAD - 40;
/// Fixed data length inside each fragment: FRAGMENT_LEN minus msg_ref (16),
/// index, count and the 2-byte length of `data`.
pub const FRAGMENT_DATA: usize = FRAGMENT_LEN - 20;
pub const BUCKETS: [u8; 4] = [3, 4, 6, 8];
/// Incomplete sets are dropped after this long.
pub const REASSEMBLY_TTL_SECS: u64 = 7 * 24 * 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub msg_ref: [u8; 16],
    pub index: u8,
    pub count: u8,
    pub data: Vec<u8>,
}

impl Fragment {
    /// Encodes to exactly `FRAGMENT_LEN` bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_LEN);
        out.extend_from_slice(&self.msg_ref);
        out.push(self.index);
        out.push(self.count);
        write_vec(&mut out, &self.data);
        debug_assert_eq!(out.len(), FRAGMENT_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FRAGMENT_LEN {
            return Err(Error::Decode);
        }
        let mut r = Reader::new(bytes);
        let msg_ref = r.array()?;
        let index = r.u8()?;
        let count = r.u8()?;
        let data = r.vec()?.to_vec();
        r.finish()?;
        if !BUCKETS.contains(&count) || index >= count || data.len() != FRAGMENT_DATA {
            return Err(Error::Decode);
        }
        Ok(Self { msg_ref, index, count, data })
    }
}

/// Smallest bucket that fits `len` bytes plus the 4-byte length prefix.
pub fn bucket_for(len: usize) -> Result<u8, Error> {
    BUCKETS
        .iter()
        .copied()
        .find(|&b| b as usize * FRAGMENT_DATA >= len + 4)
        .ok_or(Error::TooLarge)
}

/// Splits `message` into a full bucket of fragments, each carrying exactly
/// `FRAGMENT_DATA` bytes so all fragments look alike.
pub fn split(message: &[u8]) -> Result<Vec<Fragment>, Error> {
    let count = bucket_for(message.len())?;
    let msg_ref = random::<16>().map_err(|_| Error::Rng)?;
    let mut padded = Vec::with_capacity(count as usize * FRAGMENT_DATA);
    padded.extend_from_slice(&(message.len() as u32).to_be_bytes());
    padded.extend_from_slice(message);
    padded.resize(count as usize * FRAGMENT_DATA, 0);
    Ok(padded
        .chunks(FRAGMENT_DATA)
        .enumerate()
        .map(|(i, chunk)| Fragment { msg_ref, index: i as u8, count, data: chunk.to_vec() })
        .collect())
}

struct Partial {
    first_seen: u64,
    count: u8,
    parts: Vec<Option<Vec<u8>>>,
}

/// Reassembles fragments arriving in any order.
#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<[u8; 16], Partial>,
}

impl Reassembler {
    /// Returns the full message once its last fragment arrives.
    pub fn push(&mut self, f: Fragment, now: u64) -> Result<Option<Vec<u8>>, Error> {
        let p = self.pending.entry(f.msg_ref).or_insert_with(|| Partial {
            first_seen: now,
            count: f.count,
            parts: vec![None; f.count as usize],
        });
        if p.count != f.count {
            return Err(Error::Decode);
        }
        p.parts[f.index as usize] = Some(f.data);
        if p.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let p = self.pending.remove(&f.msg_ref).expect("present");
        let joined: Vec<u8> = p.parts.into_iter().flatten().flatten().collect();
        let len = u32::from_be_bytes(joined[..4].try_into().expect("4 bytes")) as usize;
        if len + 4 > joined.len() || joined[4 + len..].iter().any(|&b| b != 0) {
            return Err(Error::Decode);
        }
        Ok(Some(joined[4..4 + len].to_vec()))
    }

    pub fn expire(&mut self, now: u64) {
        self.pending.retain(|_, p| now.saturating_sub(p.first_seen) < REASSEMBLY_TTL_SECS);
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets() {
        assert_eq!(bucket_for(0).unwrap(), 3);
        assert_eq!(bucket_for(3 * FRAGMENT_DATA - 4).unwrap(), 3);
        assert_eq!(bucket_for(3 * FRAGMENT_DATA - 3).unwrap(), 4);
        assert_eq!(bucket_for(8 * FRAGMENT_DATA - 4).unwrap(), 8);
        assert_eq!(bucket_for(8 * FRAGMENT_DATA), Err(Error::TooLarge));
    }

    #[test]
    fn split_reassemble_out_of_order() {
        let msg: Vec<u8> = (0..7000u32).map(|i| i as u8).collect();
        let mut frags = split(&msg).unwrap();
        assert_eq!(frags.len(), 4);
        frags.reverse();
        let mut r = Reassembler::default();
        let mut out = None;
        for f in frags {
            let wire = f.encode();
            assert_eq!(wire.len(), FRAGMENT_LEN);
            out = r.push(Fragment::decode(&wire).unwrap(), 0).unwrap();
        }
        assert_eq!(out.unwrap(), msg);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn expiry() {
        let mut r = Reassembler::default();
        let f = split(b"hi").unwrap().remove(0);
        assert!(r.push(f, 0).unwrap().is_none());
        r.expire(REASSEMBLY_TTL_SECS);
        assert_eq!(r.pending(), 0);
    }
}
