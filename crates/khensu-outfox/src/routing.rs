// SPDX-License-Identifier: Apache-2.0
//! `RoutingInfo` (PROTOCOL.md 8.2).

use khensu_crypto::Reader;

use crate::{Error, Lane, ROUTING_LEN, Result};

pub const FLAG_FINAL: u8 = 1 << 0;
/// Only ever set inside a final payload; a header carrying it is rejected.
pub const FLAG_LOOP: u8 = 1 << 1;
/// Final hop of a SURB path: `next_node_id` is the client's delivery ID and
/// `reserved[..16]` is the SURB's `payload_key_ref`.
pub const FLAG_REPLY: u8 = 1 << 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingInfo {
    pub next_node_id: [u8; 32],
    pub delay_ms: u32,
    pub flags: u8,
    pub lane: Lane,
    pub reserved: [u8; 18],
}

impl RoutingInfo {
    pub fn relay(next_node_id: [u8; 32], delay_ms: u32, lane: Lane) -> Self {
        Self { next_node_id, delay_ms, flags: 0, lane, reserved: [0; 18] }
    }

    pub fn is_final(&self) -> bool {
        self.flags & FLAG_FINAL != 0
    }

    pub fn is_reply(&self) -> bool {
        self.flags & FLAG_REPLY != 0
    }

    /// The 16-byte tag in `reserved`: payload digest on a forward final hop,
    /// `payload_key_ref` on a reply final hop.
    pub fn tag16(&self) -> [u8; 16] {
        self.reserved[..16].try_into().expect("16 bytes")
    }

    pub fn encode(&self) -> [u8; ROUTING_LEN] {
        let mut out = [0u8; ROUTING_LEN];
        out[..32].copy_from_slice(&self.next_node_id);
        out[32..36].copy_from_slice(&self.delay_ms.to_be_bytes());
        out[36] = self.flags;
        out[37] = self.lane as u8;
        out[38..].copy_from_slice(&self.reserved);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let ri = Self {
            next_node_id: r.array()?,
            delay_ms: r.u32()?,
            flags: r.u8()?,
            lane: Lane::from_u8(r.u8()?)?,
            reserved: r.array()?,
        };
        r.finish()?;
        let known = FLAG_FINAL | FLAG_REPLY;
        if ri.flags & !known != 0 || (ri.is_reply() && !ri.is_final()) {
            return Err(Error::Decode);
        }
        if !ri.is_final() && ri.reserved != [0; 18] {
            return Err(Error::Decode);
        }
        Ok(ri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reject_loop_flag() {
        let ri = RoutingInfo::relay([9; 32], 1234, Lane::Bulk);
        assert_eq!(RoutingInfo::decode(&ri.encode()).unwrap(), ri);
        let mut bad = ri.encode();
        bad[36] = FLAG_LOOP;
        assert_eq!(RoutingInfo::decode(&bad), Err(Error::Decode));
        bad[36] = FLAG_REPLY;
        assert_eq!(RoutingInfo::decode(&bad), Err(Error::Decode));
    }
}
