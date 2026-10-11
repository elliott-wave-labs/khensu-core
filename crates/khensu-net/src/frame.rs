// SPDX-License-Identifier: Apache-2.0
//! Link frames. Every frame is padded to one of two sizes, the small-packet
//! class (1 + 10,248 bytes) and the bulk class (1 + 73,736 bytes), so a sealed
//! frame reveals only its class.
//!
//! ```text
//! enum { packet(1), deliver(2), subscribe(3), padding(4), (255) } FrameType;
//! packet:    a mix packet of the class's lane
//! deliver:   opaque payload_key_ref[16]; opaque payload[lane payload]   (entry node to client, SURB replies)
//! subscribe: opaque delivery_id[32]                                       (client to entry node, small class)
//! padding:   zeros
//! ```

use khensu_outfox::{BULK_PACKET, Lane, SMALL_PACKET};

use crate::{Error, Result};

pub const SMALL_FRAME: usize = 1 + SMALL_PACKET;
pub const BULK_FRAME: usize = 1 + BULK_PACKET;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Packet(Vec<u8>),
    Deliver { payload_key_ref: [u8; 16], payload: Vec<u8> },
    Subscribe { delivery_id: [u8; 32] },
    Padding(Lane),
}

fn class_len(lane: Lane) -> usize {
    match lane {
        Lane::Small => SMALL_FRAME,
        Lane::Bulk => BULK_FRAME,
    }
}

impl Frame {
    pub fn lane(&self) -> Lane {
        match self {
            Frame::Packet(p) if p.len() == BULK_PACKET => Lane::Bulk,
            Frame::Deliver { payload, .. } if payload.len() == Lane::Bulk.payload_len() => Lane::Bulk,
            Frame::Padding(l) => *l,
            _ => Lane::Small,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let lane = self.lane();
        let mut out = Vec::with_capacity(class_len(lane));
        match self {
            Frame::Packet(p) => {
                out.push(1);
                out.extend_from_slice(p);
            }
            Frame::Deliver { payload_key_ref, payload } => {
                out.push(2);
                out.extend_from_slice(payload_key_ref);
                out.extend_from_slice(payload);
            }
            Frame::Subscribe { delivery_id } => {
                out.push(3);
                out.extend_from_slice(delivery_id);
            }
            Frame::Padding(_) => out.push(4),
        }
        out.resize(class_len(lane), 0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let lane = match bytes.len() {
            SMALL_FRAME => Lane::Small,
            BULK_FRAME => Lane::Bulk,
            _ => return Err(Error::Length),
        };
        let (ty, body) = bytes.split_first().ok_or(Error::Length)?;
        let zero_after = |n: usize| body[n..].iter().all(|&b| b == 0);
        match ty {
            1 => Ok(Frame::Packet(body.to_vec())),
            2 => {
                let n = 16 + lane.payload_len();
                if !zero_after(n) {
                    return Err(Error::Decode);
                }
                Ok(Frame::Deliver {
                    payload_key_ref: body[..16].try_into().expect("16 bytes"),
                    payload: body[16..n].to_vec(),
                })
            }
            3 if lane == Lane::Small && zero_after(32) => {
                Ok(Frame::Subscribe { delivery_id: body[..32].try_into().expect("32 bytes") })
            }
            4 => Ok(Frame::Padding(lane)),
            _ => Err(Error::Decode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use khensu_outfox::{BULK_PAYLOAD, SMALL_PAYLOAD};

    #[test]
    fn roundtrip_all_types() {
        let frames = [
            Frame::Packet(vec![7; SMALL_PACKET]),
            Frame::Packet(vec![8; BULK_PACKET]),
            Frame::Deliver { payload_key_ref: [1; 16], payload: vec![2; SMALL_PAYLOAD] },
            Frame::Deliver { payload_key_ref: [3; 16], payload: vec![4; BULK_PAYLOAD] },
            Frame::Subscribe { delivery_id: [5; 32] },
            Frame::Padding(Lane::Small),
            Frame::Padding(Lane::Bulk),
        ];
        for f in frames {
            let e = f.encode();
            assert!(e.len() == SMALL_FRAME || e.len() == BULK_FRAME);
            assert_eq!(Frame::decode(&e).unwrap(), f);
        }
        assert!(Frame::decode(&[0; 10]).is_err());
    }
}
