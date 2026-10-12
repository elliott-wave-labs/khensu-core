// SPDX-License-Identifier: Apache-2.0
//! Link frames. Every frame is padded to one of two sizes, the small-packet
//! class (1 + 10,248 bytes) and the bulk class (1 + 73,736 bytes), so a sealed
//! frame reveals only its class.
//!
//! ```text
//! enum { packet(1), deliver(2), subscribe(3), padding(4), control(5), (255) } FrameType;
//! packet:    a mix packet of the class's lane
//! deliver:   opaque payload_key_ref[16]; opaque payload[lane payload]   (entry node to client, SURB replies)
//! subscribe: opaque delivery_id[32]                                       (client to entry node, small class)
//! padding:   zeros
//! control:   uint32 msg_id; uint16 part; uint16 parts; opaque body<V>    (one part of a control message, either class)
//! ```

use khensu_outfox::{BULK_PACKET, Lane, SMALL_PACKET};

use crate::{Error, Result};

pub const SMALL_FRAME: usize = 1 + SMALL_PACKET;
pub const BULK_FRAME: usize = 1 + BULK_PACKET;
/// Largest control part body in a small-class frame.
pub const SMALL_CONTROL: usize = SMALL_FRAME - 1 - 8 - 4;
/// Largest control part body in a bulk-class frame.
pub const BULK_CONTROL: usize = BULK_FRAME - 1 - 8 - 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlPart {
    pub msg_id: u32,
    pub part: u16,
    pub parts: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Packet(Vec<u8>),
    Deliver { payload_key_ref: [u8; 16], payload: Vec<u8> },
    Subscribe { delivery_id: [u8; 32] },
    Padding(Lane),
    Control(ControlPart),
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
            Frame::Control(c) if c.body.len() > SMALL_CONTROL => Lane::Bulk,
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
            Frame::Control(c) => {
                out.push(5);
                out.extend_from_slice(&c.msg_id.to_be_bytes());
                out.extend_from_slice(&c.part.to_be_bytes());
                out.extend_from_slice(&c.parts.to_be_bytes());
                out.extend_from_slice(&(c.body.len() as u32).to_be_bytes());
                out.extend_from_slice(&c.body);
            }
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
            5 => {
                let msg_id = u32::from_be_bytes(body[..4].try_into().expect("4 bytes"));
                let part = u16::from_be_bytes(body[4..6].try_into().expect("2 bytes"));
                let parts = u16::from_be_bytes(body[6..8].try_into().expect("2 bytes"));
                let len = u32::from_be_bytes(body[8..12].try_into().expect("4 bytes")) as usize;
                let max = match lane {
                    Lane::Small => SMALL_CONTROL,
                    Lane::Bulk => BULK_CONTROL,
                };
                if len > max || parts == 0 || part >= parts || !zero_after(12 + len) {
                    return Err(Error::Decode);
                }
                Ok(Frame::Control(ControlPart { msg_id, part, parts, body: body[12..12 + len].to_vec() }))
            }
            _ => Err(Error::Decode),
        }
    }

    /// Splits a control message into frames: one small frame when it fits,
    /// else as many bulk frames as it takes.
    pub fn control(msg_id: u32, message: &[u8]) -> Vec<Frame> {
        if message.len() <= SMALL_CONTROL {
            return vec![Frame::Control(ControlPart { msg_id, part: 0, parts: 1, body: message.to_vec() })];
        }
        let chunks: Vec<&[u8]> = message.chunks(BULK_CONTROL).collect();
        let parts = chunks.len() as u16;
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| Frame::Control(ControlPart { msg_id, part: i as u16, parts, body: c.to_vec() }))
            .collect()
    }
}

/// Puts control parts back together. Single-part messages pass straight
/// through; multi-part messages are collected by ID, a few at a time, so a
/// small message sent between the bulk parts of a big one does not break it.
#[derive(Default)]
pub struct ControlAssembler {
    /// In progress: (msg_id, parts, bodies), oldest first.
    pending: Vec<(u32, u16, Vec<Vec<u8>>)>,
}

/// Multi-part messages kept in progress per link.
const MAX_IN_PROGRESS: usize = 4;

impl ControlAssembler {
    /// Returns the whole message once its last part has arrived.
    pub fn push(&mut self, p: ControlPart) -> Option<Vec<u8>> {
        if p.parts == 1 {
            return Some(p.body);
        }
        if p.part >= p.parts {
            return None;
        }
        let idx = match self.pending.iter().position(|(id, parts, _)| *id == p.msg_id && *parts == p.parts) {
            Some(i) => i,
            None => {
                if self.pending.len() >= MAX_IN_PROGRESS {
                    self.pending.remove(0);
                }
                self.pending.push((p.msg_id, p.parts, vec![Vec::new(); p.parts as usize]));
                self.pending.len() - 1
            }
        };
        let bodies = &mut self.pending[idx].2;
        bodies[p.part as usize] = p.body;
        if bodies.iter().all(|b| !b.is_empty()) {
            let (_, _, bodies) = self.pending.remove(idx);
            return Some(bodies.concat());
        }
        None
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
            Frame::Control(ControlPart { msg_id: 1, part: 0, parts: 1, body: vec![9; 100] }),
            Frame::Control(ControlPart { msg_id: 2, part: 1, parts: 3, body: vec![9; BULK_CONTROL] }),
        ];
        for f in frames {
            let e = f.encode();
            assert!(e.len() == SMALL_FRAME || e.len() == BULK_FRAME);
            assert_eq!(Frame::decode(&e).unwrap(), f);
        }
        assert!(Frame::decode(&[0; 10]).is_err());
    }

    #[test]
    fn control_split_and_assemble() {
        let msg: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let frames = Frame::control(7, &msg);
        assert_eq!(frames.len(), 3);
        let mut asm = ControlAssembler::default();
        let mut out = None;
        for (i, f) in frames.into_iter().enumerate() {
            let Frame::Control(p) = Frame::decode(&f.encode()).unwrap() else { panic!() };
            out = asm.push(p);
            if i == 0 {
                // A small message between the parts of a big one passes through without harm.
                let Frame::Control(v) = Frame::control(8, b"vote").remove(0) else { panic!() };
                assert_eq!(asm.push(v).as_deref(), Some(&b"vote"[..]));
                // So does the first part of another big message.
                let Frame::Control(o) = Frame::control(9, &msg).remove(0) else { panic!() };
                assert!(asm.push(o).is_none());
            }
        }
        assert_eq!(out.unwrap(), msg);
        let small = Frame::control(8, b"hi");
        assert_eq!(small.len(), 1);
        assert_eq!(small[0].lane(), Lane::Small);
    }
}
