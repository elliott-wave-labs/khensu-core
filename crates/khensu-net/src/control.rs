// SPDX-License-Identifier: Apache-2.0
//! Control messages carried in `Frame::Control` between nodes, and from an
//! entry node to its clients. They ride inside the sealed session like every
//! other frame, so the wire shows only frame classes.
//!
//! ```text
//! enum { node_auth(1), receipt(2), submit(3), header(4), header_request(5), proposal(6), vote(7), (255) } ControlType;
//! node_auth:      opaque node_id[32]; opaque signature<V>    // Sign(node key, "link auth", binding || node_id || peer_node_id)
//! receipt:        ForwardingReceipt                           // from the receiving node to the sending node
//! submit:         struct { uint8 kind; opaque body<V>; } items<V>   // kinds: 1 receipt, 2 measurement, 3 storage, 4 lease, 5 evidence
//! header:         HeaderBundle
//! header_request: uint64 have_epoch
//! proposal:       Proposal
//! vote:           uint64 network_epoch; opaque header_hash[64]; uint8 member_index; opaque signature<V>
//! ```

use khensu_crypto::{Reader, SigKeyPair, SigPublicKey, Signature, write_varint, write_vec};

use crate::header::{EpochHeader, Evidence, HeaderBundle};
use crate::lease::Lease;
use crate::work::{ForwardingReceipt, MeasurementReport, Root, StorageReceipt};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq)]
// A lease carries its public keys inline (about 4 KB); items are few and
// short-lived, so the wire enum stays flat rather than boxing one variant.
#[allow(clippy::large_enum_variant)]
pub enum Item {
    Receipt(ForwardingReceipt),
    Measurement(MeasurementReport),
    Storage(StorageReceipt),
    Lease(Lease),
    Evidence(Evidence),
}

impl Item {
    fn kind(&self) -> u8 {
        match self {
            Item::Receipt(_) => 1,
            Item::Measurement(_) => 2,
            Item::Storage(_) => 3,
            Item::Lease(_) => 4,
            Item::Evidence(_) => 5,
        }
    }

    /// The bytes the receipts root is built over for this item.
    pub fn encode_body(&self) -> Vec<u8> {
        match self {
            Item::Receipt(r) => r.encode(),
            Item::Measurement(m) => m.encode(),
            Item::Storage(s) => s.encode(),
            Item::Lease(l) => l.encode(),
            Item::Evidence(e) => e.encode(),
        }
    }

    /// A leaf for the receipts root: kind-tagged, so items of different kinds never collide.
    pub fn leaf(&self) -> Vec<u8> {
        let mut out = vec![self.kind()];
        out.extend_from_slice(&self.encode_body());
        out
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.kind());
        write_vec(out, &self.encode_body());
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let kind = r.u8()?;
        let body = r.vec()?;
        Ok(match kind {
            1 => Item::Receipt(ForwardingReceipt::decode(body)?),
            2 => Item::Measurement(MeasurementReport::decode(body)?),
            3 => Item::Storage(StorageReceipt::decode(body)?),
            4 => Item::Lease(Lease::decode(body)?),
            5 => Item::Evidence(Evidence::decode(body)?),
            _ => return Err(Error::Decode),
        })
    }

    pub fn from_leaf(leaf: &[u8]) -> Result<Self> {
        let (kind, body) = leaf.split_first().ok_or(Error::Decode)?;
        Ok(match kind {
            1 => Item::Receipt(ForwardingReceipt::decode(body)?),
            2 => Item::Measurement(MeasurementReport::decode(body)?),
            3 => Item::Storage(StorageReceipt::decode(body)?),
            4 => Item::Lease(Lease::decode(body)?),
            5 => Item::Evidence(Evidence::decode(body)?),
            _ => return Err(Error::Decode),
        })
    }
}

/// A committee member's proposal for the next header: the unsigned header,
/// the leases and the items its roots are built from, signed by the proposer.
#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    pub header: EpochHeader,
    pub leases: Vec<Lease>,
    /// Receipts, measurements and storage receipts of the epoch before.
    pub items: Vec<Item>,
    pub evidence: Vec<Evidence>,
    pub proposer: u8,
    pub signature: Vec<u8>,
}

impl Proposal {
    fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // The whole header encoding (a proposal carries no signatures yet), so `decode` reads it back.
        write_vec(&mut out, &self.header.encode());
        write_varint(&mut out, self.leases.len() as u64);
        for l in &self.leases {
            write_vec(&mut out, &l.encode());
        }
        write_varint(&mut out, self.items.len() as u64);
        for i in &self.items {
            i.encode(&mut out);
        }
        write_varint(&mut out, self.evidence.len() as u64);
        for e in &self.evidence {
            write_vec(&mut out, &e.encode());
        }
        out.push(self.proposer);
        out
    }

    pub fn sign(mut self, key: &SigKeyPair) -> Result<Self> {
        self.signature = key.sign("header proposal", &self.tbs())?.0;
        Ok(self)
    }

    pub fn verify(&self, proposer_pk: &SigPublicKey) -> bool {
        proposer_pk.verify("header proposal", &self.tbs(), &Signature(self.signature.clone())).is_ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        write_vec(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let header = EpochHeader::decode(r.vec()?)?;
        let n = r.varint()?;
        if n > 100_000 {
            return Err(Error::Decode);
        }
        let mut leases = Vec::with_capacity(n as usize);
        for _ in 0..n {
            leases.push(Lease::decode(r.vec()?)?);
        }
        let n = r.varint()?;
        if n > 1_000_000 {
            return Err(Error::Decode);
        }
        let mut items = Vec::with_capacity(n.min(1024) as usize);
        for _ in 0..n {
            items.push(Item::decode(&mut r)?);
        }
        let n = r.varint()?;
        if n > 100_000 {
            return Err(Error::Decode);
        }
        let mut evidence = Vec::with_capacity(n.min(1024) as usize);
        for _ in 0..n {
            evidence.push(Evidence::decode(r.vec()?)?);
        }
        let proposer = r.u8()?;
        let signature = r.vec()?.to_vec();
        r.finish()?;
        Ok(Self { header, leases, items, evidence, proposer, signature })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Control {
    NodeAuth { node_id: [u8; 32], signature: Vec<u8> },
    Receipt(ForwardingReceipt),
    Submit(Vec<Item>),
    Header(HeaderBundle),
    HeaderRequest { have_epoch: u64 },
    Proposal(Proposal),
    Vote { network_epoch: u64, header_hash: Root, member_index: u8, signature: Vec<u8> },
}

fn auth_tbs(binding: &[u8; 32], node_id: &[u8; 32], peer: &[u8; 32]) -> Vec<u8> {
    [binding.as_slice(), node_id, peer].concat()
}

impl Control {
    /// The connecting node's proof of identity for one link.
    pub fn node_auth(key: &SigKeyPair, binding: &[u8; 32], peer: &[u8; 32]) -> Result<Self> {
        let node_id = crate::node_id(&key.public().0);
        let signature = key.sign("link auth", &auth_tbs(binding, &node_id, peer))?.0;
        Ok(Control::NodeAuth { node_id, signature })
    }

    /// Checks a `NodeAuth` received by the node whose ID is `me`.
    pub fn verify_node_auth(node_id: &[u8; 32], signature: &[u8], pk: &SigPublicKey, binding: &[u8; 32], me: &[u8; 32]) -> bool {
        crate::node_id(&pk.0) == *node_id && pk.verify("link auth", &auth_tbs(binding, node_id, me), &Signature(signature.to_vec())).is_ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Control::NodeAuth { node_id, signature } => {
                out.push(1);
                out.extend_from_slice(node_id);
                write_vec(&mut out, signature);
            }
            Control::Receipt(r) => {
                out.push(2);
                out.extend_from_slice(&r.encode());
            }
            Control::Submit(items) => {
                out.push(3);
                write_varint(&mut out, items.len() as u64);
                for i in items {
                    i.encode(&mut out);
                }
            }
            Control::Header(b) => {
                out.push(4);
                out.extend_from_slice(&b.encode());
            }
            Control::HeaderRequest { have_epoch } => {
                out.push(5);
                out.extend_from_slice(&have_epoch.to_be_bytes());
            }
            Control::Proposal(p) => {
                out.push(6);
                out.extend_from_slice(&p.encode());
            }
            Control::Vote { network_epoch, header_hash, member_index, signature } => {
                out.push(7);
                out.extend_from_slice(&network_epoch.to_be_bytes());
                out.extend_from_slice(header_hash);
                out.push(*member_index);
                write_vec(&mut out, signature);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (ty, rest) = bytes.split_first().ok_or(Error::Decode)?;
        let mut r = Reader::new(rest);
        let v = match ty {
            1 => {
                let node_id = r.array()?;
                let signature = r.vec()?.to_vec();
                r.finish()?;
                Control::NodeAuth { node_id, signature }
            }
            2 => Control::Receipt(ForwardingReceipt::decode(rest)?),
            3 => {
                let n = r.varint()?;
                if n > 1_000_000 {
                    return Err(Error::Decode);
                }
                let mut items = Vec::with_capacity(n.min(1024) as usize);
                for _ in 0..n {
                    items.push(Item::decode(&mut r)?);
                }
                r.finish()?;
                Control::Submit(items)
            }
            4 => Control::Header(HeaderBundle::decode(rest)?),
            5 => {
                let have_epoch = r.u64()?;
                r.finish()?;
                Control::HeaderRequest { have_epoch }
            }
            6 => Control::Proposal(Proposal::decode(rest)?),
            7 => {
                let network_epoch = r.u64()?;
                let header_hash = r.array()?;
                let member_index = r.u8()?;
                let signature = r.vec()?.to_vec();
                r.finish()?;
                Control::Vote { network_epoch, header_hash, member_index, signature }
            }
            _ => return Err(Error::Decode),
        };
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_auth_and_roundtrips() {
        let key = SigKeyPair::from_seed([5; 32]);
        let me = [7; 32];
        let binding = [3; 32];
        let auth = Control::node_auth(&key, &binding, &me).unwrap();
        let bytes = auth.encode();
        let Control::NodeAuth { node_id, signature } = Control::decode(&bytes).unwrap() else { panic!() };
        assert!(Control::verify_node_auth(&node_id, &signature, key.public(), &binding, &me));
        assert!(!Control::verify_node_auth(&node_id, &signature, key.public(), &[4; 32], &me));
        assert!(!Control::verify_node_auth(&node_id, &signature, key.public(), &binding, &[8; 32]));

        let r = ForwardingReceipt::sign(&key, 3, [1; 32], 10, 2).unwrap();
        let c = Control::Submit(vec![Item::Receipt(r.clone()), Item::Measurement(MeasurementReport::sign(&key, 3, [2; 32], 5, 5).unwrap())]);
        assert_eq!(Control::decode(&c.encode()).unwrap(), c);
        let c = Control::Receipt(r);
        assert_eq!(Control::decode(&c.encode()).unwrap(), c);
        let c = Control::HeaderRequest { have_epoch: 9 };
        assert_eq!(Control::decode(&c.encode()).unwrap(), c);
        let c = Control::Vote { network_epoch: 9, header_hash: [1; 64], member_index: 2, signature: vec![1, 2, 3] };
        assert_eq!(Control::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn proposal_survives_control_frames() {
        use crate::directory::tests::sample_dir;
        use crate::frame::{ControlAssembler, Frame};
        let (d, nodes, _) = sample_dir(5..9);
        let prev = d.epoch_header.as_ref().unwrap();
        let header = crate::header::EpochHeader { network_epoch: 6, prev_header_hash: prev.hash(), ..prev.clone() };
        let r = ForwardingReceipt::sign(&nodes[1].1, 4, nodes[0].0.node_id(), 10, 2).unwrap();
        let p = Proposal { header, leases: d.lease_list.clone(), items: vec![Item::Receipt(r)], evidence: Vec::new(), proposer: 0, signature: Vec::new() }.sign(&nodes[0].1).unwrap();
        let c = Control::Proposal(p.clone());
        let bytes = c.encode();
        assert_eq!(Control::decode(&bytes).unwrap(), c);
        let frames = Frame::control(3, &bytes);
        assert!(frames.len() >= 2, "a proposal with six leases spans bulk frames");
        let mut asm = ControlAssembler::default();
        let mut out = None;
        for f in frames {
            let Frame::Control(part) = Frame::decode(&f.encode()).unwrap() else { panic!() };
            out = asm.push(part);
        }
        let Control::Proposal(back) = Control::decode(&out.unwrap()).unwrap() else { panic!() };
        assert_eq!(back, p);
        assert!(back.verify(nodes[0].1.public()));
    }
}
