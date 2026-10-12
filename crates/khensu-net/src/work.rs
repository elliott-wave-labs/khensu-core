// SPDX-License-Identifier: Apache-2.0
//! Work receipts, measurement reports and loop records (PROTOCOL.md 8.6 and
//! 12.4), plus the Merkle roots the epoch header commits to.
//!
//! ```text
//! struct { uint64 network_epoch; opaque from_node[32]; opaque to_node[32];
//!          uint64 small_packets; uint64 bulk_packets; opaque signature<V>; } ForwardingReceipt;
//! struct { uint64 network_epoch; opaque node[32]; uint64 byte_hours; uint32 replicas_checked;
//!          opaque signature<V>; struct { opaque auditor[32]; opaque signature<V>; } audits<V>; } StorageReceipt;
//! struct { uint64 network_epoch; opaque measurer_id[32]; opaque node_id[32];
//!          uint64 sent; uint64 returned; opaque signature<V>; } MeasurementReport;
//! ```
//!
//! A loop packet is a cover packet (`FinalPayload.kind = 6`) whose body only
//! its sender can read, because every hop's Lioness layer sits on top of it:
//!
//! ```text
//! struct { uint8 flags = 0x02; opaque nonce[16]; uint64 sent_ms; opaque path<V>; } LoopBody;   // path: node IDs, 32 bytes each
//! ```

use khensu_crypto::sym::h;
use khensu_crypto::{Reader, SigKeyPair, SigPublicKey, Signature, write_varint, write_vec};
use khensu_outfox::delivery::{FinalKind, FinalPayload};
use khensu_outfox::routing::FLAG_LOOP;
use khensu_outfox::Lane;

use crate::{Error, Result};

/// A 64-byte root as the epoch header carries it.
pub type Root = [u8; 64];

/// Merkle root over `leaves` with SHA-512: leaves are hashed under
/// `Label(l || " leaf")`, inner nodes under `Label(l || " node")`, an odd
/// leaf is carried up unchanged, and an empty list hashes the label alone.
/// Leaves are sorted first, so the root does not depend on arrival order.
pub fn merkle_root(l: &str, leaves: &[Vec<u8>]) -> Root {
    let leaf_label = format!("{l} leaf");
    let node_label = format!("{l} node");
    let mut sorted: Vec<&Vec<u8>> = leaves.iter().collect();
    sorted.sort();
    sorted.dedup();
    let mut level: Vec<Root> = sorted.iter().map(|x| h(&leaf_label, &[x])).collect();
    if level.is_empty() {
        return h(&format!("{l} empty"), &[]);
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| if pair.len() == 2 { h(&node_label, &[&pair[0], &pair[1]]) } else { pair[0] })
            .collect();
    }
    level[0]
}

fn sig_from(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    Ok(r.vec()?.to_vec())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardingReceipt {
    pub network_epoch: u64,
    pub from_node: [u8; 32],
    pub to_node: [u8; 32],
    pub small_packets: u64,
    pub bulk_packets: u64,
    pub signature: Vec<u8>,
}

impl ForwardingReceipt {
    fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(88);
        out.extend_from_slice(&self.network_epoch.to_be_bytes());
        out.extend_from_slice(&self.from_node);
        out.extend_from_slice(&self.to_node);
        out.extend_from_slice(&self.small_packets.to_be_bytes());
        out.extend_from_slice(&self.bulk_packets.to_be_bytes());
        out
    }

    /// Signed by the receiving node (`to_node`).
    pub fn sign(key: &SigKeyPair, network_epoch: u64, from_node: [u8; 32], small_packets: u64, bulk_packets: u64) -> Result<Self> {
        let mut r = Self { network_epoch, from_node, to_node: crate::node_id(&key.public().0), small_packets, bulk_packets, signature: Vec::new() };
        r.signature = key.sign("forwarding receipt", &r.tbs())?.0;
        Ok(r)
    }

    pub fn verify(&self, to_node_pk: &SigPublicKey) -> Result<()> {
        if crate::node_id(&to_node_pk.0) != self.to_node {
            return Err(Error::Handshake);
        }
        to_node_pk.verify("forwarding receipt", &self.tbs(), &Signature(self.signature.clone())).map_err(|_| Error::Decode)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        write_vec(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let v = Self {
            network_epoch: r.u64()?,
            from_node: r.array()?,
            to_node: r.array()?,
            small_packets: r.u64()?,
            bulk_packets: r.u64()?,
            signature: sig_from(&mut r)?,
        };
        r.finish()?;
        Ok(v)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audit {
    pub auditor: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageReceipt {
    pub network_epoch: u64,
    pub node: [u8; 32],
    pub byte_hours: u64,
    pub replicas_checked: u32,
    pub signature: Vec<u8>,
    pub audits: Vec<Audit>,
}

impl StorageReceipt {
    fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(52);
        out.extend_from_slice(&self.network_epoch.to_be_bytes());
        out.extend_from_slice(&self.node);
        out.extend_from_slice(&self.byte_hours.to_be_bytes());
        out.extend_from_slice(&self.replicas_checked.to_be_bytes());
        out
    }

    /// Signed by the storing node itself; auditors countersign with [`Self::audit`].
    pub fn sign(key: &SigKeyPair, network_epoch: u64, byte_hours: u64, replicas_checked: u32) -> Result<Self> {
        let mut r = Self { network_epoch, node: crate::node_id(&key.public().0), byte_hours, replicas_checked, signature: Vec::new(), audits: Vec::new() };
        r.signature = key.sign("storage receipt", &r.tbs())?.0;
        Ok(r)
    }

    /// An auditor's countersignature over the node's signed receipt.
    pub fn audit(&mut self, auditor: &SigKeyPair) -> Result<()> {
        let mut tbs = self.tbs();
        write_vec(&mut tbs, &self.signature);
        let signature = auditor.sign("storage audit", &tbs)?.0;
        self.audits.push(Audit { auditor: crate::node_id(&auditor.public().0), signature });
        Ok(())
    }

    pub fn verify(&self, node_pk: &SigPublicKey) -> Result<()> {
        if crate::node_id(&node_pk.0) != self.node {
            return Err(Error::Handshake);
        }
        node_pk.verify("storage receipt", &self.tbs(), &Signature(self.signature.clone())).map_err(|_| Error::Decode)
    }

    pub fn verify_audit(&self, audit: &Audit, auditor_pk: &SigPublicKey) -> Result<()> {
        if crate::node_id(&auditor_pk.0) != audit.auditor {
            return Err(Error::Handshake);
        }
        let mut tbs = self.tbs();
        write_vec(&mut tbs, &self.signature);
        auditor_pk.verify("storage audit", &tbs, &Signature(audit.signature.clone())).map_err(|_| Error::Decode)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        write_vec(&mut out, &self.signature);
        write_varint(&mut out, self.audits.len() as u64);
        for a in &self.audits {
            out.extend_from_slice(&a.auditor);
            write_vec(&mut out, &a.signature);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let mut v = Self {
            network_epoch: r.u64()?,
            node: r.array()?,
            byte_hours: r.u64()?,
            replicas_checked: r.u32()?,
            signature: sig_from(&mut r)?,
            audits: Vec::new(),
        };
        let n = r.varint()?;
        if n > 64 {
            return Err(Error::Decode);
        }
        for _ in 0..n {
            v.audits.push(Audit { auditor: r.array()?, signature: sig_from(&mut r)? });
        }
        r.finish()?;
        Ok(v)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementReport {
    pub network_epoch: u64,
    pub measurer_id: [u8; 32],
    pub node_id: [u8; 32],
    pub sent: u64,
    pub returned: u64,
    pub signature: Vec<u8>,
}

impl MeasurementReport {
    fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(88);
        out.extend_from_slice(&self.network_epoch.to_be_bytes());
        out.extend_from_slice(&self.measurer_id);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.sent.to_be_bytes());
        out.extend_from_slice(&self.returned.to_be_bytes());
        out
    }

    pub fn sign(key: &SigKeyPair, network_epoch: u64, node_id: [u8; 32], sent: u64, returned: u64) -> Result<Self> {
        let mut r = Self { network_epoch, measurer_id: crate::node_id(&key.public().0), node_id, sent, returned, signature: Vec::new() };
        r.signature = key.sign("measurement report", &r.tbs())?.0;
        Ok(r)
    }

    pub fn verify(&self, measurer_pk: &SigPublicKey) -> Result<()> {
        if crate::node_id(&measurer_pk.0) != self.measurer_id {
            return Err(Error::Handshake);
        }
        measurer_pk.verify("measurement report", &self.tbs(), &Signature(self.signature.clone())).map_err(|_| Error::Decode)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        write_vec(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let v = Self {
            network_epoch: r.u64()?,
            measurer_id: r.array()?,
            node_id: r.array()?,
            sent: r.u64()?,
            returned: r.u64()?,
            signature: sig_from(&mut r)?,
        };
        r.finish()?;
        Ok(v)
    }
}

/// What a loop packet carries back to its sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopBody {
    pub nonce: [u8; 16],
    pub sent_ms: u64,
    pub path: Vec<[u8; 32]>,
}

impl LoopBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(28 + 32 * self.path.len());
        out.push(FLAG_LOOP);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sent_ms.to_be_bytes());
        write_vec(&mut out, &self.path.concat());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.u8()? != FLAG_LOOP {
            return Err(Error::Decode);
        }
        let nonce = r.array()?;
        let sent_ms = r.u64()?;
        let ids = r.vec()?;
        r.finish()?;
        if ids.len() % 32 != 0 {
            return Err(Error::Decode);
        }
        let path = ids.chunks(32).map(|c| c.try_into().expect("32 bytes")).collect();
        Ok(Self { nonce, sent_ms, path })
    }

    /// The final payload of the loop packet: a cover packet to anyone else.
    pub fn to_payload(&self, lane: Lane) -> Result<Vec<u8>> {
        Ok(FinalPayload { kind: FinalKind::Cover, body: self.encode() }.encode(lane)?)
    }

    /// Reads a loop record out of a final payload, if it is one.
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        let fp = FinalPayload::decode(payload).ok()?;
        if fp.kind != FinalKind::Cover {
            return None;
        }
        Self::decode(&fp.body).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_sign_verify_roundtrip() {
        let to = SigKeyPair::from_seed([1; 32]);
        let from = crate::node_id(&SigKeyPair::from_seed([2; 32]).public().0);
        let r = ForwardingReceipt::sign(&to, 7, from, 1200, 30).unwrap();
        let d = ForwardingReceipt::decode(&r.encode()).unwrap();
        assert_eq!(d, r);
        d.verify(to.public()).unwrap();
        let mut bad = d.clone();
        bad.small_packets += 1;
        assert!(bad.verify(to.public()).is_err());
        assert!(d.verify(SigKeyPair::from_seed([3; 32]).public()).is_err());

        let m = MeasurementReport::sign(&to, 7, from, 100, 97).unwrap();
        let m2 = MeasurementReport::decode(&m.encode()).unwrap();
        m2.verify(to.public()).unwrap();

        let auditor = SigKeyPair::from_seed([4; 32]);
        let mut s = StorageReceipt::sign(&to, 7, 4096, 2).unwrap();
        s.audit(&auditor).unwrap();
        let s2 = StorageReceipt::decode(&s.encode()).unwrap();
        assert_eq!(s2, s);
        s2.verify(to.public()).unwrap();
        s2.verify_audit(&s2.audits[0], auditor.public()).unwrap();
        assert!(s2.verify_audit(&s2.audits[0], to.public()).is_err());
    }

    #[test]
    fn loop_body_hides_in_cover() {
        let b = LoopBody { nonce: [9; 16], sent_ms: 1_700_000_000_000, path: vec![[1; 32], [2; 32], [3; 32]] };
        let p = b.to_payload(Lane::Small).unwrap();
        assert_eq!(p.len(), Lane::Small.payload_len());
        assert_eq!(LoopBody::from_payload(&p).unwrap(), b);
        assert!(LoopBody::from_payload(&FinalPayload::cover().encode(Lane::Small).unwrap()).is_none());
    }

    #[test]
    fn merkle_is_order_independent() {
        let a = merkle_root("receipts", &[vec![1], vec![2], vec![3]]);
        let b = merkle_root("receipts", &[vec![3], vec![1], vec![2]]);
        assert_eq!(a, b);
        assert_ne!(a, merkle_root("receipts", &[vec![1], vec![2]]));
        assert_ne!(merkle_root("receipts", &[]), merkle_root("evidence", &[]));
    }
}
