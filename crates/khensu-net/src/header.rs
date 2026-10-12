// SPDX-License-Identifier: Apache-2.0
//! The rule set, the epoch header, evidence and the committee (PROTOCOL.md 12.2
//! and 12.3).
//!
//! ```text
//! struct {
//!   uint32 chain_id;
//!   uint64 network_epoch;
//!   opaque prev_header_hash[64];
//!   opaque node_list_root[64];     // Merkle root over the Lease entries active this epoch
//!   opaque state_root[64];
//!   opaque receipts_root[64];      // work receipts of the previous epoch
//!   opaque evidence_root[64];
//!   opaque rules_hash[64];
//!   opaque committee_root[64];     // the members that sign the next header
//!   opaque founder_cosig<V>;       // launch stages only
//!   struct { uint8 member_index; opaque signature<V>; } signatures<V>;
//! } EpochHeader;
//! ```
//!
//! The header for epoch E+1 is signed by the committee listed in header E, so a
//! light client that holds header E can check it with that committee's keys.
//! The committee of E+1 is drawn from the leases active in E+1 by sortition
//! seeded with the hash of header E, which every node computes alike.

use std::collections::BTreeMap;

use khensu_crypto::sym::{h, h256};
use khensu_crypto::{Reader, SigKeyPair, SigPublicKey, Signature, write_varint, write_vec};
use serde::{Deserialize, Serialize};

use crate::directory::Params;
use crate::lease::{Lease, ROLE_COMMITTEE, ROLE_MIX};
use crate::work::{Root, merkle_root};
use crate::{Error, Result};

/// Consensus rules. `rules_hash` in the header commits to them; a change goes
/// through the rule-change process (founder plus 2/3 of the committee).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub version: u32,
    pub chain_id: u32,
    /// Members drawn each epoch; the devnet uses every committee-capable node.
    pub committee_size: u16,
    /// Signatures a header needs.
    pub threshold: u16,
    /// Founder co-signing key during launch stages, base64; empty once the switch has fired.
    #[serde(default)]
    pub founder_pk: String,
    pub tick_ms: u64,
    pub small_per_tick: u32,
    pub downstream_per_tick: u32,
    pub mix_delay_mean_ms: u32,
    pub surbs_per_fetch: u32,
    /// Node-to-node constant rates per link, in thousandths of a packet per second.
    pub link_small_rate_mpps: u32,
    pub link_bulk_rate_mpps: u32,
    /// Loop packets each node sends per minute for measurement.
    pub node_loops_per_min: u32,
    /// Mailbox replicas per mailbox ID.
    pub mailbox_replicas: u8,
    pub mix_layers: u8,
    /// Camouflage profile the clients and nodes present (design/camouflage.md 3.2).
    pub camouflage_profile: u16,
    /// A node whose loops return below this rate (per mille) over an epoch
    /// gets `failed_measurement` evidence.
    pub min_return_permille: u16,
}

impl Rules {
    /// The devnet rule set: a committee of everyone able, two thirds plus one
    /// to sign, and the phone and link rates from PROTOCOL.md 8.8.
    pub fn devnet(committee_size: u16) -> Self {
        let threshold = committee_size * 2 / 3 + 1;
        Self {
            version: 1,
            chain_id: 1,
            committee_size,
            threshold: threshold.min(committee_size).max(1),
            founder_pk: String::new(),
            tick_ms: 2000,
            small_per_tick: 4,
            downstream_per_tick: 4,
            mix_delay_mean_ms: 250,
            surbs_per_fetch: 4,
            link_small_rate_mpps: 20_000,
            link_bulk_rate_mpps: 2_000,
            node_loops_per_min: 12,
            mailbox_replicas: 2,
            mix_layers: 3,
            camouflage_profile: 0,
            min_return_permille: 500,
        }
    }

    pub fn founder_key(&self) -> Result<Option<SigPublicKey>> {
        if self.founder_pk.is_empty() {
            return Ok(None);
        }
        use base64::Engine;
        let k = base64::engine::general_purpose::STANDARD.decode(&self.founder_pk).map_err(|_| Error::Directory("founder_pk".into()))?;
        if k.len() != khensu_crypto::sig::PUBLIC_KEY_LEN {
            return Err(Error::Directory("founder_pk length".into()));
        }
        Ok(Some(SigPublicKey(k)))
    }

    pub fn params(&self) -> Params {
        Params {
            tick_ms: self.tick_ms,
            small_per_tick: self.small_per_tick,
            downstream_per_tick: self.downstream_per_tick,
            mix_delay_mean_ms: self.mix_delay_mean_ms,
            surbs_per_fetch: self.surbs_per_fetch,
            link_small_rate: self.link_small_rate_mpps as f64 / 1000.0,
            link_bulk_rate: self.link_bulk_rate_mpps as f64 / 1000.0,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.committee_size.to_be_bytes());
        out.extend_from_slice(&self.threshold.to_be_bytes());
        write_vec(&mut out, self.founder_pk.as_bytes());
        out.extend_from_slice(&self.tick_ms.to_be_bytes());
        out.extend_from_slice(&self.small_per_tick.to_be_bytes());
        out.extend_from_slice(&self.downstream_per_tick.to_be_bytes());
        out.extend_from_slice(&self.mix_delay_mean_ms.to_be_bytes());
        out.extend_from_slice(&self.surbs_per_fetch.to_be_bytes());
        out.extend_from_slice(&self.link_small_rate_mpps.to_be_bytes());
        out.extend_from_slice(&self.link_bulk_rate_mpps.to_be_bytes());
        out.extend_from_slice(&self.node_loops_per_min.to_be_bytes());
        out.push(self.mailbox_replicas);
        out.push(self.mix_layers);
        out.extend_from_slice(&self.camouflage_profile.to_be_bytes());
        out.extend_from_slice(&self.min_return_permille.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let v = Self {
            version: r.u32()?,
            chain_id: r.u32()?,
            committee_size: r.u16()?,
            threshold: r.u16()?,
            founder_pk: String::from_utf8(r.vec()?.to_vec()).map_err(|_| Error::Decode)?,
            tick_ms: r.u64()?,
            small_per_tick: r.u32()?,
            downstream_per_tick: r.u32()?,
            mix_delay_mean_ms: r.u32()?,
            surbs_per_fetch: r.u32()?,
            link_small_rate_mpps: r.u32()?,
            link_bulk_rate_mpps: r.u32()?,
            node_loops_per_min: r.u32()?,
            mailbox_replicas: r.u8()?,
            mix_layers: r.u8()?,
            camouflage_profile: r.u16()?,
            min_return_permille: r.u16()?,
        };
        r.finish()?;
        v.validate()?;
        Ok(v)
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Directory(format!("rules: {m}")));
        if self.version != 1 {
            return bad("unsupported version");
        }
        if self.committee_size == 0 || self.threshold == 0 || self.threshold > self.committee_size {
            return bad("committee size and threshold");
        }
        if self.mix_layers == 0 || self.mix_layers > 3 {
            return bad("mix layers must be 1 to 3");
        }
        if self.mailbox_replicas == 0 {
            return bad("mailbox replicas");
        }
        if self.tick_ms < 100 || self.small_per_tick == 0 || self.downstream_per_tick == 0 {
            return bad("tick");
        }
        self.founder_key()?;
        Ok(())
    }

    pub fn hash(&self) -> Root {
        h("rules", &[&self.encode()])
    }
}

/// `state_root` until the chain exists.
pub fn empty_state_root() -> Root {
    h("state empty", &[])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberSignature {
    pub member_index: u8,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochHeader {
    pub chain_id: u32,
    pub network_epoch: u64,
    pub prev_header_hash: Root,
    pub node_list_root: Root,
    pub state_root: Root,
    pub receipts_root: Root,
    pub evidence_root: Root,
    pub rules_hash: Root,
    pub committee_root: Root,
    pub founder_cosig: Vec<u8>,
    pub signatures: Vec<MemberSignature>,
}

impl EpochHeader {
    /// Fields before `founder_cosig`: what the founder co-signs.
    fn founder_tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + 7 * 64);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.network_epoch.to_be_bytes());
        for r in [&self.prev_header_hash, &self.node_list_root, &self.state_root, &self.receipts_root, &self.evidence_root, &self.rules_hash, &self.committee_root] {
            out.extend_from_slice(r);
        }
        out
    }

    /// Fields before `signatures`: what the committee signs, and what the hash covers.
    pub fn tbs(&self) -> Vec<u8> {
        let mut out = self.founder_tbs();
        write_vec(&mut out, &self.founder_cosig);
        out
    }

    pub fn hash(&self) -> Root {
        h("epoch header hash", &[&self.tbs()])
    }

    /// The genesis header of a network: no previous header, no receipts or
    /// evidence, the committee drawn from the leases with a zero seed, and the
    /// founder's co-signature when a founder key is given.
    pub fn genesis(rules: &Rules, leases: &[Lease], epoch: u64, genesis_time: u64, founder: Option<&SigKeyPair>) -> Result<Self> {
        let committee = draw_committee(&[0; 64], leases, epoch, genesis_time, rules.committee_size);
        let mut header = Self {
            chain_id: rules.chain_id,
            network_epoch: epoch,
            prev_header_hash: [0; 64],
            node_list_root: node_list_root(leases),
            state_root: empty_state_root(),
            receipts_root: receipts_root(&[]),
            evidence_root: evidence_root(&[]),
            rules_hash: rules.hash(),
            committee_root: committee_root(&committee),
            founder_cosig: Vec::new(),
            signatures: Vec::new(),
        };
        if let Some(f) = founder {
            header.founder_sign(f)?;
        }
        Ok(header)
    }

    pub fn founder_sign(&mut self, founder: &SigKeyPair) -> Result<()> {
        self.founder_cosig = founder.sign("epoch header founder", &self.founder_tbs())?.0;
        Ok(())
    }

    /// A committee member's signature; the caller adds it with [`Self::add_signature`].
    pub fn member_sign(&self, key: &SigKeyPair) -> Result<Vec<u8>> {
        Ok(key.sign("epoch header", &self.tbs())?.0)
    }

    pub fn verify_member(&self, pk: &SigPublicKey, signature: &[u8]) -> bool {
        pk.verify("epoch header", &self.tbs(), &Signature(signature.to_vec())).is_ok()
    }

    /// Adds a signature, keeping one per member in index order.
    pub fn add_signature(&mut self, member_index: u8, signature: Vec<u8>) {
        self.signatures.retain(|s| s.member_index != member_index);
        self.signatures.push(MemberSignature { member_index, signature });
        self.signatures.sort_by_key(|s| s.member_index);
    }

    /// Checks the signatures against the signing committee's keys (in member
    /// order), the threshold and, when the rules name a founder, the co-signature.
    pub fn verify(&self, committee: &[SigPublicKey], threshold: u16, founder: Option<&SigPublicKey>) -> Result<()> {
        let bad = |m: &str| Err(Error::Directory(format!("epoch header {}: {m}", self.network_epoch)));
        match founder {
            Some(f) => {
                if f.verify("epoch header founder", &self.founder_tbs(), &Signature(self.founder_cosig.clone())).is_err() {
                    return bad("founder co-signature");
                }
            }
            None if !self.founder_cosig.is_empty() => return bad("unexpected founder co-signature"),
            None => {}
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut good = 0u16;
        for s in &self.signatures {
            let Some(pk) = committee.get(s.member_index as usize) else { return bad("member index") };
            if !seen.insert(s.member_index) {
                return bad("duplicate member signature");
            }
            if !self.verify_member(pk, &s.signature) {
                return bad("member signature");
            }
            good += 1;
        }
        if good < threshold {
            return bad("below threshold");
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        write_varint(&mut out, self.signatures.len() as u64);
        for s in &self.signatures {
            out.push(s.member_index);
            write_vec(&mut out, &s.signature);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let mut v = Self {
            chain_id: r.u32()?,
            network_epoch: r.u64()?,
            prev_header_hash: r.array()?,
            node_list_root: r.array()?,
            state_root: r.array()?,
            receipts_root: r.array()?,
            evidence_root: r.array()?,
            rules_hash: r.array()?,
            committee_root: r.array()?,
            founder_cosig: r.vec()?.to_vec(),
            signatures: Vec::new(),
        };
        let n = r.varint()?;
        if n > 255 {
            return Err(Error::Decode);
        }
        for _ in 0..n {
            v.signatures.push(MemberSignature { member_index: r.u8()?, signature: r.vec()?.to_vec() });
        }
        r.finish()?;
        Ok(v)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EvidenceType {
    Equivocation = 1,
    ConflictingLease = 2,
    FailedMeasurement = 3,
    DoubleVote = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub kind: EvidenceType,
    pub proof: Vec<u8>,
}

impl Evidence {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.kind as u8];
        write_vec(&mut out, &self.proof);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let kind = match r.u8()? {
            1 => EvidenceType::Equivocation,
            2 => EvidenceType::ConflictingLease,
            3 => EvidenceType::FailedMeasurement,
            4 => EvidenceType::DoubleVote,
            _ => return Err(Error::Decode),
        };
        let proof = r.vec()?.to_vec();
        r.finish()?;
        Ok(Self { kind, proof })
    }
}

/// Root over the active leases, as the header commits to them.
pub fn node_list_root(leases: &[Lease]) -> Root {
    let items: Vec<Vec<u8>> = leases.iter().map(Lease::encode).collect();
    merkle_root("node list", &items)
}

pub fn receipts_root(receipts: &[Vec<u8>]) -> Root {
    merkle_root("receipts", receipts)
}

pub fn evidence_root(items: &[Evidence]) -> Root {
    let items: Vec<Vec<u8>> = items.iter().map(Evidence::encode).collect();
    merkle_root("evidence", &items)
}

pub fn committee_root(members: &[[u8; 32]]) -> Root {
    let items: Vec<Vec<u8>> = members.iter().map(|m| m.to_vec()).collect();
    merkle_root("committee", &items)
}

/// Draws the committee for the epoch whose leases are given: every lease with
/// the committee role covering the epoch is a candidate; when there are more
/// than `size`, the ones with the lowest `H256("sortition" || seed || node_id)`
/// are drawn. Members are returned sorted by node ID; that order is the
/// `member_index`.
pub fn draw_committee(seed: &Root, leases: &[Lease], epoch: u64, genesis_time: u64, size: u16) -> Vec<[u8; 32]> {
    let mut cands: Vec<([u8; 32], [u8; 32])> = leases
        .iter()
        .filter(|l| l.roles_in(epoch, genesis_time) & ROLE_COMMITTEE != 0)
        .map(|l| {
            let id = l.node_id();
            (h256("sortition", &[seed, &id]), id)
        })
        .collect();
    cands.sort();
    let mut members: Vec<[u8; 32]> = cands.into_iter().take(size as usize).map(|(_, id)| id).collect();
    members.sort();
    members
}

/// Deals the mixes active in `epoch` into layers 1..=layers, balanced, in an
/// order every node computes alike.
pub fn mix_layers(leases: &[Lease], epoch: u64, genesis_time: u64, layers: u8) -> BTreeMap<[u8; 32], u8> {
    let mut mixes: Vec<([u8; 32], [u8; 32])> = leases
        .iter()
        .filter(|l| l.roles_in(epoch, genesis_time) & ROLE_MIX != 0 && l.mix_ek(epoch).is_some())
        .map(|l| {
            let id = l.node_id();
            (h256("mix layer", &[&epoch.to_be_bytes(), &id]), id)
        })
        .collect();
    mixes.sort();
    mixes.into_iter().enumerate().map(|(i, (_, id))| (id, (i % layers.max(1) as usize) as u8 + 1)).collect()
}

/// A header with everything a node or client needs to act on it.
#[derive(Clone, Debug, PartialEq)]
pub struct HeaderBundle {
    pub header: EpochHeader,
    /// Leases active in `header.network_epoch`; must hash to `node_list_root`.
    pub leases: Vec<Lease>,
    /// Present when the rule set changed with this header.
    pub rules: Option<Rules>,
}

impl HeaderBundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_vec(&mut out, &self.header.encode());
        write_varint(&mut out, self.leases.len() as u64);
        for l in &self.leases {
            write_vec(&mut out, &l.encode());
        }
        write_vec(&mut out, &self.rules.as_ref().map(Rules::encode).unwrap_or_default());
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
        let rules = r.vec()?;
        let rules = if rules.is_empty() { None } else { Some(Rules::decode(rules)?) };
        r.finish()?;
        Ok(Self { header, leases, rules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::tests::sample;
    use crate::lease::{ROLE_GATEWAY, ROLE_MAILBOX};

    #[test]
    fn header_signs_and_verifies_with_threshold() {
        let rules = Rules::devnet(3);
        assert_eq!(rules.threshold, 3);
        let rules = Rules { threshold: 2, ..rules };
        let members: Vec<_> = (1..=3u8).map(|s| sample(s, ROLE_MIX | ROLE_COMMITTEE, 5..7)).collect();
        let leases: Vec<Lease> = members.iter().map(|m| m.0.clone()).collect();
        let committee = draw_committee(&[0; 64], &leases, 5, 0, rules.committee_size);
        assert_eq!(committee.len(), 3);
        let keys: Vec<SigPublicKey> = committee
            .iter()
            .map(|id| members.iter().find(|m| m.0.node_id() == *id).unwrap().1.public().clone())
            .collect();
        let founder = SigKeyPair::from_seed([77; 32]);
        let mut hdr = EpochHeader {
            chain_id: 1,
            network_epoch: 6,
            prev_header_hash: [1; 64],
            node_list_root: node_list_root(&leases),
            state_root: empty_state_root(),
            receipts_root: receipts_root(&[]),
            evidence_root: evidence_root(&[]),
            rules_hash: rules.hash(),
            committee_root: committee_root(&committee),
            founder_cosig: Vec::new(),
            signatures: Vec::new(),
        };
        hdr.founder_sign(&founder).unwrap();
        assert!(hdr.verify(&keys, 2, Some(founder.public())).is_err(), "no member signatures yet");
        for (i, id) in committee.iter().enumerate().take(2) {
            let key = &members.iter().find(|m| m.0.node_id() == *id).unwrap().1;
            let sig = hdr.member_sign(key).unwrap();
            hdr.add_signature(i as u8, sig);
        }
        hdr.verify(&keys, 2, Some(founder.public())).unwrap();
        assert!(hdr.verify(&keys, 3, Some(founder.public())).is_err());
        assert!(hdr.verify(&keys, 2, None).is_err(), "founder cosig present but not expected");
        let d = EpochHeader::decode(&hdr.encode()).unwrap();
        assert_eq!(d, hdr);
        assert_eq!(d.hash(), hdr.hash());
        let b = HeaderBundle { header: hdr, leases: leases.clone(), rules: Some(rules) };
        assert_eq!(HeaderBundle::decode(&b.encode()).unwrap(), b);

        let layers = mix_layers(&leases, 5, 0, 3);
        let mut seen: Vec<u8> = layers.values().copied().collect();
        seen.sort();
        assert_eq!(seen, vec![1, 2, 3]);
        let (gw, _, _) = sample(9, ROLE_GATEWAY | ROLE_MAILBOX, 5..7);
        assert!(mix_layers(&[gw], 5, 0, 3).is_empty());
    }
}
