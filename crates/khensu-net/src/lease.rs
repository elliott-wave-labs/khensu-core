// SPDX-License-Identifier: Apache-2.0
//! Node leases (PROTOCOL.md 12.1).
//!
//! ```text
//! enum { mix(0), mailbox(1), sequencer(2), relay(3), committee(4), pir(5), bridge(6), channel_cache(7), deadman(8), gateway(9) } Role;
//! enum { always_on(1), scheduled(2), n_hours(3), idle_time(4) } LeaseMode;
//! struct {
//!   opaque node_id[32];            // H256(Label("node") || node_sig_pk)
//!   opaque node_sig_pk<V>;
//!   opaque link_ek[1568];          // extension: ML-KEM-1024 key for the inner handshake (design/camouflage.md 4)
//!   opaque mix_eks<V>;             // { uint64 epoch; opaque ek[1568]; } per epoch of the lease
//!   uint16 roles;                  // bitmask of Role
//!   LeaseMode mode;
//!   uint64 start_epoch;
//!   uint64 end_epoch;
//!   opaque schedule<V>;            // scheduled: 21 bytes, one bit per hour of the week, Monday 00:00 UTC first
//!   opaque operator_address[32];
//!   opaque stake_ref[32];
//!   opaque endpoints<V>;           // { opaque endpoint<V>; } list, "host:port"
//!   opaque label<V>;               // extension: a short operator-chosen name for logs and tools
//!   opaque signature<V>;           // Sign(node_sig_pk, "lease", fields above)
//! } Lease;
//! ```
//!
//! `gateway(9)` and `link_ek` extend PROTOCOL.md 12.1: the entry node that
//! terminates client links and delivers SURB replies, and the key those links
//! are opened with.

use khensu_crypto::kem::{self, KemPublicKey};
use khensu_crypto::{Reader, SigKeyPair, SigPublicKey, Signature, write_varint, write_vec};
use khensu_outfox::epoch::{EPOCH_SECS, epoch_start};

use crate::{Error, Result, node_id};

pub const ROLE_MIX: u16 = 1 << 0;
pub const ROLE_MAILBOX: u16 = 1 << 1;
pub const ROLE_SEQUENCER: u16 = 1 << 2;
pub const ROLE_RELAY: u16 = 1 << 3;
pub const ROLE_COMMITTEE: u16 = 1 << 4;
pub const ROLE_PIR: u16 = 1 << 5;
pub const ROLE_BRIDGE: u16 = 1 << 6;
pub const ROLE_CHANNEL_CACHE: u16 = 1 << 7;
pub const ROLE_DEADMAN: u16 = 1 << 8;
pub const ROLE_GATEWAY: u16 = 1 << 9;
const ROLES_KNOWN: u16 = (1 << 10) - 1;
/// Roles that need the lease to cover the whole epoch (12.1).
pub const ROLES_WHOLE_EPOCH: u16 = ROLE_COMMITTEE | ROLE_RELAY | ROLE_SEQUENCER | ROLE_MIX;
pub const SCHEDULE_LEN: usize = 21;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_LABEL: usize = 32;

/// Role names as used in configuration and the command line.
pub const ROLE_NAMES: [(&str, u16); 10] = [
    ("mix", ROLE_MIX),
    ("mailbox", ROLE_MAILBOX),
    ("sequencer", ROLE_SEQUENCER),
    ("relay", ROLE_RELAY),
    ("committee", ROLE_COMMITTEE),
    ("pir", ROLE_PIR),
    ("bridge", ROLE_BRIDGE),
    ("channel_cache", ROLE_CHANNEL_CACHE),
    ("deadman", ROLE_DEADMAN),
    ("gateway", ROLE_GATEWAY),
];

pub fn role_bit(name: &str) -> Option<u16> {
    ROLE_NAMES.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
}

pub fn role_names(roles: u16) -> Vec<&'static str> {
    ROLE_NAMES.iter().filter(|(_, b)| roles & b != 0).map(|(n, _)| *n).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LeaseMode {
    AlwaysOn = 1,
    Scheduled = 2,
    NHours = 3,
    IdleTime = 4,
}

impl LeaseMode {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::AlwaysOn,
            2 => Self::Scheduled,
            3 => Self::NHours,
            4 => Self::IdleTime,
            _ => return Err(Error::Decode),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::AlwaysOn => "always_on",
            Self::Scheduled => "scheduled",
            Self::NHours => "n_hours",
            Self::IdleTime => "idle_time",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "always_on" | "always-on" => Self::AlwaysOn,
            "scheduled" => Self::Scheduled,
            "n_hours" | "n-hours" => Self::NHours,
            "idle_time" | "idle-time" => Self::IdleTime,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixEk {
    pub epoch: u64,
    pub ek: KemPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub node_sig_pk: Vec<u8>,
    pub link_ek: KemPublicKey,
    pub mix_eks: Vec<MixEk>,
    pub roles: u16,
    pub mode: LeaseMode,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub schedule: Vec<u8>,
    pub operator_address: [u8; 32],
    pub stake_ref: [u8; 32],
    pub endpoints: Vec<String>,
    pub label: String,
    pub signature: Vec<u8>,
}

/// Hour of the week, Monday 00:00 UTC = 0, for the start of `epoch`.
pub fn hour_of_week(epoch: u64, genesis_time: u64) -> usize {
    let hours = epoch_start(epoch, genesis_time) / EPOCH_SECS;
    // 1970-01-01 was a Thursday: shift by three days so Monday is 0.
    ((hours + 72) % 168) as usize
}

impl Lease {
    pub fn node_id(&self) -> [u8; 32] {
        node_id(&self.node_sig_pk)
    }

    pub fn has(&self, role: u16) -> bool {
        self.roles & role != 0
    }

    pub fn mix_ek(&self, epoch: u64) -> Option<&KemPublicKey> {
        self.mix_eks.iter().find(|m| m.epoch == epoch).map(|m| &m.ek)
    }

    pub fn sig_public(&self) -> SigPublicKey {
        SigPublicKey(self.node_sig_pk.clone())
    }

    /// The name shown in logs and tools: the label, else the first bytes of the node ID.
    pub fn name(&self) -> String {
        if self.label.is_empty() { hex::encode(&self.node_id()[..4]) } else { self.label.clone() }
    }

    /// Whether the lease covers `epoch` (12.1): inside its range and, for a
    /// scheduled lease, with that hour of the week switched on.
    pub fn covers(&self, epoch: u64, genesis_time: u64) -> bool {
        if epoch < self.start_epoch || epoch > self.end_epoch {
            return false;
        }
        match self.mode {
            LeaseMode::Scheduled => {
                let h = hour_of_week(epoch, genesis_time);
                self.schedule.get(h / 8).is_some_and(|b| b & (1 << (h % 8)) != 0)
            }
            _ => true,
        }
    }

    /// Roles this lease may serve in `epoch`: every role it holds while it
    /// covers the epoch; nothing otherwise. Leases that end during an epoch
    /// end at its boundary, so covering an epoch means covering all of it.
    pub fn roles_in(&self, epoch: u64, genesis_time: u64) -> u16 {
        if self.covers(epoch, genesis_time) { self.roles } else { 0 }
    }

    fn tbs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.mix_eks.len() * (8 + kem::PUBLIC_KEY_LEN));
        out.extend_from_slice(&self.node_id());
        write_vec(&mut out, &self.node_sig_pk);
        out.extend_from_slice(&self.link_ek.0);
        let mut eks = Vec::with_capacity(self.mix_eks.len() * (8 + kem::PUBLIC_KEY_LEN));
        for m in &self.mix_eks {
            eks.extend_from_slice(&m.epoch.to_be_bytes());
            eks.extend_from_slice(&m.ek.0);
        }
        write_vec(&mut out, &eks);
        out.extend_from_slice(&self.roles.to_be_bytes());
        out.push(self.mode as u8);
        out.extend_from_slice(&self.start_epoch.to_be_bytes());
        out.extend_from_slice(&self.end_epoch.to_be_bytes());
        write_vec(&mut out, &self.schedule);
        out.extend_from_slice(&self.operator_address);
        out.extend_from_slice(&self.stake_ref);
        let mut eps = Vec::new();
        write_varint(&mut eps, self.endpoints.len() as u64);
        for e in &self.endpoints {
            write_vec(&mut eps, e.as_bytes());
        }
        write_vec(&mut out, &eps);
        write_vec(&mut out, self.label.as_bytes());
        out
    }

    /// Signs the lease with the node's identity key; `node_sig_pk` is taken from it.
    pub fn sign(mut self, key: &SigKeyPair) -> Result<Self> {
        self.node_sig_pk = key.public().0.clone();
        self.check_fields()?;
        self.signature = key.sign("lease", &self.tbs())?.0;
        Ok(self)
    }

    fn check_fields(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Directory(format!("lease {}: {m}", self.name())));
        if self.roles == 0 || self.roles & !ROLES_KNOWN != 0 {
            return bad("roles");
        }
        if self.start_epoch > self.end_epoch {
            return bad("start after end");
        }
        if self.mode == LeaseMode::Scheduled && self.schedule.len() != SCHEDULE_LEN {
            return bad("schedule must be 21 bytes");
        }
        if self.mode != LeaseMode::Scheduled && !self.schedule.is_empty() {
            return bad("schedule only for scheduled leases");
        }
        if self.endpoints.is_empty() != self.has(ROLE_BRIDGE) || self.endpoints.len() > MAX_ENDPOINTS {
            return bad("endpoints");
        }
        if self.label.len() > MAX_LABEL || self.label.chars().any(|c| c.is_control()) {
            return bad("label");
        }
        if self.has(ROLE_MIX) && self.mix_eks.is_empty() {
            return bad("a mix needs mix keys");
        }
        let mut last = None;
        for m in &self.mix_eks {
            if m.epoch < self.start_epoch || m.epoch > self.end_epoch || last.is_some_and(|l| l >= m.epoch) {
                return bad("mix key epochs must be strictly increasing inside the lease");
            }
            last = Some(m.epoch);
        }
        Ok(())
    }

    /// Checks the fields and the node's signature.
    pub fn verify(&self) -> Result<()> {
        self.check_fields()?;
        self.sig_public()
            .verify("lease", &self.tbs(), &Signature(self.signature.clone()))
            .map_err(|_| Error::Directory(format!("lease {}: bad signature", self.name())))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.tbs();
        write_vec(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let id: [u8; 32] = r.array()?;
        let node_sig_pk = r.vec()?.to_vec();
        if node_id(&node_sig_pk) != id {
            return Err(Error::Decode);
        }
        let link_ek = KemPublicKey::from_slice(r.take(kem::PUBLIC_KEY_LEN)?)?;
        let mut eks = Reader::new(r.vec()?);
        let mut mix_eks = Vec::new();
        while !eks.is_empty() {
            let epoch = eks.u64()?;
            let ek = KemPublicKey::from_slice(eks.take(kem::PUBLIC_KEY_LEN)?)?;
            mix_eks.push(MixEk { epoch, ek });
        }
        let roles = r.u16()?;
        let mode = LeaseMode::from_u8(r.u8()?)?;
        let start_epoch = r.u64()?;
        let end_epoch = r.u64()?;
        let schedule = r.vec()?.to_vec();
        let operator_address = r.array()?;
        let stake_ref = r.array()?;
        let mut eps = Reader::new(r.vec()?);
        let n = eps.varint()? as usize;
        if n > MAX_ENDPOINTS {
            return Err(Error::Decode);
        }
        let mut endpoints = Vec::with_capacity(n);
        for _ in 0..n {
            endpoints.push(String::from_utf8(eps.vec()?.to_vec()).map_err(|_| Error::Decode)?);
        }
        eps.finish()?;
        let label = String::from_utf8(r.vec()?.to_vec()).map_err(|_| Error::Decode)?;
        let signature = r.vec()?.to_vec();
        r.finish()?;
        Ok(Self { node_sig_pk, link_ek, mix_eks, roles, mode, start_epoch, end_epoch, schedule, operator_address, stake_ref, endpoints, label, signature })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use khensu_crypto::KemKeyPair;

    pub(crate) fn sample(seed: u8, roles: u16, epochs: std::ops::Range<u64>) -> (Lease, SigKeyPair, Vec<KemKeyPair>) {
        let sig = SigKeyPair::from_seed([seed; 32]);
        let link = KemKeyPair::from_seed([seed; 64]);
        let mix: Vec<KemKeyPair> = epochs.clone().map(|e| KemKeyPair::from_seed([seed ^ (e as u8) ^ 0x80; 64])).collect();
        let lease = Lease {
            node_sig_pk: Vec::new(),
            link_ek: link.public().clone(),
            mix_eks: epochs.clone().zip(&mix).map(|(e, k)| MixEk { epoch: e, ek: k.public().clone() }).collect(),
            roles,
            mode: LeaseMode::AlwaysOn,
            start_epoch: epochs.start,
            end_epoch: epochs.end - 1,
            schedule: Vec::new(),
            operator_address: [seed; 32],
            stake_ref: [0; 32],
            endpoints: vec![format!("127.0.0.1:{}", 47000 + seed as u16)],
            label: format!("n{seed}"),
            signature: Vec::new(),
        }
        .sign(&sig)
        .unwrap();
        (lease, sig, mix)
    }

    #[test]
    fn roundtrip_verify_and_schedule() {
        let (l, _, _) = sample(1, ROLE_MIX | ROLE_COMMITTEE, 5..8);
        let d = Lease::decode(&l.encode()).unwrap();
        assert_eq!(d, l);
        d.verify().unwrap();
        assert!(d.covers(5, 0) && d.covers(7, 0) && !d.covers(8, 0));
        assert!(d.mix_ek(6).is_some() && d.mix_ek(9).is_none());
        let mut bad = d.clone();
        bad.roles |= ROLE_MAILBOX;
        assert!(bad.verify().is_err());

        // Scheduled: only Monday 00:00-00:59 UTC. Epoch 0 at genesis 0 is Thursday.
        let sig = SigKeyPair::from_seed([2; 32]);
        let mut schedule = vec![0u8; SCHEDULE_LEN];
        schedule[0] = 1;
        let s = Lease { mode: LeaseMode::Scheduled, schedule, mix_eks: Vec::new(), roles: ROLE_MAILBOX, end_epoch: 1000, ..d.clone() }.sign(&sig).unwrap();
        s.verify().unwrap();
        assert!(!s.covers(5, 0));
        let monday = (4 * 24) as u64; // 1970-01-05 00:00 UTC
        assert_eq!(hour_of_week(monday, 0), 0);
        assert!(s.covers(monday, 0) && !s.covers(monday + 1, 0));
    }
}
