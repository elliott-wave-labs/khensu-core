// SPDX-License-Identifier: Apache-2.0
//! The node directory and route selection.
//!
//! A directory is an epoch header plus the leases it commits to (PROTOCOL.md
//! 12). The pinned genesis file (`devnet.json` on a devnet) carries the rules,
//! the genesis header and its leases; every later header arrives as a
//! [`HeaderBundle`] from the node this client or node is linked to, and
//! [`Directory::advance`] checks it against the committee of the header before.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use khensu_crypto::sym::h256;
use khensu_crypto::{KemPublicKey, SigPublicKey};
use khensu_outfox::epoch::{EPOCH_SECS, network_epoch};
use khensu_outfox::{Hop, sample_delay_ms};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

use crate::header::{EpochHeader, HeaderBundle, Rules, committee_root, draw_committee, mix_layers, node_list_root};
use crate::lease::{self, Lease, MixEk};
use crate::work::Root;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Entry node: first hop of every client packet, last hop of every SURB.
    Gateway,
    Mix,
    Mailbox,
    Sequencer,
    Relay,
    Committee,
    Pir,
    Bridge,
    ChannelCache,
    Deadman,
}

impl Role {
    pub fn bit(self) -> u16 {
        match self {
            Role::Gateway => lease::ROLE_GATEWAY,
            Role::Mix => lease::ROLE_MIX,
            Role::Mailbox => lease::ROLE_MAILBOX,
            Role::Sequencer => lease::ROLE_SEQUENCER,
            Role::Relay => lease::ROLE_RELAY,
            Role::Committee => lease::ROLE_COMMITTEE,
            Role::Pir => lease::ROLE_PIR,
            Role::Bridge => lease::ROLE_BRIDGE,
            Role::ChannelCache => lease::ROLE_CHANNEL_CACHE,
            Role::Deadman => lease::ROLE_DEADMAN,
        }
    }

    pub const ALL: [Role; 10] = [
        Role::Gateway,
        Role::Mix,
        Role::Mailbox,
        Role::Sequencer,
        Role::Relay,
        Role::Committee,
        Role::Pir,
        Role::Bridge,
        Role::ChannelCache,
        Role::Deadman,
    ];

    pub fn from_bits(bits: u16) -> Vec<Role> {
        Role::ALL.into_iter().filter(|r| bits & r.bit() != 0).collect()
    }
}

/// Consensus parameters (from the rules) that clients and nodes need for routing and ticks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Params {
    /// Phone tick (PROTOCOL.md 8.8).
    pub tick_ms: u64,
    /// Small packets per client burst, including the fetch slot.
    pub small_per_tick: u32,
    /// Replies the entry node sends a client per tick, padded with cover.
    pub downstream_per_tick: u32,
    /// Mean Poisson delay per mix.
    pub mix_delay_mean_ms: u32,
    /// SURBs per mailbox fetch (at most 7 on the bulk lane).
    pub surbs_per_fetch: u32,
    /// Node-to-node constant rates per link, packets per second.
    pub link_small_rate: f64,
    pub link_bulk_rate: f64,
}

impl Default for Params {
    fn default() -> Self {
        Rules::devnet(1).params()
    }
}

/// One node as the directory presents it for this epoch's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEntry {
    pub name: String,
    /// Hex `H256(Label("node") || sig_pk)`.
    pub node_id: String,
    pub roles: Vec<Role>,
    pub role_bits: u16,
    /// `host:port` of the node's QUIC endpoint (the first one in the lease).
    pub endpoint: String,
    pub endpoints: Vec<String>,
    pub sig_pk: SigPublicKey,
    pub kem_pk: KemPublicKey,
    pub mix_keys: Vec<MixEk>,
}

impl NodeEntry {
    pub fn id(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&self.node_id, &mut out).expect("built from a lease");
        out
    }

    pub fn has_role(&self, r: Role) -> bool {
        self.role_bits & r.bit() != 0
    }

    pub fn sig_public(&self) -> SigPublicKey {
        self.sig_pk.clone()
    }

    pub fn kem_public(&self) -> KemPublicKey {
        self.kem_pk.clone()
    }

    pub fn mix_ek(&self, epoch: u64) -> Option<KemPublicKey> {
        self.mix_keys.iter().find(|k| k.epoch == epoch).map(|k| k.ek.clone())
    }

    fn from_lease(l: &Lease) -> Self {
        Self {
            name: l.name(),
            node_id: hex::encode(l.node_id()),
            roles: Role::from_bits(l.roles),
            role_bits: l.roles,
            endpoint: l.endpoints.first().cloned().unwrap_or_default(),
            endpoints: l.endpoints.clone(),
            sig_pk: l.sig_public(),
            kem_pk: l.link_ek.clone(),
            mix_keys: l.mix_eks.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Directory {
    pub version: u32,
    pub network: String,
    pub genesis_time: u64,
    pub epoch_secs: u64,
    pub rules: Rules,
    /// The latest epoch header, base64.
    pub header: String,
    /// Leases active in that header's epoch, base64.
    pub leases: Vec<String>,
    #[serde(skip)]
    pub params: Params,
    #[serde(skip)]
    pub nodes: Vec<NodeEntry>,
    #[serde(skip)]
    pub epoch_header: Option<EpochHeader>,
    #[serde(skip)]
    pub lease_list: Vec<Lease>,
    /// Members that sign the next header, in `member_index` order.
    #[serde(skip)]
    pub committee: Vec<[u8; 32]>,
}

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn unb64(s: &str, what: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|_| Error::Directory(format!("{what}: base64")))
}

impl Directory {
    /// Builds the directory for a bundle whose header has already been checked
    /// (or is the pinned genesis).
    fn build(network: String, genesis_time: u64, rules: Rules, bundle: HeaderBundle) -> Result<Self> {
        let HeaderBundle { header, leases, .. } = bundle;
        let epoch = header.network_epoch;
        if rules.hash() != header.rules_hash {
            return Err(Error::Directory("header does not commit to these rules".into()));
        }
        if header.chain_id != rules.chain_id {
            return Err(Error::Directory("chain id".into()));
        }
        let mut ids = std::collections::BTreeSet::new();
        for l in &leases {
            l.verify()?;
            if !l.covers(epoch, genesis_time) {
                return Err(Error::Directory(format!("lease {} does not cover epoch {epoch}", l.name())));
            }
            if !ids.insert(l.node_id()) {
                return Err(Error::Directory(format!("two leases for node {}", l.name())));
            }
        }
        if node_list_root(&leases) != header.node_list_root {
            return Err(Error::Directory("leases do not match node_list_root".into()));
        }
        let committee = draw_committee(&header.prev_header_hash, &leases, epoch, genesis_time, rules.committee_size);
        if committee_root(&committee) != header.committee_root {
            return Err(Error::Directory("committee_root".into()));
        }
        let nodes = leases.iter().map(NodeEntry::from_lease).collect();
        Ok(Self {
            version: 2,
            network,
            genesis_time,
            epoch_secs: EPOCH_SECS,
            params: rules.params(),
            rules,
            header: b64(&header.encode()),
            leases: leases.iter().map(|l| b64(&l.encode())).collect(),
            nodes,
            epoch_header: Some(header),
            lease_list: leases,
            committee,
        })
    }

    /// A genesis directory: the header must carry the founder's co-signature
    /// when the rules name a founder, and otherwise the signatures of the
    /// committee it draws for itself.
    pub fn genesis(network: &str, genesis_time: u64, rules: Rules, bundle: HeaderBundle) -> Result<Self> {
        rules.validate()?;
        let founder = rules.founder_key()?;
        let d = Self::build(network.into(), genesis_time, rules, bundle)?;
        let hdr = d.epoch_header.as_ref().expect("built");
        match &founder {
            Some(f) => hdr.verify(&[], 0, Some(f))?,
            None => hdr.verify(&d.committee_keys(), d.rules.threshold, None)?,
        }
        Ok(d)
    }

    /// The next directory from the bundle for the following epoch, checked
    /// against this header's committee (and the founder when rules change).
    pub fn advance(&self, bundle: HeaderBundle) -> Result<Self> {
        let prev = self.epoch_header.as_ref().ok_or(Error::Directory("no header".into()))?;
        let h = &bundle.header;
        if h.network_epoch != prev.network_epoch + 1 {
            return Err(Error::Directory(format!("header for epoch {} after {}", h.network_epoch, prev.network_epoch)));
        }
        if h.prev_header_hash != prev.hash() {
            return Err(Error::Directory("prev_header_hash".into()));
        }
        let rules = match &bundle.rules {
            Some(r) if r.hash() != self.rules.hash() => {
                r.validate()?;
                h.verify(&self.committee_keys(), self.rules.committee_size * 2 / 3 + 1, self.rules.founder_key()?.as_ref())?;
                r.clone()
            }
            _ => {
                h.verify(&self.committee_keys(), self.rules.threshold, None)?;
                self.rules.clone()
            }
        };
        Self::build(self.network.clone(), self.genesis_time, rules, bundle)
    }

    /// The bundle this directory was built from.
    pub fn bundle(&self) -> HeaderBundle {
        HeaderBundle { header: self.epoch_header.clone().expect("built"), leases: self.lease_list.clone(), rules: Some(self.rules.clone()) }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch_header.as_ref().map_or(0, |h| h.network_epoch)
    }

    pub fn header_hash(&self) -> Root {
        self.epoch_header.as_ref().map_or([0; 64], EpochHeader::hash)
    }

    /// Public keys of the committee, in member order.
    pub fn committee_keys(&self) -> Vec<SigPublicKey> {
        self.committee.iter().filter_map(|id| self.node(id).map(NodeEntry::sig_public)).collect()
    }

    pub fn committee_index(&self, id: &[u8; 32]) -> Option<u8> {
        self.committee.iter().position(|m| m == id).map(|i| i as u8)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let d: Directory = serde_json::from_str(json).map_err(|e| Error::Directory(e.to_string()))?;
        if d.version != 2 {
            return Err(Error::Directory(format!("unsupported version {}", d.version)));
        }
        if d.epoch_secs != EPOCH_SECS {
            return Err(Error::Directory("epoch_secs must be 3600".into()));
        }
        let header = EpochHeader::decode(&unb64(&d.header, "header")?)?;
        let leases = d.leases.iter().map(|l| Lease::decode(&unb64(l, "lease")?)).collect::<Result<Vec<_>>>()?;
        Self::genesis(&d.network, d.genesis_time, d.rules, HeaderBundle { header, leases, rules: None })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serializable")
    }

    /// A directory from JSON this process wrote itself (a node's
    /// `data_dir/directory.json`): the header's structure is checked but its
    /// signatures are not, since the chain that proves them is not kept. Never
    /// use it for a directory that came from somewhere else.
    pub fn from_json_trusted(json: &str) -> Result<Self> {
        let d: Directory = serde_json::from_str(json).map_err(|e| Error::Directory(e.to_string()))?;
        if d.version != 2 {
            return Err(Error::Directory(format!("unsupported version {}", d.version)));
        }
        let header = EpochHeader::decode(&unb64(&d.header, "header")?)?;
        let leases = d.leases.iter().map(|l| Lease::decode(&unb64(l, "lease")?)).collect::<Result<Vec<_>>>()?;
        d.rules.validate()?;
        Self::build(d.network, d.genesis_time, d.rules, HeaderBundle { header, leases, rules: None })
    }

    /// Re-checks a directory that was built or loaded already.
    pub fn validate(&self) -> Result<()> {
        if self.epoch_header.is_none() || self.nodes.len() != self.lease_list.len() {
            return Err(Error::Directory("directory was not built from a header".into()));
        }
        Ok(())
    }

    pub fn epoch_at(&self, unix_secs: u64) -> u64 {
        network_epoch(unix_secs, self.genesis_time)
    }

    pub fn node(&self, id: &[u8; 32]) -> Option<&NodeEntry> {
        let h = hex::encode(id);
        self.nodes.iter().find(|n| n.node_id == h)
    }

    pub fn lease(&self, id: &[u8; 32]) -> Option<&Lease> {
        self.lease_list.iter().find(|l| l.node_id() == *id)
    }

    pub fn node_by_name(&self, name: &str) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn with_role(&self, r: Role) -> impl Iterator<Item = &NodeEntry> {
        self.nodes.iter().filter(move |n| n.has_role(r))
    }

    /// Mix layers for `epoch`, dealt from the leases (PROTOCOL.md 8.1).
    pub fn layers(&self, epoch: u64) -> BTreeMap<[u8; 32], u8> {
        mix_layers(&self.lease_list, epoch, self.genesis_time, self.rules.mix_layers)
    }

    pub fn layer_of(&self, id: &[u8; 32], epoch: u64) -> Option<u8> {
        self.layers(epoch).get(id).copied()
    }

    /// Mailbox replicas for `mailbox_id` by rendezvous hashing (PROTOCOL.md
    /// 6.2), best first, as many as the rules ask for and the network has.
    pub fn mailboxes_for(&self, mailbox_id: &[u8; 32], epoch: u64) -> Vec<&NodeEntry> {
        let mut v: Vec<(Root32, &NodeEntry)> = self
            .with_role(Role::Mailbox)
            .filter(|n| n.mix_ek(epoch).is_some())
            .map(|n| (h256("rendezvous", &[mailbox_id, &n.id()]), n))
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.0));
        v.into_iter().take(self.rules.mailbox_replicas.max(1) as usize).map(|(_, n)| n).collect()
    }

    /// The first replica.
    pub fn mailbox_for(&self, mailbox_id: &[u8; 32], epoch: u64) -> Option<&NodeEntry> {
        self.mailboxes_for(mailbox_id, epoch).into_iter().next()
    }

    fn hop(&self, n: &NodeEntry, epoch: u64, delay_ms: u32) -> Result<Hop> {
        Ok(Hop { node_id: n.id(), mix_ek: n.mix_ek(epoch).ok_or(Error::NoRoute("no mix key for epoch"))?, delay_ms })
    }

    /// One mix per layer, each with its Poisson delay; `avoid` keeps a node's
    /// own loops off itself where the network allows it.
    pub fn mixes(&self, rng: &mut (impl RngCore + CryptoRng), epoch: u64, avoid: Option<&[u8; 32]>) -> Result<Vec<Hop>> {
        let layers = self.layers(epoch);
        (1..=self.rules.mix_layers.max(1))
            .map(|layer| {
                let mut layer_nodes: Vec<&NodeEntry> = self
                    .nodes
                    .iter()
                    .filter(|n| layers.get(&n.id()) == Some(&layer))
                    .collect();
                if layer_nodes.len() > 1 {
                    if let Some(a) = avoid {
                        layer_nodes.retain(|n| n.id() != *a);
                    }
                }
                if layer_nodes.is_empty() {
                    return Err(Error::NoRoute("empty mix layer"));
                }
                let n = layer_nodes[rng.gen_range(0..layer_nodes.len())];
                let d = sample_delay_ms(rng, self.params.mix_delay_mean_ms);
                self.hop(n, epoch, d)
            })
            .collect()
    }

    /// Entry node, one mix per layer, destination (PROTOCOL.md 8.1).
    pub fn forward_route(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        gateway: &NodeEntry,
        destination: &NodeEntry,
        epoch: u64,
    ) -> Result<Vec<Hop>> {
        let mut route = vec![self.hop(gateway, epoch, 0)?];
        route.extend(self.mixes(rng, epoch, None)?);
        route.push(self.hop(destination, epoch, 0)?);
        Ok(route)
    }

    /// One mix per layer, then the client's entry node.
    pub fn reply_route(&self, rng: &mut (impl RngCore + CryptoRng), gateway: &NodeEntry, epoch: u64) -> Result<Vec<Hop>> {
        let mut route = self.mixes(rng, epoch, None)?;
        route.push(self.hop(gateway, epoch, 0)?);
        Ok(route)
    }

    /// A client's loop: entry node, the mixes, back to the entry node, which
    /// delivers it like a SURB reply (PROTOCOL.md 8.6).
    pub fn client_loop_route(&self, rng: &mut (impl RngCore + CryptoRng), gateway: &NodeEntry, epoch: u64) -> Result<Vec<Hop>> {
        let mut route = vec![self.hop(gateway, epoch, 0)?];
        route.extend(self.mixes(rng, epoch, None)?);
        route.push(self.hop(gateway, epoch, 0)?);
        Ok(route)
    }

    /// A node's loop: the mixes (not itself where possible), then back to itself.
    pub fn node_loop_route(&self, rng: &mut (impl RngCore + CryptoRng), me: &NodeEntry, epoch: u64) -> Result<Vec<Hop>> {
        let mut route = self.mixes(rng, epoch, Some(&me.id()))?;
        route.push(self.hop(me, epoch, 0)?);
        Ok(route)
    }
}

type Root32 = [u8; 32];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::header::{empty_state_root, evidence_root, receipts_root};
    use crate::lease::tests::sample;
    use crate::lease::{ROLE_COMMITTEE, ROLE_GATEWAY, ROLE_MAILBOX, ROLE_MIX};
    use khensu_crypto::{KemKeyPair, SigKeyPair};
    use rand::SeedableRng;

    /// A node of the sample directory: its lease, signing key and mix keys by epoch.
    pub(crate) type SampleNode = (Lease, SigKeyPair, Vec<KemKeyPair>);

    /// A devnet-shaped directory: gateway, three mixes, two mailboxes, all on
    /// the committee; with the nodes' keys and the founder key.
    pub(crate) fn sample_dir(epochs: std::ops::Range<u64>) -> (Directory, Vec<SampleNode>, SigKeyPair) {
        let specs = [
            (1u8, ROLE_GATEWAY | ROLE_MIX),
            (2, ROLE_MIX),
            (3, ROLE_MIX),
            (4, ROLE_MIX),
            (5, ROLE_MAILBOX | ROLE_MIX),
            (6, ROLE_MAILBOX | ROLE_MIX),
        ];
        let nodes: Vec<_> = specs.iter().map(|(s, r)| sample(*s, r | ROLE_COMMITTEE, epochs.clone())).collect();
        let leases: Vec<Lease> = nodes.iter().map(|n| n.0.clone()).collect();
        let founder = SigKeyPair::from_seed([99; 32]);
        let rules = Rules { founder_pk: b64(&founder.public().0), ..Rules::devnet(6) };
        let committee = draw_committee(&[0; 64], &leases, epochs.start, 0, 6);
        let mut header = EpochHeader {
            chain_id: 1,
            network_epoch: epochs.start,
            prev_header_hash: [0; 64],
            node_list_root: node_list_root(&leases),
            state_root: empty_state_root(),
            receipts_root: receipts_root(&[]),
            evidence_root: evidence_root(&[]),
            rules_hash: rules.hash(),
            committee_root: committee_root(&committee),
            founder_cosig: Vec::new(),
            signatures: Vec::new(),
        };
        header.founder_sign(&founder).unwrap();
        let d = Directory::genesis("test", 0, rules, HeaderBundle { header, leases, rules: None }).unwrap();
        (d, nodes, founder)
    }

    #[test]
    fn json_roundtrip_and_routes() {
        let (d, _, _) = sample_dir(5..7);
        let d = Directory::from_json(&d.to_json()).unwrap();
        assert_eq!(d.nodes.len(), 6);
        assert_eq!(d.committee.len(), 6);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let gw = d.node_by_name("n1").unwrap();
        let mbs = d.mailboxes_for(&[1; 32], 5);
        assert_eq!(mbs.len(), 2);
        let r = d.forward_route(&mut rng, gw, mbs[0], 5).unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].node_id, gw.id());
        assert_eq!(r[4].node_id, mbs[0].id());
        assert_eq!(d.reply_route(&mut rng, gw, 6).unwrap().len(), 4);
        assert_eq!(d.client_loop_route(&mut rng, gw, 6).unwrap().len(), 5);
        let own = d.node_loop_route(&mut rng, gw, 6).unwrap();
        assert_eq!(own.len(), 4);
        assert_eq!(own[3].node_id, gw.id());
        assert!(d.forward_route(&mut rng, gw, mbs[0], 7).is_err(), "no keys for epoch 7");
        let layers = d.layers(5);
        assert_eq!(layers.len(), 6);
    }

    #[test]
    fn advance_checks_the_chain() {
        let (d, nodes, _) = sample_dir(5..8);
        let leases = d.lease_list.clone();
        let committee = draw_committee(&d.header_hash(), &leases, 6, 0, 6);
        let mut next = EpochHeader {
            chain_id: 1,
            network_epoch: 6,
            prev_header_hash: d.header_hash(),
            node_list_root: node_list_root(&leases),
            state_root: empty_state_root(),
            receipts_root: receipts_root(&[vec![1, 2, 3]]),
            evidence_root: evidence_root(&[]),
            rules_hash: d.rules.hash(),
            committee_root: committee_root(&committee),
            founder_cosig: Vec::new(),
            signatures: Vec::new(),
        };
        let bundle = |h: &EpochHeader| HeaderBundle { header: h.clone(), leases: leases.clone(), rules: None };
        assert!(d.advance(bundle(&next)).is_err(), "unsigned");
        for (i, id) in d.committee.iter().enumerate() {
            let key = &nodes.iter().find(|n| n.0.node_id() == *id).unwrap().1;
            let sig = next.member_sign(key).unwrap();
            next.add_signature(i as u8, sig);
            if i + 1 == d.rules.threshold as usize {
                break;
            }
        }
        let d2 = d.advance(bundle(&next)).unwrap();
        assert_eq!(d2.epoch(), 6);
        assert!(d2.advance(bundle(&next)).is_err(), "same epoch again");
        let mut tampered = next.clone();
        tampered.receipts_root = [9; 64];
        assert!(d.advance(bundle(&tampered)).is_err());
    }
}
