// SPDX-License-Identifier: Apache-2.0
//! The node directory and route selection.
//!
//! On the real network this comes from the epoch header's lease list
//! (PROTOCOL.md 12); devnets write the same information to `devnet.json`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use khensu_crypto::sym::h256;
use khensu_crypto::{KemPublicKey, SigPublicKey};
use khensu_outfox::epoch::{EPOCH_SECS, network_epoch};
use khensu_outfox::{Hop, sample_delay_ms};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{Error, Result, node_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Entry node: first hop of every client packet, last hop of every SURB.
    Gateway,
    Mix,
    Mailbox,
}

/// Consensus parameters (epoch header) that clients and nodes need.
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
        Self {
            tick_ms: 2000,
            small_per_tick: 4,
            downstream_per_tick: 4,
            mix_delay_mean_ms: 250,
            surbs_per_fetch: 4,
            link_small_rate: 20.0,
            link_bulk_rate: 2.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixKey {
    pub epoch: u64,
    /// ML-KEM-1024 encapsulation key, base64.
    pub ek: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEntry {
    pub name: String,
    /// Hex `H256(Label("node") || sig_pk)`.
    pub node_id: String,
    pub roles: Vec<Role>,
    /// Mix layer 1 to 3; absent for other roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<u8>,
    /// `host:port` of the node's QUIC endpoint.
    pub endpoint: String,
    /// ML-DSA-87 directory signing key, base64.
    pub sig_pk: String,
    /// ML-KEM-1024 directory key for the inner handshake, base64.
    pub kem_pk: String,
    pub mix_keys: Vec<MixKey>,
}

impl NodeEntry {
    pub fn id(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&self.node_id, &mut out).expect("validated on load");
        out
    }

    pub fn has_role(&self, r: Role) -> bool {
        self.roles.contains(&r)
    }

    pub fn sig_public(&self) -> SigPublicKey {
        SigPublicKey(B64.decode(&self.sig_pk).expect("validated on load"))
    }

    pub fn kem_public(&self) -> KemPublicKey {
        KemPublicKey::from_slice(&B64.decode(&self.kem_pk).expect("validated on load")).expect("validated on load")
    }

    pub fn mix_ek(&self, epoch: u64) -> Option<KemPublicKey> {
        let k = self.mix_keys.iter().find(|k| k.epoch == epoch)?;
        KemPublicKey::from_slice(&B64.decode(&k.ek).ok()?).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Directory {
    pub version: u32,
    pub network: String,
    pub genesis_time: u64,
    pub epoch_secs: u64,
    #[serde(default)]
    pub params: Params,
    pub nodes: Vec<NodeEntry>,
}

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

impl Directory {
    pub fn from_json(json: &str) -> Result<Self> {
        let d: Directory = serde_json::from_str(json).map_err(|e| Error::Directory(e.to_string()))?;
        d.validate()?;
        Ok(d)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serializable")
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::Directory(m));
        if self.version != 1 {
            return bad(format!("unsupported version {}", self.version));
        }
        if self.epoch_secs != EPOCH_SECS {
            return bad("epoch_secs must be 3600".into());
        }
        for n in &self.nodes {
            let sig = B64.decode(&n.sig_pk).map_err(|_| Error::Directory(format!("{}: sig_pk", n.name)))?;
            if hex::encode(node_id(&sig)) != n.node_id {
                return bad(format!("{}: node_id does not match sig_pk", n.name));
            }
            let kem = B64.decode(&n.kem_pk).map_err(|_| Error::Directory(format!("{}: kem_pk", n.name)))?;
            KemPublicKey::from_slice(&kem).map_err(|_| Error::Directory(format!("{}: kem_pk", n.name)))?;
            if n.has_role(Role::Mix) && !matches!(n.layer, Some(1..=3)) {
                return bad(format!("{}: mix needs layer 1-3", n.name));
            }
            for k in &n.mix_keys {
                let ek = B64.decode(&k.ek).map_err(|_| Error::Directory(format!("{}: mix key", n.name)))?;
                KemPublicKey::from_slice(&ek).map_err(|_| Error::Directory(format!("{}: mix key", n.name)))?;
            }
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

    pub fn node_by_name(&self, name: &str) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn with_role(&self, r: Role) -> impl Iterator<Item = &NodeEntry> {
        self.nodes.iter().filter(move |n| n.has_role(r))
    }

    /// Mailbox replica for `mailbox_id` by rendezvous hashing (PROTOCOL.md 6.2).
    /// v0.1 uses the top-ranked replica only.
    pub fn mailbox_for(&self, mailbox_id: &[u8; 32], epoch: u64) -> Option<&NodeEntry> {
        self.with_role(Role::Mailbox)
            .filter(|n| n.mix_ek(epoch).is_some())
            .max_by_key(|n| h256("rendezvous", &[mailbox_id, &n.id()]))
    }

    fn hop(&self, n: &NodeEntry, epoch: u64, delay_ms: u32) -> Result<Hop> {
        Ok(Hop { node_id: n.id(), mix_ek: n.mix_ek(epoch).ok_or(Error::NoRoute("no mix key for epoch"))?, delay_ms })
    }

    fn mixes(&self, rng: &mut (impl RngCore + CryptoRng), epoch: u64) -> Result<Vec<Hop>> {
        (1..=3u8)
            .map(|layer| {
                let layer_nodes: Vec<&NodeEntry> = self
                    .with_role(Role::Mix)
                    .filter(|n| n.layer == Some(layer) && n.mix_ek(epoch).is_some())
                    .collect();
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
        route.extend(self.mixes(rng, epoch)?);
        route.push(self.hop(destination, epoch, 0)?);
        Ok(route)
    }

    /// One mix per layer, then the client's entry node.
    pub fn reply_route(&self, rng: &mut (impl RngCore + CryptoRng), gateway: &NodeEntry, epoch: u64) -> Result<Vec<Hop>> {
        let mut route = self.mixes(rng, epoch)?;
        route.push(self.hop(gateway, epoch, 0)?);
        Ok(route)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use khensu_crypto::{KemKeyPair, SigKeyPair};
    use rand::SeedableRng;

    pub(crate) fn sample(epochs: std::ops::Range<u64>) -> (Directory, Vec<(SigKeyPair, Vec<KemKeyPair>)>) {
        let mut nodes = Vec::new();
        let mut keys = Vec::new();
        let specs = [("gw", Role::Gateway, None), ("m1", Role::Mix, Some(1)), ("m2", Role::Mix, Some(2)), ("m3", Role::Mix, Some(3)), ("mb", Role::Mailbox, None)];
        for (i, (name, role, layer)) in specs.into_iter().enumerate() {
            let sig = SigKeyPair::from_seed([i as u8; 32]);
            let kem = KemKeyPair::from_seed([i as u8; 64]);
            let mix: Vec<KemKeyPair> = epochs.clone().map(|e| KemKeyPair::from_seed([(i as u8) ^ (e as u8) ^ 0x80; 64])).collect();
            nodes.push(NodeEntry {
                name: name.into(),
                node_id: hex::encode(node_id(&sig.public().0)),
                roles: vec![role],
                layer,
                endpoint: format!("127.0.0.1:{}", 47000 + i),
                sig_pk: b64(&sig.public().0),
                kem_pk: b64(&kem.public().0),
                mix_keys: epochs.clone().zip(&mix).map(|(e, k)| MixKey { epoch: e, ek: b64(&k.public().0) }).collect(),
            });
            keys.push((sig, mix));
        }
        let d = Directory { version: 1, network: "test".into(), genesis_time: 0, epoch_secs: 3600, params: Params::default(), nodes };
        (d, keys)
    }

    #[test]
    fn json_roundtrip_and_routes() {
        let (d, _) = sample(5..7);
        let d = Directory::from_json(&d.to_json()).unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let gw = d.node_by_name("gw").unwrap();
        let mb = d.mailbox_for(&[1; 32], 5).unwrap();
        let r = d.forward_route(&mut rng, gw, mb, 5).unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].node_id, gw.id());
        assert_eq!(r[4].node_id, mb.id());
        assert_eq!(d.reply_route(&mut rng, gw, 6).unwrap().len(), 4);
        assert!(d.forward_route(&mut rng, gw, mb, 7).is_err(), "no keys for epoch 7");
    }

    #[test]
    fn rejects_forged_node_id() {
        let (mut d, _) = sample(0..1);
        d.nodes[1].node_id = d.nodes[0].node_id.clone();
        assert!(Directory::from_json(&d.to_json()).is_err());
    }
}
