// SPDX-License-Identifier: Apache-2.0
//! Client state machine: conversations, outbox, ticks and incoming replies.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use khensu_crypto::kem::{KemCiphertext, KemKeyPair, KemPublicKey};
use khensu_crypto::sym::{kdf, open, seal};
use khensu_crypto::{SigKeyPair, random};
use khensu_mls::content::{ContentType, KhensuContent};
use khensu_mls::fragment::{Fragment, Reassembler, bucket_for, split};
use khensu_mls::mailbox::{intro_mailbox, mailbox_id, mailbox_seed};
use khensu_mls::tree::{TreeManifest, assemble, chunk_address, chunk_tree};
use khensu_mls::{KhensuCredential, KhensuProvider, MlDsaSigner, SUITE, capabilities, create_config, join_config};
use khensu_net::{Directory, NodeEntry, Role};
use khensu_outfox::delivery::{FinalPayload, MAX_FETCH_SURBS, MailboxOp, MailboxReply, MailboxRequest, ReplyBody, item_id};
use khensu_outfox::epoch::DEVNET_GENESIS_TIME;
use khensu_outfox::{Lane, SurbKeys, forward, surb};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use rand::rngs::OsRng;

use crate::identity::{Identity, display_address};
use crate::wire::{ContactCard, Envelope, IntroBundle};
use crate::{ClientEvent, ConversationInfo, KhensuError, MemberInfo, OutgoingPacket};

const ZERO_NONCE: [u8; 12] = [0; 12];
const SEEN_TTL_SECS: u64 = 30 * 24 * 3600;
const HOLD_TTL_SECS: u64 = 7 * 24 * 3600;
const KEY_PACKAGE_TTL_EPOCHS: u64 = 90 * 24;
const TREE_GET_RETRY_TICKS: u64 = 10;
/// Item IDs per small-lane `ack` (62 fit; leave room).
const ACK_BATCH: usize = 60;

pub(crate) fn mls_err(e: impl core::fmt::Debug) -> KhensuError {
    KhensuError::Mls { msg: format!("{e:?}") }
}

pub(crate) struct Group {
    pub mls: MlsGroup,
    pub signer_seed: [u8; 32],
    pub title: String,
    pub direct: bool,
    /// Mailbox seed of the previous group epoch, still watched.
    pub prev_seed: Option<[u8; 32]>,
}

pub(crate) struct PendingKp {
    pub signer_seed: [u8; 32],
    pub intro_seed: [u8; 64],
    pub created_epoch: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum SurbPurpose {
    Fetch([u8; 32]),
    TreeGet([u8; 32]),
}

pub(crate) struct PendingSurb {
    pub keys: SurbKeys,
    pub purpose: SurbPurpose,
    pub epoch: u64,
}

#[derive(Clone)]
pub(crate) enum Outgoing {
    Request { rendezvous: [u8; 32], request: MailboxRequest },
    TreeGet([u8; 32]),
}

pub(crate) enum BlobPurpose {
    Join { kp_ref: Vec<u8>, welcome: Vec<u8>, tree_key: [u8; 32], title: String },
    Message { group_id: Vec<u8> },
}

pub(crate) struct PendingBlob {
    pub manifest: TreeManifest,
    pub chunks: BTreeMap<[u8; 32], Vec<u8>>,
    pub requested: BTreeMap<[u8; 32], u64>,
    pub purpose: BlobPurpose,
    pub since: u64,
}

pub(crate) struct Held {
    pub group_id: Vec<u8>,
    pub message: Vec<u8>,
    pub since: u64,
}

enum Target {
    Group(Vec<u8>),
    Intro(Vec<u8>),
}

pub(crate) struct Core {
    pub provider: KhensuProvider,
    pub identity: Identity,
    pub display_name: String,
    pub device_index: u16,
    pub delivery_id: [u8; 32],
    pub directory: Option<Arc<Directory>>,
    pub gateway: Option<String>,
    pub groups: BTreeMap<Vec<u8>, Group>,
    pub key_packages: BTreeMap<Vec<u8>, PendingKp>,
    pub surbs: HashMap<[u8; 16], PendingSurb>,
    pub small_out: VecDeque<Outgoing>,
    pub bulk_out: VecDeque<Outgoing>,
    pub acks: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    pub reassembler: Reassembler,
    pub seen: HashMap<[u8; 32], u64>,
    pub held: Vec<Held>,
    pub blobs: Vec<PendingBlob>,
    pub priority: VecDeque<[u8; 32]>,
    pub cursor: u64,
    pub ticks: u64,
}

fn secs(now_ms: u64) -> u64 {
    now_ms / 1000
}

impl Core {
    pub fn new(display_name: String, now_ms: u64) -> Result<Self, KhensuError> {
        let epoch = khensu_outfox::epoch::network_epoch(secs(now_ms), DEVNET_GENESIS_TIME);
        Self::with_identity(Identity::create(epoch)?, display_name, random()?)
    }

    pub fn with_identity(identity: Identity, display_name: String, delivery_id: [u8; 32]) -> Result<Self, KhensuError> {
        Ok(Self {
            provider: KhensuProvider::in_memory().map_err(mls_err)?,
            identity,
            display_name,
            device_index: 0,
            delivery_id,
            directory: None,
            gateway: None,
            groups: BTreeMap::new(),
            key_packages: BTreeMap::new(),
            surbs: HashMap::new(),
            small_out: VecDeque::new(),
            bulk_out: VecDeque::new(),
            acks: BTreeMap::new(),
            reassembler: Reassembler::default(),
            seen: HashMap::new(),
            held: Vec::new(),
            blobs: Vec::new(),
            priority: VecDeque::new(),
            cursor: 0,
            ticks: 0,
        })
    }

    fn credential(&self) -> KhensuCredential {
        // log_index stays 0 until the key transparency log exists.
        KhensuCredential { address: self.identity.address, device_index: self.device_index, log_index: 0 }
    }

    pub fn dir(&self) -> Result<Arc<Directory>, KhensuError> {
        self.directory.clone().ok_or(KhensuError::State { msg: "no directory loaded".into() })
    }

    pub fn epoch(&self, now_ms: u64) -> u64 {
        let genesis = self.directory.as_ref().map_or(DEVNET_GENESIS_TIME, |d| d.genesis_time);
        khensu_outfox::epoch::network_epoch(secs(now_ms), genesis)
    }

    pub fn gateway_entry(&self, dir: &Directory) -> Result<NodeEntry, KhensuError> {
        let gw = match &self.gateway {
            Some(name) => dir.node_by_name(name),
            None => dir.with_role(Role::Gateway).next(),
        };
        gw.cloned().ok_or(KhensuError::NotFound { msg: "gateway".into() })
    }

    // ---- conversations ----

    pub fn create_contact_card(&mut self, now_ms: u64) -> Result<Vec<u8>, KhensuError> {
        let seed: [u8; 32] = random()?;
        let signer = MlDsaSigner::from_seed(seed);
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(SUITE, &self.provider, &signer, self.credential().with_key(signer.public_key()))
            .map_err(mls_err)?;
        let kp = bundle.key_package();
        let kp_ref = kp.hash_ref(self.provider.crypto()).map_err(mls_err)?.as_slice().to_vec();
        let intro_seed: [u8; 64] = random()?;
        let intro = KemKeyPair::from_seed(intro_seed);
        let card = ContactCard::signed(
            kp.tls_serialize_detached().map_err(mls_err)?,
            intro.public().0.to_vec(),
            self.display_name.clone(),
            &SigKeyPair::from_seed(seed),
        )?;
        let created_epoch = self.epoch(now_ms);
        self.key_packages.insert(kp_ref, PendingKp { signer_seed: seed, intro_seed, created_epoch });
        Ok(card.encode())
    }

    pub fn create_group(&mut self, title: String, direct: bool) -> Result<Vec<u8>, KhensuError> {
        let seed: [u8; 32] = random()?;
        let signer = MlDsaSigner::from_seed(seed);
        let g = MlsGroup::new(&self.provider, &signer, &create_config(), self.credential().with_key(signer.public_key()))
            .map_err(mls_err)?;
        let gid = g.group_id().as_slice().to_vec();
        self.groups.insert(gid.clone(), Group { mls: g, signer_seed: seed, title, direct, prev_seed: None });
        Ok(gid)
    }

    pub fn add_member(&mut self, gid: &[u8], card_bytes: &[u8], now_ms: u64) -> Result<(), KhensuError> {
        let epoch = self.epoch(now_ms);
        let card = ContactCard::decode(card_bytes)?;
        let kp = KeyPackageIn::tls_deserialize_exact(&card.key_package)
            .map_err(mls_err)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_err)?;
        card.verify(kp.leaf_node().signature_key().as_slice())?;
        KhensuCredential::from_mls(kp.leaf_node().credential())?;
        let kp_ref = kp.hash_ref(self.provider.crypto()).map_err(mls_err)?.as_slice().to_vec();
        let intro_ek = KemPublicKey::from_slice(&card.intro_ek)?;

        let Core { provider, groups, .. } = self;
        let g = groups.get_mut(gid).ok_or(KhensuError::NotFound { msg: "conversation".into() })?;
        let signer = MlDsaSigner::from_seed(g.signer_seed);
        let own = g.mls.own_leaf_index();
        let existing: Vec<u32> = g.mls.members().map(|m| m.index).filter(|&i| i != own).map(|i| i.u32()).collect();
        let old_seed = mailbox_seed(&g.mls, provider.crypto())?;
        let (commit, welcome, _) = g.mls.add_members(provider, &signer, &[kp]).map_err(mls_err)?;
        g.mls.merge_pending_commit(provider).map_err(mls_err)?;
        g.prev_seed = Some(old_seed);
        let title = if g.direct { self.display_name.clone() } else { g.title.clone() };
        let tree = g.mls.export_ratchet_tree().tls_serialize_detached().map_err(mls_err)?;

        if !existing.is_empty() {
            let commit = commit.tls_serialize_detached().map_err(mls_err)?;
            let ids = existing.iter().map(|&l| mailbox_id(&old_seed, l, epoch)).collect();
            self.queue_mls(commit, ids)?;
        }
        let tree_key: [u8; 32] = random()?;
        let manifest = self.put_blob(&seal(&tree_key, &ZERO_NONCE, &tree, b""));
        let bundle = IntroBundle { welcome: welcome.tls_serialize_detached().map_err(mls_err)?, tree_key, manifest, title };
        let (kem_ct, ss) = intro_ek.encapsulate()?;
        let key: [u8; 32] = kdf(&ss, &[], "intro bundle");
        let sealed = seal(&key, &ZERO_NONCE, &bundle.encode(), &kp_ref);
        let env = Envelope::Intro { kem_ct: kem_ct.0.to_vec(), sealed };
        self.queue_envelope(&env, vec![intro_mailbox(&kp_ref, epoch)])
    }

    pub fn send_text(&mut self, gid: &[u8], text: &str, now_ms: u64) -> Result<[u8; 16], KhensuError> {
        let epoch = self.epoch(now_ms);
        let message_id: [u8; 16] = random()?;
        let content = KhensuContent {
            content_type: ContentType::Text,
            message_id,
            sent_at_ms: now_ms,
            expires_after_s: 0,
            body: text.as_bytes().to_vec(),
        };
        let Core { provider, groups, .. } = self;
        let g = groups.get_mut(gid).ok_or(KhensuError::NotFound { msg: "conversation".into() })?;
        if !g.mls.is_active() {
            return Err(KhensuError::State { msg: "no longer a member".into() });
        }
        let signer = MlDsaSigner::from_seed(g.signer_seed);
        let msg = g.mls.create_message(provider, &signer, &content.encode()).map_err(mls_err)?;
        let seed = mailbox_seed(&g.mls, provider.crypto())?;
        let own = g.mls.own_leaf_index();
        let ids: Vec<[u8; 32]> =
            g.mls.members().filter(|m| m.index != own).map(|m| mailbox_id(&seed, m.index.u32(), epoch)).collect();
        if ids.is_empty() {
            return Err(KhensuError::State { msg: "conversation has no other members yet".into() });
        }
        self.queue_mls(msg.tls_serialize_detached().map_err(mls_err)?, ids)?;
        Ok(message_id)
    }

    fn queue_mls(&mut self, mls: Vec<u8>, mailbox_ids: Vec<[u8; 32]>) -> Result<(), KhensuError> {
        let env = Envelope::Mls(mls);
        if bucket_for(env.encode().len()).is_ok() {
            return self.queue_envelope(&env, mailbox_ids);
        }
        let Envelope::Mls(mls) = env else { unreachable!() };
        let manifest = self.put_blob(&mls);
        self.queue_envelope(&Envelope::Chunked(manifest), mailbox_ids)
    }

    fn queue_envelope(&mut self, env: &Envelope, mailbox_ids: Vec<[u8; 32]>) -> Result<(), KhensuError> {
        let frags = split(&env.encode())?;
        for mbx in mailbox_ids {
            for f in &frags {
                let request = MailboxRequest::new(mbx, MailboxOp::Store { sealed: f.encode(), surb: None });
                self.small_out.push_back(Outgoing::Request { rendezvous: mbx, request });
            }
        }
        Ok(())
    }

    fn put_blob(&mut self, bytes: &[u8]) -> TreeManifest {
        let (manifest, chunks) = chunk_tree(bytes);
        for (chunk, addr) in chunks.into_iter().zip(&manifest.chunk_hashes) {
            let request = MailboxRequest::new(*addr, MailboxOp::TreePut { chunk });
            self.bulk_out.push_back(Outgoing::Request { rendezvous: *addr, request });
        }
        manifest
    }

    pub fn conversations(&self) -> Vec<ConversationInfo> {
        self.groups
            .iter()
            .map(|(gid, g)| {
                let own = g.mls.own_leaf_index();
                let members = g
                    .mls
                    .members()
                    .filter_map(|m| {
                        let c = KhensuCredential::from_mls(&m.credential).ok()?;
                        Some(MemberInfo {
                            address: display_address(&c.address),
                            device_index: c.device_index,
                            leaf_index: m.index.u32(),
                            is_self: m.index == own,
                        })
                    })
                    .collect();
                ConversationInfo {
                    conversation_id: hex::encode(gid),
                    title: g.title.clone(),
                    direct: g.direct,
                    epoch: g.mls.epoch().as_u64(),
                    active: g.mls.is_active(),
                    members,
                }
            })
            .collect()
    }

    // ---- ticks ----

    fn prune(&mut self, now_ms: u64, epoch: u64) {
        let now = secs(now_ms);
        self.surbs.retain(|_, s| s.epoch + 2 > epoch);
        self.seen.retain(|_, t| now.saturating_sub(*t) < SEEN_TTL_SECS);
        self.held.retain(|h| now.saturating_sub(h.since) < HOLD_TTL_SECS);
        self.blobs.retain(|b| now.saturating_sub(b.since) < HOLD_TTL_SECS);
        self.reassembler.expire(now);
        self.key_packages.retain(|_, k| k.created_epoch + KEY_PACKAGE_TTL_EPOCHS > epoch);
    }

    fn watched(&self, epoch: u64) -> Vec<([u8; 32], bool, Target)> {
        let mut out = Vec::new();
        let prev_epoch = epoch.checked_sub(1);
        for (gid, g) in &self.groups {
            if !g.mls.is_active() {
                continue;
            }
            let Ok(seed) = mailbox_seed(&g.mls, self.provider.crypto()) else { continue };
            let leaf = g.mls.own_leaf_index().u32();
            out.push((mailbox_id(&seed, leaf, epoch), true, Target::Group(gid.clone())));
            for s in std::iter::once(seed).chain(g.prev_seed) {
                for e in [Some(epoch), prev_epoch].into_iter().flatten() {
                    if s != seed || e != epoch {
                        out.push((mailbox_id(&s, leaf, e), false, Target::Group(gid.clone())));
                    }
                }
            }
        }
        for kp_ref in self.key_packages.keys() {
            out.push((intro_mailbox(kp_ref, epoch), true, Target::Intro(kp_ref.clone())));
            if let Some(e) = prev_epoch {
                out.push((intro_mailbox(kp_ref, e), false, Target::Intro(kp_ref.clone())));
            }
        }
        out
    }

    fn resolve(&self, mbx: &[u8; 32], epoch: u64) -> Option<Target> {
        self.watched(epoch).into_iter().chain(self.watched(epoch + 1)).find(|w| &w.0 == mbx).map(|w| w.2)
    }

    /// Current-epoch mailboxes every tick in turn; the previous seed and
    /// epoch every fourth.
    fn next_fetch(&mut self, epoch: u64) -> Option<[u8; 32]> {
        if let Some(p) = self.priority.pop_front() {
            return Some(p);
        }
        let w = self.watched(epoch);
        let primary: Vec<[u8; 32]> = w.iter().filter(|x| x.1).map(|x| x.0).collect();
        let secondary: Vec<[u8; 32]> = w.iter().filter(|x| !x.1).map(|x| x.0).collect();
        self.cursor += 1;
        let c = self.cursor as usize;
        if !secondary.is_empty() && (c % 4 == 0 || primary.is_empty()) {
            Some(secondary[(c / 4) % secondary.len()])
        } else if !primary.is_empty() {
            Some(primary[c % primary.len()])
        } else {
            None
        }
    }

    fn flush_acks(&mut self) {
        for (mbx, ids) in std::mem::take(&mut self.acks) {
            for chunk in ids.chunks(ACK_BATCH) {
                let request = MailboxRequest::new(mbx, MailboxOp::Ack { item_ids: chunk.to_vec() });
                self.small_out.push_front(Outgoing::Request { rendezvous: mbx, request });
            }
        }
    }

    fn schedule_tree_gets(&mut self) {
        let tick = self.ticks;
        let mut wanted = Vec::new();
        for b in &mut self.blobs {
            for h in &b.manifest.chunk_hashes {
                if b.chunks.contains_key(h) {
                    continue;
                }
                let due = b.requested.get(h).is_none_or(|&t| tick >= t + TREE_GET_RETRY_TICKS);
                if due {
                    b.requested.insert(*h, tick);
                    wanted.push(*h);
                }
            }
        }
        self.bulk_out.extend(wanted.into_iter().map(Outgoing::TreeGet));
    }

    fn packet(&self, dir: &Directory, gw: &NodeEntry, rendezvous: &[u8; 32], payload: &[u8], epoch: u64) -> Result<OutgoingPacket, KhensuError> {
        let dest = dir.mailbox_for(rendezvous, epoch).ok_or(KhensuError::Network { msg: "no mailbox node".into() })?;
        let route = dir.forward_route(&mut OsRng, gw, dest, epoch)?;
        let p = forward(&mut OsRng, &route, payload)?;
        Ok(OutgoingPacket { first_hop: gw.node_id.clone(), endpoint: gw.endpoint.clone(), bytes: p.to_bytes() })
    }

    fn cover(&self, dir: &Directory, gw: &NodeEntry, lane: Lane, epoch: u64) -> Result<OutgoingPacket, KhensuError> {
        let r: [u8; 32] = random()?;
        self.packet(dir, gw, &r, &FinalPayload::cover().encode(lane)?, epoch)
    }

    fn reply_surb(&mut self, dir: &Directory, gw: &NodeEntry, lane: Lane, purpose: SurbPurpose, epoch: u64) -> Result<khensu_outfox::Surb, KhensuError> {
        let route = dir.reply_route(&mut OsRng, gw, epoch)?;
        let (s, keys) = surb::create(&mut OsRng, &route, self.delivery_id, lane)?;
        self.surbs.insert(keys.payload_key_ref, PendingSurb { keys, purpose, epoch });
        Ok(s)
    }

    pub(crate) fn build(&mut self, dir: &Directory, gw: &NodeEntry, o: Outgoing, lane: Lane, epoch: u64) -> Result<OutgoingPacket, KhensuError> {
        match o {
            Outgoing::Request { rendezvous, request } => self.packet(dir, gw, &rendezvous, &request.to_payload(lane)?, epoch),
            Outgoing::TreeGet(h) => {
                let s = self.reply_surb(dir, gw, Lane::Bulk, SurbPurpose::TreeGet(h), epoch)?;
                let req = MailboxRequest::new(h, MailboxOp::TreeGet { chunk_hash: h, surb: s });
                self.packet(dir, gw, &h, &req.to_payload(Lane::Bulk)?, epoch)
            }
        }
    }

    fn build_fetch(&mut self, dir: &Directory, gw: &NodeEntry, mbx: [u8; 32], epoch: u64) -> Result<OutgoingPacket, KhensuError> {
        let n = (dir.params.surbs_per_fetch as usize).clamp(1, MAX_FETCH_SURBS);
        let surbs = (0..n)
            .map(|_| self.reply_surb(dir, gw, Lane::Small, SurbPurpose::Fetch(mbx), epoch))
            .collect::<Result<Vec<_>, _>>()?;
        let req = MailboxRequest::new(mbx, MailboxOp::Fetch { max_items: n as u32, surbs });
        self.packet(dir, gw, &mbx, &req.to_payload(Lane::Bulk)?, epoch)
    }

    /// One burst: a bulk packet (mailbox fetch, or a queued bulk request every
    /// other tick) and `small_per_tick - 1` small packets, cover when idle.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<OutgoingPacket>, KhensuError> {
        let dir = self.dir()?;
        let gw = self.gateway_entry(&dir)?;
        let epoch = self.epoch(now_ms);
        self.prune(now_ms, epoch);
        self.ticks += 1;
        self.schedule_tree_gets();
        self.flush_acks();

        let mut out = Vec::new();
        let fetch = self.next_fetch(epoch);
        let bulk = match (self.bulk_out.is_empty(), fetch) {
            (false, f) if f.is_none() || self.ticks % 2 == 0 => {
                let o = self.bulk_out.pop_front().expect("non-empty");
                if let Some(f) = f {
                    self.priority.push_front(f);
                }
                self.build(&dir, &gw, o, Lane::Bulk, epoch)?
            }
            (_, Some(f)) => self.build_fetch(&dir, &gw, f, epoch)?,
            (_, None) => self.cover(&dir, &gw, Lane::Bulk, epoch)?,
        };
        out.push(bulk);
        for _ in 1..dir.params.small_per_tick.max(1) {
            let p = match self.small_out.pop_front() {
                Some(o) => self.build(&dir, &gw, o, Lane::Small, epoch)?,
                None => self.cover(&dir, &gw, Lane::Small, epoch)?,
            };
            out.push(p);
        }
        Ok(out)
    }

    pub fn pending(&self) -> u32 {
        (self.small_out.len() + self.bulk_out.len()) as u32
    }

    // ---- incoming ----

    pub fn process_incoming(&mut self, payload_key_ref: &[u8], payload: Vec<u8>, now_ms: u64) -> Result<Vec<ClientEvent>, KhensuError> {
        let Ok(r) = <[u8; 16]>::try_from(payload_key_ref) else { return Ok(Vec::new()) };
        // Unknown references are the entry node's cover deliveries.
        let Some(ps) = self.surbs.remove(&r) else { return Ok(Vec::new()) };
        let Ok(plain) = ps.keys.open(payload) else { return Ok(Vec::new()) };
        let Ok(reply) = MailboxReply::decode(&plain) else { return Ok(Vec::new()) };
        match (ps.purpose, reply.body) {
            (SurbPurpose::Fetch(mbx), body) => {
                if reply.more && !self.priority.contains(&mbx) {
                    self.priority.push_back(mbx);
                }
                match body {
                    ReplyBody::Item { sealed } => self.on_item(mbx, sealed, now_ms),
                    _ => Ok(Vec::new()),
                }
            }
            (SurbPurpose::TreeGet(h), ReplyBody::TreeChunk { chunk }) => self.on_chunk(h, chunk, now_ms),
            _ => Ok(Vec::new()),
        }
    }

    fn on_item(&mut self, mbx: [u8; 32], sealed: Vec<u8>, now_ms: u64) -> Result<Vec<ClientEvent>, KhensuError> {
        let id = item_id(&sealed);
        self.acks.entry(mbx).or_default().push(id);
        if self.seen.insert(id, secs(now_ms)).is_some() {
            return Ok(Vec::new());
        }
        let Ok(frag) = Fragment::decode(&sealed) else { return Ok(Vec::new()) };
        let Ok(Some(msg)) = self.reassembler.push(frag, secs(now_ms)) else { return Ok(Vec::new()) };
        let Ok(env) = Envelope::decode(&msg) else { return Ok(Vec::new()) };
        match (self.resolve(&mbx, self.epoch(now_ms)), env) {
            (Some(Target::Group(gid)), Envelope::Mls(m)) => self.on_mls(&gid, m, now_ms),
            (Some(Target::Group(gid)), Envelope::Chunked(manifest)) => {
                self.blobs.push(PendingBlob {
                    manifest,
                    chunks: BTreeMap::new(),
                    requested: BTreeMap::new(),
                    purpose: BlobPurpose::Message { group_id: gid },
                    since: secs(now_ms),
                });
                Ok(Vec::new())
            }
            (Some(Target::Intro(kp_ref)), Envelope::Intro { kem_ct, sealed }) => self.on_intro(kp_ref, &kem_ct, &sealed, now_ms),
            _ => Ok(Vec::new()),
        }
    }

    fn on_intro(&mut self, kp_ref: Vec<u8>, kem_ct: &[u8], sealed: &[u8], now_ms: u64) -> Result<Vec<ClientEvent>, KhensuError> {
        let Some(kp) = self.key_packages.get(&kp_ref) else { return Ok(Vec::new()) };
        let ss = KemKeyPair::from_seed(kp.intro_seed).decapsulate(&KemCiphertext::from_slice(kem_ct)?);
        let key: [u8; 32] = kdf(&ss, &[], "intro bundle");
        let Ok(plain) = open(&key, &ZERO_NONCE, sealed, &kp_ref) else { return Ok(Vec::new()) };
        let b = IntroBundle::decode(&plain)?;
        self.blobs.push(PendingBlob {
            manifest: b.manifest,
            chunks: BTreeMap::new(),
            requested: BTreeMap::new(),
            purpose: BlobPurpose::Join { kp_ref, welcome: b.welcome, tree_key: b.tree_key, title: b.title },
            since: secs(now_ms),
        });
        Ok(Vec::new())
    }

    fn on_chunk(&mut self, h: [u8; 32], chunk: Vec<u8>, now_ms: u64) -> Result<Vec<ClientEvent>, KhensuError> {
        if chunk_address(&chunk) != h {
            return Ok(Vec::new());
        }
        for b in &mut self.blobs {
            if b.manifest.chunk_hashes.contains(&h) {
                b.chunks.insert(h, chunk.clone());
            }
        }
        let Some(i) = self.blobs.iter().position(|b| b.manifest.chunk_hashes.iter().all(|c| b.chunks.contains_key(c))) else {
            return Ok(Vec::new());
        };
        let b = self.blobs.remove(i);
        let Ok(bytes) = assemble(&b.manifest, |a| b.chunks.get(a).cloned()) else { return Ok(Vec::new()) };
        match b.purpose {
            BlobPurpose::Message { group_id } => self.on_mls(&group_id, bytes, now_ms),
            BlobPurpose::Join { kp_ref, welcome, tree_key, title } => self.join(kp_ref, &welcome, &tree_key, &bytes, title),
        }
    }

    fn join(&mut self, kp_ref: Vec<u8>, welcome: &[u8], tree_key: &[u8; 32], sealed_tree: &[u8], title: String) -> Result<Vec<ClientEvent>, KhensuError> {
        let Some(kp) = self.key_packages.remove(&kp_ref) else { return Ok(Vec::new()) };
        let tree = open(tree_key, &ZERO_NONCE, sealed_tree, b"").map_err(|_| KhensuError::Crypto { msg: "tree".into() })?;
        let tree = RatchetTreeIn::tls_deserialize_exact(&tree).map_err(mls_err)?;
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(welcome).map_err(mls_err)?.extract() else {
            return Err(KhensuError::Invalid { msg: "not a welcome".into() });
        };
        let g = StagedWelcome::new_from_welcome(&self.provider, &join_config(), w, Some(tree))
            .map_err(mls_err)?
            .into_group(&self.provider)
            .map_err(mls_err)?;
        let gid = g.group_id().as_slice().to_vec();
        let direct = g.members().count() == 2;
        self.groups.insert(gid.clone(), Group { mls: g, signer_seed: kp.signer_seed, title: title.clone(), direct, prev_seed: None });
        Ok(vec![ClientEvent::ConversationJoined { conversation_id: hex::encode(&gid), title, direct }])
    }

    fn on_mls(&mut self, gid: &[u8], bytes: Vec<u8>, now_ms: u64) -> Result<Vec<ClientEvent>, KhensuError> {
        let Ok(msg) = MlsMessageIn::tls_deserialize_exact(&bytes) else { return Ok(Vec::new()) };
        let Ok(pm) = msg.try_into_protocol_message() else { return Ok(Vec::new()) };
        let Core { provider, groups, .. } = self;
        let Some(g) = groups.get_mut(gid) else { return Ok(Vec::new()) };
        if pm.epoch() > g.mls.epoch() {
            self.held.push(Held { group_id: gid.to_vec(), message: bytes, since: secs(now_ms) });
            return Ok(Vec::new());
        }
        let Ok(processed) = g.mls.process_message(provider, pm) else { return Ok(Vec::new()) };
        let sender = KhensuCredential::from_mls(processed.credential()).ok();
        let conversation_id = hex::encode(gid);
        let mut events = Vec::new();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => {
                let content = KhensuContent::decode(&m.into_bytes()).ok().filter(|c| c.content_type == ContentType::Text);
                if let (Some(c), Some(s)) = (content, sender) {
                    events.push(ClientEvent::MessageReceived {
                        conversation_id,
                        message_id: hex::encode(c.message_id),
                        sender_address: display_address(&s.address),
                        sender_device: s.device_index,
                        text: String::from_utf8_lossy(&c.body).into_owned(),
                        sent_at_ms: c.sent_at_ms,
                    });
                }
            }
            ProcessedMessageContent::StagedCommitMessage(c) => {
                let old = mailbox_seed(&g.mls, provider.crypto())?;
                g.mls.merge_staged_commit(provider, *c).map_err(mls_err)?;
                g.prev_seed = Some(old);
                events.push(if g.mls.is_active() {
                    ClientEvent::MembersChanged { conversation_id }
                } else {
                    ClientEvent::RemovedFromConversation { conversation_id }
                });
                let (retry, keep): (Vec<Held>, Vec<Held>) = std::mem::take(&mut self.held).into_iter().partition(|h| h.group_id == gid);
                self.held = keep;
                for h in retry {
                    events.extend(self.on_mls(gid, h.message, now_ms)?);
                }
            }
            _ => {}
        }
        Ok(events)
    }
}
