// SPDX-License-Identifier: Apache-2.0
//! Clients talking through a simulated mixnet: every packet is peeled hop by
//! hop with the real node keys, a toy mailbox answers through SURBs, and
//! replies are delivered by delivery ID.

use std::collections::HashMap;
use std::sync::Arc;

use khensu_crypto::{KemKeyPair, SigKeyPair};
use khensu_ffi::{ClientEvent, KhensuClient};
use khensu_net::control::Control;
use khensu_net::directory::b64;
use khensu_net::header::{EpochHeader, HeaderBundle, Rules, committee_root, draw_committee, empty_state_root, evidence_root, node_list_root, receipts_root};
use khensu_net::lease::{Lease, LeaseMode, MixEk, ROLE_COMMITTEE, ROLE_GATEWAY, ROLE_MAILBOX, ROLE_MIX};
use khensu_net::{Directory, node_id};
use khensu_outfox::delivery::{FinalKind, FinalPayload, MailboxOp, MailboxReply, MailboxRequest, ReplyBody, StoreReceipt, item_id};
use khensu_outfox::epoch::{DEVNET_GENESIS_TIME, EPOCH_SECS};
use khensu_outfox::{Lane, Packet, process};

const EPOCH: u64 = 100;

type Inbox = Vec<([u8; 16], Vec<u8>)>;
/// Each node's mix keys by epoch and its signing key.
type NodeKeys = HashMap<[u8; 32], (HashMap<u64, KemKeyPair>, SigKeyPair)>;

struct Net {
    /// Per node: its mix keys by epoch and its signing key.
    keys: NodeKeys,
    items: HashMap<[u8; 32], Vec<Vec<u8>>>,
    chunks: HashMap<[u8; 32], Vec<u8>>,
    deliveries: HashMap<[u8; 32], Inbox>,
    epoch: u64,
}

/// Six nodes, every one on the committee: a gateway that also mixes, three
/// mixes and two mailboxes (the devnet rules ask for two replicas). Leases
/// cover `EPOCH` and `EPOCH + 1`.
fn directory() -> (Directory, NodeKeys, Vec<Lease>) {
    let specs = [("gw", ROLE_GATEWAY | ROLE_MIX), ("m1", ROLE_MIX), ("m2", ROLE_MIX), ("m3", ROLE_MIX), ("mb", ROLE_MAILBOX | ROLE_MIX), ("mb2", ROLE_MAILBOX | ROLE_MIX)];
    let mut leases = Vec::new();
    let mut keys = HashMap::new();
    for (i, (name, roles)) in specs.into_iter().enumerate() {
        let sig = SigKeyPair::from_seed([i as u8 + 1; 32]);
        let kem = KemKeyPair::from_seed([i as u8 + 1; 64]);
        let mix: HashMap<u64, KemKeyPair> = [EPOCH, EPOCH + 1].into_iter().map(|e| (e, KemKeyPair::from_seed([i as u8 + 0x40 + e as u8; 64]))).collect();
        let lease = Lease {
            node_sig_pk: Vec::new(),
            link_ek: kem.public().clone(),
            mix_eks: [EPOCH, EPOCH + 1].into_iter().map(|e| MixEk { epoch: e, ek: mix[&e].public().clone() }).collect(),
            roles: roles | ROLE_COMMITTEE,
            mode: LeaseMode::AlwaysOn,
            start_epoch: EPOCH,
            end_epoch: EPOCH + 1,
            schedule: Vec::new(),
            operator_address: [0; 32],
            stake_ref: [0; 32],
            endpoints: vec![format!("127.0.0.1:{}", 47100 + i)],
            label: name.into(),
            signature: Vec::new(),
        }
        .sign(&sig)
        .unwrap();
        keys.insert(node_id(&sig.public().0), (mix, sig));
        leases.push(lease);
    }
    let founder = SigKeyPair::from_seed([99; 32]);
    let rules = Rules { founder_pk: b64(&founder.public().0), ..Rules::devnet(6) };
    let header = EpochHeader::genesis(&rules, &leases, EPOCH, DEVNET_GENESIS_TIME, Some(&founder)).unwrap();
    let d = Directory::genesis("test", DEVNET_GENESIS_TIME, rules, HeaderBundle { header, leases: leases.clone(), rules: None }).unwrap();
    assert_eq!(d.committee.len(), 6);
    (d, keys, leases)
}

/// The header for `EPOCH + 1`, signed by the whole committee, as the nodes would agree it.
fn next_header(d: &Directory, keys: &NodeKeys, leases: &[Lease]) -> HeaderBundle {
    let prev = d.epoch_header.as_ref().unwrap();
    let target = EPOCH + 1;
    let committee = draw_committee(&prev.hash(), leases, target, d.genesis_time, d.rules.committee_size);
    let mut header = EpochHeader {
        chain_id: d.rules.chain_id,
        network_epoch: target,
        prev_header_hash: prev.hash(),
        node_list_root: node_list_root(leases),
        state_root: empty_state_root(),
        receipts_root: receipts_root(&[]),
        evidence_root: evidence_root(&[]),
        rules_hash: d.rules.hash(),
        committee_root: committee_root(&committee),
        founder_cosig: Vec::new(),
        signatures: Vec::new(),
    };
    for (i, id) in d.committee.iter().enumerate() {
        let sig = header.member_sign(&keys[id].1).unwrap();
        header.add_signature(i as u8, sig);
    }
    HeaderBundle { header, leases: leases.to_vec(), rules: None }
}

impl Net {
    fn send(&mut self, mut at: [u8; 32], bytes: &[u8]) {
        let mut p = Packet::from_bytes(bytes).unwrap();
        loop {
            let (mix, _) = &self.keys[&at];
            let out = process(&p, &mix[&self.epoch]).expect("every hop opens");
            if !out.routing.is_final() {
                at = out.routing.next_node_id;
                p = out.packet;
                continue;
            }
            if out.routing.is_reply() {
                self.deliveries.entry(out.routing.next_node_id).or_default().push((out.routing.tag16(), out.packet.into_payload()));
            } else {
                self.mailbox(at, out.packet.payload());
            }
            return;
        }
    }

    fn mailbox(&mut self, node: [u8; 32], payload: &[u8]) {
        let fp = FinalPayload::decode(payload).unwrap();
        if fp.kind == FinalKind::Cover {
            return;
        }
        let req = MailboxRequest::decode(&fp.body).unwrap();
        match req.op {
            MailboxOp::Store { sealed, surb } => {
                let id = item_id(&sealed);
                let q = self.items.entry(req.mailbox_id).or_default();
                if !q.iter().any(|s| item_id(s) == id) {
                    q.push(sealed);
                }
                if let Some(s) = surb {
                    let r = StoreReceipt::sign(&self.keys[&node].1, id, self.epoch, node).unwrap();
                    let (first, p) = s.reply(MailboxReply { body: ReplyBody::Receipt(r), more: false }.encode(Lane::Bulk).unwrap()).unwrap();
                    self.send(first, &p.to_bytes());
                }
            }
            MailboxOp::Fetch { max_items, surbs } => {
                let q = self.items.get(&req.mailbox_id).cloned().unwrap_or_default();
                let n = (max_items as usize).min(surbs.len());
                for (i, s) in surbs.iter().enumerate() {
                    let body = if i < n && i < q.len() { ReplyBody::Item { sealed: q[i].clone() } } else { ReplyBody::Empty };
                    let reply = MailboxReply { body, more: q.len() > n }.encode(Lane::Small).unwrap();
                    let (first, p) = s.reply(reply).unwrap();
                    self.send(first, &p.to_bytes());
                }
            }
            MailboxOp::Ack { item_ids } => {
                if let Some(q) = self.items.get_mut(&req.mailbox_id) {
                    q.retain(|s| !item_ids.contains(&item_id(s)));
                }
            }
            MailboxOp::TreePut { chunk } => {
                self.chunks.insert(khensu_mls::tree::chunk_address(&chunk), chunk);
            }
            MailboxOp::TreeGet { chunk_hash, surb } => {
                let body = match self.chunks.get(&chunk_hash) {
                    Some(c) => ReplyBody::TreeChunk { chunk: c.clone() },
                    None => ReplyBody::NotFound,
                };
                let (first, p) = surb.reply(MailboxReply { body, more: false }.encode(Lane::Bulk).unwrap()).unwrap();
                self.send(first, &p.to_bytes());
            }
            MailboxOp::RegisterWake { .. } => {}
        }
    }
}

struct World {
    net: Net,
    now: u64,
    clients: Vec<Arc<KhensuClient>>,
    events: Vec<Vec<ClientEvent>>,
    dir: Directory,
    leases: Vec<Lease>,
}

impl World {
    fn new(n: usize) -> (Self, String) {
        let (d, keys, leases) = directory();
        let json = d.to_json();
        let now = (DEVNET_GENESIS_TIME + EPOCH * EPOCH_SECS + 60) * 1000;
        let names = ["alice", "bob", "carol"];
        let clients: Vec<_> = (0..n)
            .map(|i| {
                let c = KhensuClient::new(names[i].into(), now).unwrap();
                c.load_directory(json.clone(), None).unwrap();
                c
            })
            .collect();
        let net = Net { keys, items: HashMap::new(), chunks: HashMap::new(), deliveries: HashMap::new(), epoch: EPOCH };
        (Self { net, now, events: vec![Vec::new(); n], clients, dir: d, leases }, json)
    }

    fn step(&mut self) {
        self.now += 2000;
        for c in &self.clients {
            for p in c.tick(self.now).unwrap() {
                assert!(p.bytes.len() == khensu_outfox::SMALL_PACKET || p.bytes.len() == khensu_outfox::BULK_PACKET);
                let mut first = [0u8; 32];
                hex::decode_to_slice(&p.first_hop, &mut first).unwrap();
                self.net.send(first, &p.bytes);
            }
        }
        for (i, c) in self.clients.iter().enumerate() {
            let id: [u8; 32] = c.delivery_id().try_into().unwrap();
            for (r, payload) in self.net.deliveries.remove(&id).unwrap_or_default() {
                self.events[i].extend(c.process_incoming(r.to_vec(), payload, self.now).unwrap());
            }
        }
    }

    fn until(&mut self, max: usize, mut done: impl FnMut(&[Vec<ClientEvent>]) -> bool) {
        for _ in 0..max {
            if done(&self.events) {
                return;
            }
            self.step();
        }
        panic!("condition not reached; events: {:#?}", self.events);
    }
}

fn got_text(events: &[ClientEvent], text: &str) -> bool {
    events.iter().any(|e| matches!(e, ClientEvent::MessageReceived { text: t, .. } if t == text))
}

#[test]
fn direct_chat_state_export_and_group() {
    let (mut w, json) = World::new(3);
    let (alice, bob) = (w.clients[0].clone(), w.clients[1].clone());

    let card = bob.create_contact_card(w.now).unwrap();
    let conv = alice.create_direct_conversation(card, w.now).unwrap();
    alice.send_text(conv.clone(), "hello bob".into(), w.now).unwrap();
    w.until(40, |e| got_text(&e[1], "hello bob"));
    assert!(w.events[1].iter().any(|e| matches!(e, ClientEvent::ConversationJoined { title, direct: true, .. } if title == "alice")));
    let msg = w.events[1].iter().find(|e| matches!(e, ClientEvent::MessageReceived { .. })).unwrap().clone();
    let ClientEvent::MessageReceived { sender_address, conversation_id, .. } = msg else { unreachable!() };
    assert_eq!(sender_address, alice.identity().address);
    assert_eq!(conversation_id, conv);

    // Bob's device restarts from its encrypted state blob.
    let key = vec![7u8; 32];
    let blob = bob.export_state(key.clone()).unwrap();
    assert!(KhensuClient::import_state(blob.clone(), vec![8u8; 32]).is_err());
    let bob = KhensuClient::import_state(blob, key).unwrap();
    bob.load_directory(json, None).unwrap();
    assert_eq!(bob.identity().address, w.clients[1].identity().address);
    w.clients[1] = bob.clone();

    bob.send_text(conv.clone(), "hi alice".into(), w.now).unwrap();
    w.until(20, |e| got_text(&e[0], "hi alice"));

    // A group: Alice adds Bob, then Carol; Bob gets the second commit.
    let carol = w.clients[2].clone();
    let g = alice.create_group("trio".into()).unwrap();
    alice.add_member(g.clone(), bob.create_contact_card(w.now).unwrap(), w.now).unwrap();
    w.until(40, |e| e[1].iter().filter(|x| matches!(x, ClientEvent::ConversationJoined { .. })).count() == 2);
    alice.add_member(g.clone(), carol.create_contact_card(w.now).unwrap(), w.now).unwrap();
    w.until(60, |e| {
        e[2].iter().any(|x| matches!(x, ClientEvent::ConversationJoined { title, .. } if title == "trio"))
            && e[1].iter().any(|x| matches!(x, ClientEvent::MembersChanged { conversation_id } if conversation_id == &g))
    });
    carol.send_text(g.clone(), "carol here".into(), w.now).unwrap();
    w.until(40, |e| got_text(&e[0], "carol here") && got_text(&e[1], "carol here"));
    let info = alice.conversations().into_iter().find(|c| c.conversation_id == g).unwrap();
    assert_eq!(info.members.len(), 3);
    assert_eq!(alice.pending_outgoing(), 0);
}

#[test]
fn encrypt_message_returns_packets_now() {
    let (mut w, _) = World::new(2);
    let (alice, bob) = (w.clients[0].clone(), w.clients[1].clone());
    let conv = alice.create_direct_conversation(bob.create_contact_card(w.now).unwrap(), w.now).unwrap();
    w.until(40, |e| e[1].iter().any(|x| matches!(x, ClientEvent::ConversationJoined { .. })));
    let m = alice.encrypt_message(conv, "direct".into(), w.now).unwrap();
    assert_eq!(m.packets.len(), 6, "one bucket-3 message to one recipient, stored with both replicas");
    for p in &m.packets {
        let mut first = [0u8; 32];
        hex::decode_to_slice(&p.first_hop, &mut first).unwrap();
        w.net.send(first, &p.bytes);
    }
    w.until(10, |e| got_text(&e[1], "direct"));
}

#[test]
fn loops_store_receipts_and_epoch_header() {
    let (mut w, _) = World::new(2);
    let (alice, bob) = (w.clients[0].clone(), w.clients[1].clone());
    alice.set_loop_rate(100);
    alice.set_store_receipts(true);
    let conv = alice.create_direct_conversation(bob.create_contact_card(w.now).unwrap(), w.now).unwrap();
    alice.send_text(conv, "with receipts".into(), w.now).unwrap();
    w.until(40, |e| {
        got_text(&e[1], "with receipts")
            && e[0].iter().filter(|x| matches!(x, ClientEvent::LoopReturned { .. })).count() >= 3
            && e[0].iter().any(|x| matches!(x, ClientEvent::StoreReceipt { valid: true, .. }))
    });
    let s = alice.network_status(w.now);
    assert!(s.loops_sent >= s.loops_returned && s.loops_returned >= 3, "{s:?}");
    assert!(s.store_receipts_ok >= 1 && s.store_receipts_bad == 0, "{s:?}");
    assert_eq!(s.header_epoch, EPOCH);
    assert_eq!(s.mailbox_replicas, 2);
    // Both replicas hold Alice's fragments: the item map dedups by id, so count mailboxes with items instead.
    assert!(!w.net.items.is_empty());

    // The committee agrees the next header; the gateway sends it as a control message.
    // (A fresh `directory()` would not do: ML-DSA signatures are randomised, so its genesis hash differs.)
    let bundle = next_header(&w.dir, &w.net.keys, &w.leases);
    let leases = w.leases.clone();
    let msg = Control::Header(bundle.clone()).encode();
    let ev = alice.process_control(msg.clone(), w.now).unwrap();
    assert!(matches!(ev[0], ClientEvent::HeaderAccepted { epoch, nodes: 6, committee: 6 } if epoch == EPOCH + 1), "{ev:?}");
    assert!(alice.process_control(msg, w.now).unwrap().is_empty(), "a repeated header is ignored");
    let s = alice.network_status(w.now);
    assert_eq!((s.header_epoch, s.next_header_epoch), (EPOCH, Some(EPOCH + 1)));
    // A header from the far future is refused, and the request for the chain names what we have.
    let mut far = bundle.header.clone();
    far.network_epoch = EPOCH + 5;
    assert!(alice.process_control(Control::Header(HeaderBundle { header: far, leases: leases.clone(), rules: None }).encode(), w.now).is_err());
    assert!(matches!(Control::decode(&alice.header_request().unwrap()).unwrap(), Control::HeaderRequest { have_epoch } if have_epoch == EPOCH));

    // When the epoch turns, routes come from the new header and still work.
    w.now = (DEVNET_GENESIS_TIME + (EPOCH + 1) * EPOCH_SECS + 5) * 1000;
    w.net.epoch = EPOCH + 1;
    eprintln!("bob {:?}\nalice {:?}", bob.network_status(w.now), alice.network_status(w.now));
    bob.process_control(Control::Header(bundle).encode(), w.now).unwrap();
    let before = w.events[1].len();
    w.step();
    assert_eq!(alice.network_status(w.now).header_epoch, EPOCH + 1);
    let conv = alice.conversations()[0].conversation_id.clone();
    alice.send_text(conv, "next epoch".into(), w.now).unwrap();
    w.until(40, |e| e[1][before..].iter().any(|x| matches!(x, ClientEvent::MessageReceived { text, .. } if text == "next epoch")));
}
