// SPDX-License-Identifier: Apache-2.0
//! Clients talking through a simulated mixnet: every packet is peeled hop by
//! hop with the real node keys, a toy mailbox answers through SURBs, and
//! replies are delivered by delivery ID.

use std::collections::HashMap;
use std::sync::Arc;

use khensu_crypto::{KemKeyPair, SigKeyPair};
use khensu_ffi::{ClientEvent, KhensuClient};
use khensu_net::directory::{MixKey, b64};
use khensu_net::{Directory, NodeEntry, Params, Role, node_id};
use khensu_outfox::delivery::{FinalKind, FinalPayload, MailboxOp, MailboxReply, MailboxRequest, ReplyBody, item_id};
use khensu_outfox::epoch::{DEVNET_GENESIS_TIME, EPOCH_SECS};
use khensu_outfox::{Lane, Packet, process};

const EPOCH: u64 = 100;

type Inbox = Vec<([u8; 16], Vec<u8>)>;

struct Net {
    keys: HashMap<[u8; 32], KemKeyPair>,
    items: HashMap<[u8; 32], Vec<Vec<u8>>>,
    chunks: HashMap<[u8; 32], Vec<u8>>,
    deliveries: HashMap<[u8; 32], Inbox>,
}

fn directory() -> (Directory, HashMap<[u8; 32], KemKeyPair>) {
    let specs = [("gw", Role::Gateway, None), ("m1", Role::Mix, Some(1)), ("m2", Role::Mix, Some(2)), ("m3", Role::Mix, Some(3)), ("mb", Role::Mailbox, None)];
    let mut nodes = Vec::new();
    let mut keys = HashMap::new();
    for (i, (name, role, layer)) in specs.into_iter().enumerate() {
        let sig = SigKeyPair::from_seed([i as u8 + 1; 32]);
        let kem = KemKeyPair::from_seed([i as u8 + 1; 64]);
        let mix = KemKeyPair::from_seed([i as u8 + 0x40; 64]);
        let id = node_id(&sig.public().0);
        nodes.push(NodeEntry {
            name: name.into(),
            node_id: hex::encode(id),
            roles: vec![role],
            layer,
            endpoint: format!("127.0.0.1:{}", 47100 + i),
            sig_pk: b64(&sig.public().0),
            kem_pk: b64(&kem.public().0),
            mix_keys: vec![MixKey { epoch: EPOCH, ek: b64(&mix.public().0) }],
        });
        keys.insert(id, mix);
    }
    let d = Directory { version: 1, network: "test".into(), genesis_time: DEVNET_GENESIS_TIME, epoch_secs: EPOCH_SECS, params: Params::default(), nodes };
    (d, keys)
}

impl Net {
    fn send(&mut self, mut at: [u8; 32], bytes: &[u8]) {
        let mut p = Packet::from_bytes(bytes).unwrap();
        loop {
            let out = process(&p, &self.keys[&at]).expect("every hop opens");
            if !out.routing.is_final() {
                at = out.routing.next_node_id;
                p = out.packet;
                continue;
            }
            if out.routing.is_reply() {
                self.deliveries.entry(out.routing.next_node_id).or_default().push((out.routing.tag16(), out.packet.into_payload()));
            } else {
                self.mailbox(out.packet.payload());
            }
            return;
        }
    }

    fn mailbox(&mut self, payload: &[u8]) {
        let fp = FinalPayload::decode(payload).unwrap();
        if fp.kind == FinalKind::Cover {
            return;
        }
        let req = MailboxRequest::decode(&fp.body).unwrap();
        match req.op {
            MailboxOp::Store { sealed, .. } => {
                let q = self.items.entry(req.mailbox_id).or_default();
                if !q.iter().any(|s| item_id(s) == item_id(&sealed)) {
                    q.push(sealed);
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
}

impl World {
    fn new(n: usize) -> (Self, String) {
        let (d, keys) = directory();
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
        let net = Net { keys, items: HashMap::new(), chunks: HashMap::new(), deliveries: HashMap::new() };
        (Self { net, now, events: vec![Vec::new(); n], clients }, json)
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
    assert_eq!(m.packets.len(), 3, "one bucket-3 message to one recipient");
    for p in &m.packets {
        let mut first = [0u8; 32];
        hex::decode_to_slice(&p.first_hop, &mut first).unwrap();
        w.net.send(first, &p.bytes);
    }
    w.until(10, |e| got_text(&e[1], "direct"));
}
