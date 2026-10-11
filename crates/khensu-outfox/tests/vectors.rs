// SPDX-License-Identifier: Apache-2.0
//! Test vectors in `vectors/outfox-v1.json`. Every random byte the builder
//! draws is listed in the vector, in draw order, so other implementations can
//! replay them. Regenerate with `KHENSU_WRITE_VECTORS=1 cargo test -p khensu-outfox --test vectors`.

use khensu_crypto::KemKeyPair;
use khensu_crypto::sym::h;
use khensu_outfox::delivery::{FinalPayload, MailboxOp, MailboxRequest, MailboxReply, ReplyBody};
use khensu_outfox::lioness::LionessKey;
use khensu_outfox::{Hop, Lane, Packet, process, surb};
use rand::{CryptoRng, RngCore};
use serde_json::{Value, json};

/// Replays a fixed byte tape; panics if the builder asks for more.
struct Tape {
    bytes: Vec<u8>,
    pos: usize,
}

impl RngCore for Tape {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_be_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_be_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.bytes[self.pos..self.pos + dest.len()]);
        self.pos += dest.len();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for Tape {}

fn stream(seed: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut i = 0u32;
    while out.len() < len {
        out.extend_from_slice(&h("vector tape", &[seed.as_bytes(), &i.to_be_bytes()]));
        i += 1;
    }
    out.truncate(len);
    out
}

struct Node {
    seed: [u8; 64],
    kp: KemKeyPair,
    hop: Hop,
}

fn nodes(n: usize, delays: &[u32]) -> Vec<Node> {
    (0..n)
        .map(|i| {
            let seed: [u8; 64] = stream(&format!("node {i} kem"), 64).try_into().unwrap();
            let kp = KemKeyPair::from_seed(seed);
            let node_id: [u8; 32] = stream(&format!("node {i} id"), 32).try_into().unwrap();
            let hop = Hop { node_id, mix_ek: kp.public().clone(), delay_ms: delays[i] };
            Node { seed, kp, hop }
        })
        .collect()
}

fn generate() -> Value {
    let lkey: [u8; 192] = stream("lioness key", 192).try_into().unwrap();
    let lplain = stream("lioness plaintext", 100);
    let mut lct = lplain.clone();
    LionessKey::new(lkey).encrypt(&mut lct).unwrap();

    // Forward: entry, three mixes, mailbox.
    let fwd = nodes(5, &[0, 180, 342, 97, 0]);
    let route: Vec<Hop> = fwd.iter().map(|n| n.hop.clone()).collect();
    let req = MailboxRequest::new([0x42; 32], MailboxOp::Store { sealed: stream("sealed", 2008), surb: None });
    let payload = req.to_payload(Lane::Small).unwrap();
    let tape = stream("forward tape", 5 * 32);
    let packet = khensu_outfox::forward(&mut Tape { bytes: tape.clone(), pos: 0 }, &route, &payload).unwrap();
    let mut hops = Vec::new();
    let mut p = packet.clone();
    for n in &fwd {
        let out = process(&p, &n.kp).unwrap();
        hops.push(json!({
            "replay_tag": hex::encode(out.replay_tag),
            "routing": hex::encode(out.routing.encode()),
            "output_sha512": hex::encode(h("vector digest", &[&out.packet.to_bytes()])),
        }));
        p = out.packet;
    }
    assert_eq!(p.payload(), &payload[..]);

    // SURB: three mixes and the recipient's entry node.
    let back = nodes(4, &[211, 45, 380, 0]);
    let sroute: Vec<Hop> = back.iter().map(|n| n.hop.clone()).collect();
    let deliver_to = [0xD1; 32];
    let stape = stream("surb tape", 16 + 4 * 32 + 1640);
    let (s, keys) = surb::create(&mut Tape { bytes: stape.clone(), pos: 0 }, &sroute, deliver_to, Lane::Small).unwrap();
    let reply = MailboxReply { body: ReplyBody::Item { sealed: stream("reply item", 2008) }, more: true }
        .encode(Lane::Small)
        .unwrap();
    let (_, mut rp) = s.reply(reply.clone()).unwrap();
    for n in &back {
        rp = process(&rp, &n.kp).unwrap().packet;
    }
    let delivered = rp.into_payload();
    assert_eq!(keys.open(delivered.clone()).unwrap(), reply);

    let node_json = |ns: &[Node]| -> Vec<Value> {
        ns.iter()
            .map(|n| json!({
                "kem_seed": hex::encode(n.seed),
                "node_id": hex::encode(n.hop.node_id),
                "delay_ms": n.hop.delay_ms,
            }))
            .collect()
    };
    json!({
        "description": "khensu-outfox v1 vectors (PROTOCOL.md 8). ML-KEM-1024 keys from 64-byte (d, z) seeds; `tape` is every random byte the builder draws, in order: 32 bytes of encapsulation randomness per hop, then the unused header tail; SURBs draw payload_key_ref (16 bytes) first. `*_sha512` values are H(Label(\"vector digest\") || bytes).",
        "lioness": { "key": hex::encode(lkey), "plaintext": hex::encode(&lplain), "ciphertext": hex::encode(&lct) },
        "forward_small": {
            "nodes": node_json(&fwd),
            "final_payload": hex::encode(&payload),
            "tape": hex::encode(&tape),
            "packet": hex::encode(packet.to_bytes()),
            "hops": hops,
        },
        "surb_small": {
            "nodes": node_json(&back),
            "deliver_to": hex::encode(deliver_to),
            "tape": hex::encode(&stape),
            "surb": hex::encode(s.encode()),
            "reply": hex::encode(&reply),
            "delivered_sha512": hex::encode(h("vector digest", &[&delivered])),
        },
    })
}

fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/outfox-v1.json")
}

#[test]
fn vectors_match() {
    let fresh = generate();
    if std::env::var_os("KHENSU_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path().parent().unwrap()).unwrap();
        std::fs::write(path(), serde_json::to_string_pretty(&fresh).unwrap() + "\n").unwrap();
        return;
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(path()).expect("vectors file")).unwrap();
    assert_eq!(stored, fresh, "vectors changed; regenerate only for a deliberate format change");

    // The stored packet decodes and a mailbox-side final hop yields the request.
    let bytes = hex::decode(stored["forward_small"]["packet"].as_str().unwrap()).unwrap();
    let mut p = Packet::from_bytes(&bytes).unwrap();
    for n in nodes(5, &[0, 180, 342, 97, 0]) {
        p = process(&p, &n.kp).unwrap().packet;
    }
    let fp = FinalPayload::decode(p.payload()).unwrap();
    assert!(matches!(MailboxRequest::decode(&fp.body).unwrap().op, MailboxOp::Store { .. }));
}
