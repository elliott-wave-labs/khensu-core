// SPDX-License-Identifier: Apache-2.0
//! Final payloads (PROTOCOL.md 8.4), mailbox requests (6.2), store receipts
//! (6.7) and the mailbox reply carried back in SURBs (defined here; the spec
//! leaves it open).

use khensu_crypto::sym::h256;
use khensu_crypto::{Reader, SigKeyPair, SigPublicKey, Signature, write_varint, write_vec};

use crate::surb::{SURB_LEN, Surb};
use crate::{BULK_PAYLOAD, Error, Lane, Result, SMALL_PAYLOAD};

/// Largest `sealed` a small-lane `store` without SURB or access token can carry:
/// kind (1) + body length (2) + op (1) + mailbox_id (32) + sealed length (2)
/// + empty surb (1) + empty access_token (1) = 40 bytes of framing.
pub const SMALL_STORE_MAX_SEALED: usize = SMALL_PAYLOAD - 40;
/// Largest tree chunk that fits both `tree_put` and its `tree_get` reply on the bulk lane.
pub const TREE_CHUNK_MAX: usize = BULK_PAYLOAD - 64;
/// SURBs that fit one bulk-lane `fetch`.
pub const MAX_FETCH_SURBS: usize = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FinalKind {
    Mailbox = 1,
    Sequencer = 2,
    Pir = 3,
    Channel = 4,
    Committee = 5,
    Cover = 6,
}

impl FinalKind {
    fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::Mailbox,
            2 => Self::Sequencer,
            3 => Self::Pir,
            4 => Self::Channel,
            5 => Self::Committee,
            6 => Self::Cover,
            _ => return Err(Error::Decode),
        })
    }
}

fn pad(mut out: Vec<u8>, lane: Lane) -> Result<Vec<u8>> {
    if out.len() > lane.payload_len() {
        return Err(Error::TooLarge);
    }
    out.resize(lane.payload_len(), 0);
    Ok(out)
}

fn zero_tail(r: Reader<'_>) -> Result<()> {
    let mut r = r;
    if r.take(r.remaining())?.iter().any(|&b| b != 0) {
        return Err(Error::Decode);
    }
    Ok(())
}

/// `struct { uint8 kind; opaque body<V>; } FinalPayload;`, zero-padded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalPayload {
    pub kind: FinalKind,
    pub body: Vec<u8>,
}

impl FinalPayload {
    pub fn cover() -> Self {
        Self { kind: FinalKind::Cover, body: Vec::new() }
    }

    pub fn encode(&self, lane: Lane) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(lane.payload_len());
        out.push(self.kind as u8);
        write_vec(&mut out, &self.body);
        pad(out, lane)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Lane::for_payload_len(bytes.len())?;
        let mut r = Reader::new(bytes);
        let kind = FinalKind::from_u8(r.u8()?)?;
        let body = r.vec()?.to_vec();
        zero_tail(r)?;
        Ok(Self { kind, body })
    }
}

/// `item_id = H256(Label("item") || sealed)`.
pub fn item_id(sealed: &[u8]) -> [u8; 32] {
    h256("item", &[sealed])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailboxOp {
    Store { sealed: Vec<u8>, surb: Option<Surb> },
    Fetch { max_items: u32, surbs: Vec<Surb> },
    Ack { item_ids: Vec<[u8; 32]> },
    RegisterWake { wake_capability: Vec<u8> },
    TreePut { chunk: Vec<u8> },
    TreeGet { chunk_hash: [u8; 32], surb: Surb },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxRequest {
    pub mailbox_id: [u8; 32],
    pub op: MailboxOp,
    pub access_token: Vec<u8>,
}

impl MailboxRequest {
    pub fn new(mailbox_id: [u8; 32], op: MailboxOp) -> Self {
        Self { mailbox_id, op, access_token: Vec::new() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let code = match &self.op {
            MailboxOp::Store { .. } => 1,
            MailboxOp::Fetch { .. } => 2,
            MailboxOp::Ack { .. } => 3,
            MailboxOp::RegisterWake { .. } => 4,
            MailboxOp::TreePut { .. } => 5,
            MailboxOp::TreeGet { .. } => 6,
        };
        out.push(code);
        out.extend_from_slice(&self.mailbox_id);
        match &self.op {
            MailboxOp::Store { sealed, surb } => {
                write_vec(&mut out, sealed);
                write_vec(&mut out, &surb.as_ref().map(Surb::encode).unwrap_or_default());
            }
            MailboxOp::Fetch { max_items, surbs } => {
                out.extend_from_slice(&max_items.to_be_bytes());
                write_vec(&mut out, &Surb::encode_list(surbs));
            }
            MailboxOp::Ack { item_ids } => write_vec(&mut out, &item_ids.concat()),
            MailboxOp::RegisterWake { wake_capability } => write_vec(&mut out, wake_capability),
            MailboxOp::TreePut { chunk } => write_vec(&mut out, chunk),
            MailboxOp::TreeGet { chunk_hash, surb } => {
                out.extend_from_slice(chunk_hash);
                write_vec(&mut out, &surb.encode());
            }
        }
        write_vec(&mut out, &self.access_token);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let code = r.u8()?;
        let mailbox_id = r.array()?;
        let op = match code {
            1 => {
                let sealed = r.vec()?.to_vec();
                let surb = match r.vec()? {
                    [] => None,
                    s => Some(Surb::decode(s)?),
                };
                MailboxOp::Store { sealed, surb }
            }
            2 => MailboxOp::Fetch { max_items: r.u32()?, surbs: Surb::decode_list(r.vec()?)? },
            3 => {
                let ids = r.vec()?;
                if ids.len() % 32 != 0 {
                    return Err(Error::Decode);
                }
                MailboxOp::Ack { item_ids: ids.chunks(32).map(|c| c.try_into().expect("32 bytes")).collect() }
            }
            4 => MailboxOp::RegisterWake { wake_capability: r.vec()?.to_vec() },
            5 => MailboxOp::TreePut { chunk: r.vec()?.to_vec() },
            6 => {
                let chunk_hash = r.array()?;
                let s = r.vec()?;
                if s.len() != SURB_LEN {
                    return Err(Error::Decode);
                }
                MailboxOp::TreeGet { chunk_hash, surb: Surb::decode(s)? }
            }
            _ => return Err(Error::Decode),
        };
        let access_token = r.vec()?.to_vec();
        r.finish()?;
        Ok(Self { mailbox_id, op, access_token })
    }

    /// Wraps the request as a mailbox `FinalPayload` for `lane`.
    pub fn to_payload(&self, lane: Lane) -> Result<Vec<u8>> {
        FinalPayload { kind: FinalKind::Mailbox, body: self.encode() }.encode(lane)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreReceipt {
    pub item_id: [u8; 32],
    pub network_epoch: u64,
    pub replica_node_id: [u8; 32],
    pub signature: Vec<u8>,
}

impl StoreReceipt {
    fn tbs(item_id: &[u8; 32], network_epoch: u64, replica_node_id: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(72);
        out.extend_from_slice(item_id);
        out.extend_from_slice(&network_epoch.to_be_bytes());
        out.extend_from_slice(replica_node_id);
        out
    }

    pub fn sign(key: &SigKeyPair, item_id: [u8; 32], network_epoch: u64, replica_node_id: [u8; 32]) -> Result<Self> {
        let sig = key.sign("store receipt", &Self::tbs(&item_id, network_epoch, &replica_node_id))?;
        Ok(Self { item_id, network_epoch, replica_node_id, signature: sig.0 })
    }

    pub fn verify(&self, node_sig_pk: &SigPublicKey) -> Result<()> {
        let tbs = Self::tbs(&self.item_id, self.network_epoch, &self.replica_node_id);
        Ok(node_sig_pk.verify("store receipt", &tbs, &Signature(self.signature.clone()))?)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&Self::tbs(&self.item_id, self.network_epoch, &self.replica_node_id));
        write_vec(out, &self.signature);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self { item_id: r.array()?, network_epoch: r.u64()?, replica_node_id: r.array()?, signature: r.vec()?.to_vec() })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyBody {
    Item { sealed: Vec<u8> },
    Empty,
    Receipt(StoreReceipt),
    TreeChunk { chunk: Vec<u8> },
    NotFound,
}

/// ```text
/// enum { item(1), empty(2), store_receipt(3), tree_chunk(4), not_found(5), (255) } ReplyKind;
/// struct {
///   ReplyKind kind;
///   uint8     flags;            // bit0: more items are waiting
///   select (kind) { case item: opaque sealed<V>; case store_receipt: StoreReceipt;
///                   case tree_chunk: opaque chunk<V>; default: struct {}; };
/// } MailboxReply;               // zero-padded to the SURB's lane payload
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxReply {
    pub body: ReplyBody,
    pub more: bool,
}

impl MailboxReply {
    pub fn encode(&self, lane: Lane) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(lane.payload_len());
        let kind = match &self.body {
            ReplyBody::Item { .. } => 1,
            ReplyBody::Empty => 2,
            ReplyBody::Receipt(_) => 3,
            ReplyBody::TreeChunk { .. } => 4,
            ReplyBody::NotFound => 5,
        };
        out.push(kind);
        out.push(self.more as u8);
        match &self.body {
            ReplyBody::Item { sealed } => write_vec(&mut out, sealed),
            ReplyBody::Receipt(rc) => rc.write(&mut out),
            ReplyBody::TreeChunk { chunk } => write_vec(&mut out, chunk),
            ReplyBody::Empty | ReplyBody::NotFound => {}
        }
        pad(out, lane)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Lane::for_payload_len(bytes.len())?;
        let mut r = Reader::new(bytes);
        let kind = r.u8()?;
        let flags = r.u8()?;
        if flags & !1 != 0 {
            return Err(Error::Decode);
        }
        let body = match kind {
            1 => ReplyBody::Item { sealed: r.vec()?.to_vec() },
            2 => ReplyBody::Empty,
            3 => ReplyBody::Receipt(StoreReceipt::read(&mut r)?),
            4 => ReplyBody::TreeChunk { chunk: r.vec()?.to_vec() },
            5 => ReplyBody::NotFound,
            _ => return Err(Error::Decode),
        };
        zero_tail(r)?;
        Ok(Self { body, more: flags & 1 != 0 })
    }
}

/// Length of `opaque x<V>` for `n` content bytes.
pub fn vec_len(n: usize) -> usize {
    let mut v = Vec::new();
    write_varint(&mut v, n as u64);
    v.len() + n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Hop;
    use crate::packet::tests::nodes;
    use crate::surb;
    use rand::SeedableRng;

    fn surbs(n: usize, lane: Lane) -> Vec<Surb> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(5);
        let ns = nodes(4);
        let route: Vec<Hop> = ns.iter().map(|(_, h)| h.clone()).collect();
        (0..n).map(|_| surb::create(&mut rng, &route, [2; 32], lane).unwrap().0).collect()
    }

    #[test]
    fn small_store_of_a_full_fragment_fills_the_small_payload_exactly() {
        let req = MailboxRequest::new([3; 32], MailboxOp::Store { sealed: vec![7; SMALL_STORE_MAX_SEALED], surb: None });
        let fp = FinalPayload { kind: FinalKind::Mailbox, body: req.encode() };
        let mut unpadded = vec![fp.kind as u8];
        write_vec(&mut unpadded, &fp.body);
        assert_eq!(unpadded.len(), SMALL_PAYLOAD);
        let p = req.to_payload(Lane::Small).unwrap();
        let back = FinalPayload::decode(&p).unwrap();
        assert_eq!(MailboxRequest::decode(&back.body).unwrap(), req);

        let over = MailboxRequest::new([3; 32], MailboxOp::Store { sealed: vec![7; SMALL_STORE_MAX_SEALED + 1], surb: None });
        assert_eq!(over.to_payload(Lane::Small), Err(Error::TooLarge));
    }

    #[test]
    fn fragment_size_matches_khensu_mls() {
        use khensu_mls::fragment::{FRAGMENT_LEN, split};
        assert_eq!(FRAGMENT_LEN, SMALL_STORE_MAX_SEALED);
        let f = split(b"hello").unwrap().remove(0).encode();
        assert_eq!(f.len(), SMALL_STORE_MAX_SEALED);
        let reply = MailboxReply { body: ReplyBody::Item { sealed: f }, more: true };
        assert_eq!(MailboxReply::decode(&reply.encode(Lane::Small).unwrap()).unwrap(), reply);
    }

    #[test]
    fn surbs_need_the_bulk_lane() {
        let one = surbs(1, Lane::Small);
        let store = MailboxRequest::new([0; 32], MailboxOp::Store { sealed: vec![0; 10], surb: Some(one[0].clone()) });
        assert_eq!(store.to_payload(Lane::Small), Err(Error::TooLarge));
        assert!(store.to_payload(Lane::Bulk).is_ok());

        let max = surbs(MAX_FETCH_SURBS, Lane::Small);
        let fetch = MailboxRequest::new([1; 32], MailboxOp::Fetch { max_items: 7, surbs: max.clone() });
        let p = fetch.to_payload(Lane::Bulk).unwrap();
        assert_eq!(MailboxRequest::decode(&FinalPayload::decode(&p).unwrap().body).unwrap(), fetch);
        let mut eight = max;
        eight.push(eight[0].clone());
        let too_many = MailboxRequest::new([1; 32], MailboxOp::Fetch { max_items: 8, surbs: eight });
        assert_eq!(too_many.to_payload(Lane::Bulk), Err(Error::TooLarge));
    }

    #[test]
    fn tree_chunks_fit_bulk_both_ways() {
        let put = MailboxRequest::new([0; 32], MailboxOp::TreePut { chunk: vec![1; TREE_CHUNK_MAX] });
        assert!(put.to_payload(Lane::Bulk).is_ok());
        let get = MailboxRequest::new([0; 32], MailboxOp::TreeGet { chunk_hash: [4; 32], surb: surbs(1, Lane::Bulk).remove(0) });
        assert_eq!(MailboxRequest::decode(&get.encode()).unwrap(), get);
        let reply = MailboxReply { body: ReplyBody::TreeChunk { chunk: vec![1; TREE_CHUNK_MAX] }, more: false };
        assert_eq!(MailboxReply::decode(&reply.encode(Lane::Bulk).unwrap()).unwrap(), reply);
    }

    #[test]
    fn store_receipt_signs_and_does_not_fit_small_replies() {
        let key = SigKeyPair::from_seed([5; 32]);
        let rc = StoreReceipt::sign(&key, item_id(b"x"), 9, [6; 32]).unwrap();
        rc.verify(key.public()).unwrap();
        let reply = MailboxReply { body: ReplyBody::Receipt(rc.clone()), more: false };
        assert_eq!(reply.encode(Lane::Small), Err(Error::TooLarge));
        let back = MailboxReply::decode(&reply.encode(Lane::Bulk).unwrap()).unwrap();
        assert_eq!(back, reply);
        let mut forged = rc;
        forged.network_epoch = 10;
        assert_eq!(forged.verify(key.public()), Err(Error::BadSignature));
    }

    #[test]
    fn garbage_is_rejected() {
        let p = FinalPayload::cover().encode(Lane::Small).unwrap();
        assert_eq!(FinalPayload::decode(&p).unwrap().kind, FinalKind::Cover);
        let mut bad = p;
        bad[SMALL_PAYLOAD - 1] = 1;
        assert_eq!(FinalPayload::decode(&bad), Err(Error::Decode));
        assert!(MailboxReply::decode(&[0xFF; SMALL_PAYLOAD]).is_err());
        assert_eq!(vec_len(2008), 2010);
    }
}
