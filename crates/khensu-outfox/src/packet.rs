// SPDX-License-Identifier: Apache-2.0
//! Header construction and per-hop processing (PROTOCOL.md 8.2).
//!
//! A hop receives `H = kem_ct || routing_ct || B` with `|B| = 6,560`. It
//! decapsulates, opens `routing_ct` with `B` as associated data, and passes on
//! `(B || 0^1640) XOR S`, where `S` is the 8,200-byte AES-256-CTR keystream
//! under its header key; the last 1,640 bytes of `S` are the padding that keeps
//! the header length constant. The sender precomputes that padding (the
//! Sphinx filler) so every hop's associated data is known when it seals.

use khensu_crypto::kem::{self, KemCiphertext, KemKeyPair, KemPublicKey};
use khensu_crypto::sym::{h256, kdf, open, seal};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::lioness::{KEY_LEN, LionessKey};
use crate::routing::{FLAG_FINAL, RoutingInfo};
use crate::{BULK_PACKET, Error, HEADER_LEN, HOP_HEADER_LEN, Lane, MAX_HOPS, Result, SMALL_PACKET};

const REST_LEN: usize = HEADER_LEN - HOP_HEADER_LEN;
const ZERO_NONCE: [u8; 12] = [0; 12];

/// One hop of a route as the sender sees it.
#[derive(Clone, Debug)]
pub struct Hop {
    pub node_id: [u8; 32],
    /// The node's `node_mix_ek` for the packet's network epoch.
    pub mix_ek: KemPublicKey,
    /// How long this hop holds the packet before forwarding it.
    pub delay_ms: u32,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct HopKeys {
    routing: [u8; 32],
    header: [u8; 32],
    pub(crate) payload: LionessKey,
    pub(crate) replay_tag: [u8; 16],
}

impl HopKeys {
    fn derive(ss: &[u8; kem::SHARED_SECRET_LEN]) -> Self {
        Self {
            routing: kdf(ss, &[], "hop routing"),
            header: kdf(ss, &[], "hop header"),
            payload: LionessKey::new(kdf::<KEY_LEN>(ss, &[], "hop payload")),
            replay_tag: kdf(ss, &[], "hop replay"),
        }
    }
}

fn header_stream(key: &[u8; 32]) -> Vec<u8> {
    let mut s = vec![0u8; HEADER_LEN];
    Ctr128BE::<Aes256>::new(key.into(), &[0u8; 16].into()).apply_keystream(&mut s);
    s
}

fn xor(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// The 16-byte payload digest a forward packet's final hop checks.
pub fn payload_digest(payload: &[u8]) -> [u8; 16] {
    h256("payload digest", &[payload])[..16].try_into().expect("16 bytes")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    header: Vec<u8>,
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(header: Vec<u8>, payload: Vec<u8>) -> Result<Self> {
        if header.len() != HEADER_LEN {
            return Err(Error::Length);
        }
        Lane::for_payload_len(payload.len())?;
        Ok(Self { header, payload })
    }

    pub fn header(&self) -> &[u8] {
        &self.header
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn lane(&self) -> Lane {
        Lane::for_payload_len(self.payload.len()).expect("checked at construction")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header.len() + self.payload.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SMALL_PACKET && bytes.len() != BULK_PACKET {
            return Err(Error::Length);
        }
        let (h, p) = bytes.split_at(HEADER_LEN);
        Ok(Self { header: h.to_vec(), payload: p.to_vec() })
    }
}

/// Builds a header for 1 to 5 hops. Randomness is drawn in a fixed order (32
/// bytes of encapsulation randomness per hop, then the unused header tail) so
/// test vectors can replay it.
pub(crate) fn build_header(
    rng: &mut (impl RngCore + CryptoRng),
    hops: &[(&KemPublicKey, RoutingInfo)],
) -> Result<(Vec<u8>, Vec<HopKeys>)> {
    let n = hops.len();
    if n == 0 || n > MAX_HOPS {
        return Err(Error::Hops);
    }
    let mut cts: Vec<KemCiphertext> = Vec::with_capacity(n);
    let mut keys = Vec::with_capacity(n);
    for (ek, _) in hops {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let (ct, mut ss) = ek.encapsulate_derand(m);
        m.zeroize();
        keys.push(HopKeys::derive(&ss));
        ss.zeroize();
        cts.push(ct);
    }
    let streams: Vec<Vec<u8>> = keys.iter().map(|k| header_stream(&k.header)).collect();

    let mut filler = Vec::with_capacity(REST_LEN);
    for s in &streams[..n - 1] {
        filler.extend_from_slice(&[0u8; HOP_HEADER_LEN]);
        let off = HEADER_LEN - filler.len();
        xor(&mut filler, &s[off..]);
    }
    let mut rest = vec![0u8; REST_LEN - filler.len()];
    rng.fill_bytes(&mut rest);
    rest.extend_from_slice(&filler);

    let mut header = Vec::with_capacity(HEADER_LEN);
    for i in (0..n).rev() {
        if i < n - 1 {
            debug_assert_eq!(&header[REST_LEN..], &streams[i][REST_LEN..]);
            rest = header[..REST_LEN].to_vec();
            xor(&mut rest, &streams[i][..REST_LEN]);
        }
        let rt = seal(&keys[i].routing, &ZERO_NONCE, &hops[i].1.encode(), &rest);
        header.clear();
        header.extend_from_slice(&cts[i].0);
        header.extend_from_slice(&rt);
        header.extend_from_slice(&rest);
    }
    Ok((header, keys))
}

/// Builds a forward packet: hop `i` forwards to hop `i + 1`; the last hop is
/// the destination and receives `final_payload` (exactly one lane payload).
pub fn forward(
    rng: &mut (impl RngCore + CryptoRng),
    route: &[Hop],
    final_payload: &[u8],
) -> Result<Packet> {
    let lane = Lane::for_payload_len(final_payload.len())?;
    let n = route.len();
    let infos: Vec<(&KemPublicKey, RoutingInfo)> = route
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            let ri = if i + 1 < n {
                RoutingInfo::relay(route[i + 1].node_id, hop.delay_ms, lane)
            } else {
                let mut ri = RoutingInfo::relay([0; 32], 0, lane);
                ri.flags = FLAG_FINAL;
                ri.reserved[..16].copy_from_slice(&payload_digest(final_payload));
                ri
            };
            (&hop.mix_ek, ri)
        })
        .collect();
    let (header, keys) = build_header(rng, &infos)?;
    let mut payload = final_payload.to_vec();
    for k in keys.iter().rev() {
        k.payload.encrypt(&mut payload)?;
    }
    Packet::new(header, payload)
}

/// Result of one hop's processing. Callers must check `replay_tag` against
/// their replay filter before acting on the packet.
#[derive(Debug)]
pub struct Processed {
    pub routing: RoutingInfo,
    pub replay_tag: [u8; 16],
    /// The packet for the next hop; on a final hop its payload is the
    /// destination's plaintext (forward) or the reply to deliver (SURB).
    pub packet: Packet,
}

/// Removes one layer with this node's mix key for the packet's epoch.
/// `Error::Decrypt` means the key is wrong (another epoch) or the header was
/// modified.
pub fn process(packet: &Packet, key: &KemKeyPair) -> Result<Processed> {
    let ct = KemCiphertext::from_slice(&packet.header[..kem::CIPHERTEXT_LEN])?;
    let mut ss = key.decapsulate(&ct);
    let keys = HopKeys::derive(&ss);
    ss.zeroize();
    let rest = &packet.header[HOP_HEADER_LEN..];
    let ri = open(&keys.routing, &ZERO_NONCE, &packet.header[kem::CIPHERTEXT_LEN..HOP_HEADER_LEN], rest)
        .map_err(|_| Error::Decrypt)?;
    let routing = RoutingInfo::decode(&ri)?;
    if routing.lane != packet.lane() {
        return Err(Error::Lane);
    }
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(rest);
    header.resize(HEADER_LEN, 0);
    xor(&mut header, &header_stream(&keys.header));
    let mut payload = packet.payload.clone();
    keys.payload.decrypt(&mut payload)?;
    if routing.is_final() && !routing.is_reply() && routing.tag16() != payload_digest(&payload) {
        return Err(Error::Integrity);
    }
    Ok(Processed { routing, replay_tag: keys.replay_tag, packet: Packet { header, payload } })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{BULK_PAYLOAD, SMALL_PAYLOAD};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub(crate) fn nodes(n: usize) -> Vec<(KemKeyPair, Hop)> {
        (0..n)
            .map(|i| {
                let kp = KemKeyPair::from_seed([i as u8 + 1; 64]);
                let hop = Hop { node_id: [i as u8 + 0x10; 32], mix_ek: kp.public().clone(), delay_ms: 100 * i as u32 };
                (kp, hop)
            })
            .collect()
    }

    fn walk(nodes: &[(KemKeyPair, Hop)], mut p: Packet) -> (Vec<Processed>, Packet) {
        let mut seen = Vec::new();
        for (i, (kp, _)) in nodes.iter().enumerate() {
            let out = process(&p, kp).unwrap();
            assert_eq!(out.packet.header().len(), HEADER_LEN);
            if i + 1 < nodes.len() {
                assert!(!out.routing.is_final());
                assert_eq!(out.routing.next_node_id, nodes[i + 1].1.node_id);
                assert_eq!(out.routing.delay_ms, nodes[i].1.delay_ms);
            } else {
                assert!(out.routing.is_final());
            }
            p = out.packet.clone();
            seen.push(out);
        }
        (seen, p)
    }

    #[test]
    fn five_hops_small_and_bulk() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let ns = nodes(5);
        let route: Vec<Hop> = ns.iter().map(|(_, h)| h.clone()).collect();
        for len in [SMALL_PAYLOAD, BULK_PAYLOAD] {
            let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let p = forward(&mut rng, &route, &msg).unwrap();
            assert_eq!(p.to_bytes().len(), crate::HEADER_LEN + len);
            let (seen, last) = walk(&ns, p.clone());
            assert_eq!(last.payload(), &msg[..]);
            let tags: std::collections::HashSet<_> = seen.iter().map(|s| s.replay_tag).collect();
            assert_eq!(tags.len(), 5);
            // Headers are re-randomised at every hop.
            for w in seen.windows(2) {
                assert_ne!(w[0].packet.header()[..64], w[1].packet.header()[..64]);
            }
        }
    }

    #[test]
    fn shorter_routes() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        for n in 1..=5 {
            let ns = nodes(n);
            let route: Vec<Hop> = ns.iter().map(|(_, h)| h.clone()).collect();
            let msg = vec![0xAB; SMALL_PAYLOAD];
            let (_, last) = walk(&ns, forward(&mut rng, &route, &msg).unwrap());
            assert_eq!(last.payload(), &msg[..]);
        }
        assert_eq!(forward(&mut rng, &[], &[0; SMALL_PAYLOAD]).unwrap_err(), Error::Hops);
    }

    #[test]
    fn wrong_key_and_tampering_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let ns = nodes(5);
        let route: Vec<Hop> = ns.iter().map(|(_, h)| h.clone()).collect();
        let p = forward(&mut rng, &route, &[1; SMALL_PAYLOAD]).unwrap();
        assert_eq!(process(&p, &ns[1].0).unwrap_err(), Error::Decrypt);

        // A flipped bit anywhere in a later hop's slot fails at hop 0, because
        // hop 0's routing AEAD covers the rest of the header.
        let mut bytes = p.to_bytes();
        bytes[HOP_HEADER_LEN * 3 + 5] ^= 1;
        assert_eq!(process(&Packet::from_bytes(&bytes).unwrap(), &ns[0].0).unwrap_err(), Error::Decrypt);

        // A flipped payload bit is caught by the final hop's digest.
        let mut bytes = p.to_bytes();
        bytes[HEADER_LEN + 100] ^= 1;
        let mut q = Packet::from_bytes(&bytes).unwrap();
        for (i, (kp, _)) in ns.iter().enumerate() {
            match process(&q, kp) {
                Ok(o) => q = o.packet,
                Err(e) => {
                    assert_eq!((i, e), (4, Error::Integrity));
                    return;
                }
            }
        }
        panic!("tampered payload accepted");
    }

    #[test]
    fn lane_mismatch_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        let ns = nodes(2);
        let route: Vec<Hop> = ns.iter().map(|(_, h)| h.clone()).collect();
        let p = forward(&mut rng, &route, &[0; SMALL_PAYLOAD]).unwrap();
        let swapped = Packet::new(p.header().to_vec(), vec![0; BULK_PAYLOAD]).unwrap();
        assert_eq!(process(&swapped, &ns[0].0).unwrap_err(), Error::Lane);
    }
}
