// SPDX-License-Identifier: Apache-2.0
//! Single-use reply blocks (PROTOCOL.md 8.7).
//!
//! The replier sends its reply as the payload of a packet with the SURB's
//! header; every hop Lioness-decrypts it as usual. The SURB's final hop (the
//! recipient's entry node) delivers `(payload_key_ref, payload)` to the
//! recipient, who re-encrypts with each hop key, last hop first, to recover
//! the reply.

use khensu_crypto::{KemPublicKey, Reader};
use rand::{CryptoRng, RngCore};

use crate::lioness::{KEY_LEN, LionessKey};
use crate::packet::{Hop, Packet, build_header};
use crate::routing::{FLAG_FINAL, FLAG_REPLY, RoutingInfo};
use crate::{Error, HEADER_LEN, Lane, MAX_HOPS, Result};

pub const SURB_LEN: usize = 32 + HEADER_LEN + 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surb {
    pub first_hop: [u8; 32],
    pub header: Vec<u8>,
    pub payload_key_ref: [u8; 16],
}

impl Surb {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SURB_LEN);
        out.extend_from_slice(&self.first_hop);
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.payload_key_ref);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let s = Self { first_hop: r.array()?, header: r.take(HEADER_LEN)?.to_vec(), payload_key_ref: r.array()? };
        r.finish()?;
        Ok(s)
    }

    /// `surbs<V>` holds SURBs back to back.
    pub fn encode_list(surbs: &[Surb]) -> Vec<u8> {
        surbs.iter().flat_map(Surb::encode).collect()
    }

    pub fn decode_list(bytes: &[u8]) -> Result<Vec<Surb>> {
        if bytes.len() % SURB_LEN != 0 {
            return Err(Error::Length);
        }
        bytes.chunks(SURB_LEN).map(Surb::decode).collect()
    }

    /// The packet carrying `reply` (one lane payload) and the node to send it to.
    pub fn reply(&self, reply: Vec<u8>) -> Result<([u8; 32], Packet)> {
        Ok((self.first_hop, Packet::new(self.header.clone(), reply)?))
    }
}

/// What the SURB's creator keeps to open the reply.
#[derive(Clone)]
pub struct SurbKeys {
    pub payload_key_ref: [u8; 16],
    pub lane: Lane,
    keys: Vec<LionessKey>,
}

impl SurbKeys {
    pub fn open(&self, mut payload: Vec<u8>) -> Result<Vec<u8>> {
        if payload.len() != self.lane.payload_len() {
            return Err(Error::Lane);
        }
        for k in self.keys.iter().rev() {
            k.encrypt(&mut payload)?;
        }
        Ok(payload)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + self.keys.len() * KEY_LEN);
        out.extend_from_slice(&self.payload_key_ref);
        out.push(self.lane as u8);
        out.push(self.keys.len() as u8);
        for k in &self.keys {
            out.extend_from_slice(k.as_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let payload_key_ref = r.array()?;
        let lane = Lane::from_u8(r.u8()?)?;
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_HOPS {
            return Err(Error::Decode);
        }
        let keys = (0..n).map(|_| r.array::<KEY_LEN>().map(LionessKey::new)).collect::<core::result::Result<_, _>>()?;
        r.finish()?;
        Ok(Self { payload_key_ref, lane, keys })
    }
}

/// Builds a SURB over `route` (mixes, then the recipient's entry node, which
/// delivers to `deliver_to`).
pub fn create(
    rng: &mut (impl RngCore + CryptoRng),
    route: &[Hop],
    deliver_to: [u8; 32],
    lane: Lane,
) -> Result<(Surb, SurbKeys)> {
    let n = route.len();
    let mut payload_key_ref = [0u8; 16];
    rng.fill_bytes(&mut payload_key_ref);
    let infos: Vec<(&KemPublicKey, RoutingInfo)> = route
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            let ri = if i + 1 < n {
                RoutingInfo::relay(route[i + 1].node_id, hop.delay_ms, lane)
            } else {
                let mut ri = RoutingInfo::relay(deliver_to, 0, lane);
                ri.flags = FLAG_FINAL | FLAG_REPLY;
                ri.reserved[..16].copy_from_slice(&payload_key_ref);
                ri
            };
            (&hop.mix_ek, ri)
        })
        .collect();
    let (header, hop_keys) = build_header(rng, &infos)?;
    let keys = hop_keys.iter().map(|k| k.payload.clone()).collect();
    let first_hop = route.first().ok_or(Error::Hops)?.node_id;
    Ok((Surb { first_hop, header, payload_key_ref }, SurbKeys { payload_key_ref, lane, keys }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::process;
    use crate::packet::tests::nodes;
    use rand::SeedableRng;

    #[test]
    fn reply_roundtrip() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
        let ns = nodes(4);
        let route: Vec<Hop> = ns.iter().map(|(_, h)| h.clone()).collect();
        for lane in [Lane::Small, Lane::Bulk] {
            let (surb, keys) = create(&mut rng, &route, [0xDD; 32], lane).unwrap();
            let surb = Surb::decode(&surb.encode()).unwrap();
            let keys = SurbKeys::decode(&keys.encode()).unwrap();
            assert_eq!(surb.encode().len(), SURB_LEN);

            let reply: Vec<u8> = (0..lane.payload_len()).map(|i| (i % 7) as u8).collect();
            let (first, mut p) = surb.reply(reply.clone()).unwrap();
            assert_eq!(first, route[0].node_id);
            let mut last = None;
            for (kp, _) in &ns {
                let out = process(&p, kp).unwrap();
                p = out.packet.clone();
                last = Some(out);
            }
            let last = last.unwrap();
            assert!(last.routing.is_final() && last.routing.is_reply());
            assert_eq!(last.routing.next_node_id, [0xDD; 32]);
            assert_eq!(last.routing.tag16(), keys.payload_key_ref);
            assert_ne!(last.packet.payload(), &reply[..]);
            assert_eq!(keys.open(last.packet.into_payload()).unwrap(), reply);
        }
    }

    #[test]
    fn list_codec() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(4);
        let ns = nodes(2);
        let route: Vec<Hop> = ns.iter().map(|(_, h)| h.clone()).collect();
        let surbs: Vec<Surb> = (0..3).map(|_| create(&mut rng, &route, [1; 32], Lane::Small).unwrap().0).collect();
        assert_eq!(Surb::decode_list(&Surb::encode_list(&surbs)).unwrap(), surbs);
        assert_eq!(Surb::decode_list(&[0; 5]), Err(Error::Length));
    }
}
