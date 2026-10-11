// SPDX-License-Identifier: Apache-2.0
//! Inner handshake (design/camouflage.md 4.1-4.4).
//!
//! ```text
//! struct { uint64 network_epoch; opaque kem_ciphertext[1568]; opaque client_nonce[32]; opaque tag[32]; } InnerHello;
//! struct { opaque node_nonce[32]; opaque signature<V>; } InnerAccept;
//! tag       = HMAC-SHA-512(KDF(ss, salt = outer_exporter, Label("inner hello tag")), fields above)[..32]
//! signature = Sign(node_sig_sk, "inner accept", InnerHello || node_nonce || outer_exporter)
//! c2n, n2c  = KDF(ss, salt = outer_exporter, Label("inner c2n") / Label("inner n2c"))
//! ```
//!
//! Sealed frames use AES-256-GCM with nonce `0^4 || uint64 counter`, one
//! counter per direction, over an ordered stream.

use hmac::{Hmac, Mac};
use khensu_crypto::kem::{self, KemCiphertext, KemKeyPair, KemPublicKey};
use khensu_crypto::sym::{kdf, open, seal};
use khensu_crypto::{Reader, SigKeyPair, SigPublicKey, Signature, random, write_vec};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::frame::{BULK_FRAME, Frame};
use crate::{Error, Result};

/// RFC 8446 7.5 exporter label for the channel binding.
pub const EXPORTER_LABEL: &[u8] = b"khensu camouflage v1";
pub const EXPORTER_LEN: usize = 64;
pub const HELLO_LEN: usize = 8 + kem::CIPHERTEXT_LEN + 32 + 32;
pub const ACCEPT_LEN: usize = 32 + 2 + khensu_crypto::sig::SIGNATURE_LEN;
/// Largest sealed frame on the wire, after the 4-byte length prefix.
pub const MAX_SEALED_FRAME: usize = BULK_FRAME + 16;

fn hello_tag(ss: &[u8; 32], exporter: &[u8; EXPORTER_LEN], fields: &[u8]) -> Hmac<Sha512> {
    let mut key: [u8; 32] = kdf(ss, exporter, "inner hello tag");
    let mut m = Hmac::<Sha512>::new_from_slice(&key).expect("any key length");
    key.zeroize();
    m.update(fields);
    m
}

fn accept_tbs(hello: &[u8], node_nonce: &[u8; 32], exporter: &[u8; EXPORTER_LEN]) -> Vec<u8> {
    [hello, node_nonce, exporter].concat()
}

fn session(ss: &[u8; 32], exporter: &[u8; EXPORTER_LEN], client: bool) -> Session {
    let c2n: [u8; 32] = kdf(ss, exporter, "inner c2n");
    let n2c: [u8; 32] = kdf(ss, exporter, "inner n2c");
    let (send, recv) = if client { (c2n, n2c) } else { (n2c, c2n) };
    Session { send: Direction { key: send, counter: 0 }, recv: Direction { key: recv, counter: 0 } }
}

/// Client side, between sending `InnerHello` and receiving `InnerAccept`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientHandshake {
    ss: [u8; 32],
    exporter: [u8; EXPORTER_LEN],
    hello: Vec<u8>,
}

impl ClientHandshake {
    /// Returns the handshake state and the `InnerHello` bytes to send.
    pub fn start(node_kem_pk: &KemPublicKey, exporter: &[u8; EXPORTER_LEN], network_epoch: u64) -> Result<(Self, Vec<u8>)> {
        let (ct, ss) = node_kem_pk.encapsulate()?;
        let nonce: [u8; 32] = random()?;
        let mut hello = Vec::with_capacity(HELLO_LEN);
        hello.extend_from_slice(&network_epoch.to_be_bytes());
        hello.extend_from_slice(&ct.0);
        hello.extend_from_slice(&nonce);
        let tag = hello_tag(&ss, exporter, &hello).finalize().into_bytes();
        hello.extend_from_slice(&tag[..32]);
        Ok((Self { ss, exporter: *exporter, hello: hello.clone() }, hello))
    }

    /// Checks the node's signature against its directory key.
    pub fn finish(self, accept: &[u8], node_sig_pk: &SigPublicKey) -> Result<Session> {
        let mut r = Reader::new(accept);
        let node_nonce: [u8; 32] = r.array().map_err(|_| Error::Handshake)?;
        let sig = r.vec().map_err(|_| Error::Handshake)?.to_vec();
        r.finish().map_err(|_| Error::Handshake)?;
        node_sig_pk
            .verify("inner accept", &accept_tbs(&self.hello, &node_nonce, &self.exporter), &Signature(sig))
            .map_err(|_| Error::Handshake)?;
        Ok(session(&self.ss, &self.exporter, true))
    }
}

/// Node side: checks `InnerHello` and returns the session and `InnerAccept`.
/// Any error must be answered like an unknown path on the cover website.
pub fn accept(
    node_kem: &KemKeyPair,
    node_sig: &SigKeyPair,
    exporter: &[u8; EXPORTER_LEN],
    hello: &[u8],
    current_epoch: u64,
) -> Result<(Session, Vec<u8>)> {
    if hello.len() != HELLO_LEN {
        return Err(Error::Handshake);
    }
    let mut r = Reader::new(hello);
    let epoch = r.u64()?;
    let ct = KemCiphertext::from_slice(r.take(kem::CIPHERTEXT_LEN)?)?;
    if epoch != current_epoch && epoch + 1 != current_epoch && epoch != current_epoch + 1 {
        return Err(Error::Handshake);
    }
    let mut ss = node_kem.decapsulate(&ct);
    let (fields, tag) = hello.split_at(HELLO_LEN - 32);
    let ok = hello_tag(&ss, exporter, fields).verify_truncated_left(tag).is_ok();
    if !ok {
        ss.zeroize();
        return Err(Error::Handshake);
    }
    let node_nonce: [u8; 32] = random()?;
    let sig = node_sig.sign("inner accept", &accept_tbs(hello, &node_nonce, exporter))?;
    let mut out = Vec::with_capacity(ACCEPT_LEN);
    out.extend_from_slice(&node_nonce);
    write_vec(&mut out, &sig.0);
    let s = session(&ss, exporter, false);
    ss.zeroize();
    Ok((s, out))
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Direction {
    key: [u8; 32],
    counter: u64,
}

impl Direction {
    fn nonce(&mut self) -> Result<[u8; 12]> {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.checked_add(1).ok_or(Error::Decrypt)?;
        Ok(n)
    }
}

/// An established inner session.
pub struct Session {
    send: Direction,
    recv: Direction,
}

impl Session {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = self.send.nonce()?;
        Ok(seal(&self.send.key, &n, plaintext, &[]))
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let n = self.recv.nonce()?;
        open(&self.recv.key, &n, ciphertext, &[]).map_err(|_| Error::Decrypt)
    }

    /// `uint32 length || sealed frame`, ready for the stream.
    pub fn seal_frame(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        let ct = self.seal(&frame.encode())?;
        let mut out = Vec::with_capacity(4 + ct.len());
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Opens one sealed frame (without its length prefix).
    pub fn open_frame(&mut self, sealed: &[u8]) -> Result<Frame> {
        Frame::decode(&self.open(sealed)?)
    }
}

/// Parses a frame length prefix, rejecting sizes no frame can have.
pub fn frame_len(prefix: [u8; 4]) -> Result<usize> {
    let n = u32::from_be_bytes(prefix) as usize;
    if n == crate::frame::SMALL_FRAME + 16 || n == MAX_SEALED_FRAME { Ok(n) } else { Err(Error::Length) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use khensu_outfox::Lane;

    fn node() -> (KemKeyPair, SigKeyPair) {
        (KemKeyPair::from_seed([1; 64]), SigKeyPair::from_seed([2; 32]))
    }

    #[test]
    fn handshake_and_frames() {
        let (kem, sig) = node();
        let exporter = [9u8; 64];
        let (hs, hello) = ClientHandshake::start(kem.public(), &exporter, 100).unwrap();
        assert_eq!(hello.len(), HELLO_LEN);
        let (mut ns, accept_bytes) = accept(&kem, &sig, &exporter, &hello, 100).unwrap();
        assert_eq!(accept_bytes.len(), ACCEPT_LEN);
        let mut cs = hs.finish(&accept_bytes, sig.public()).unwrap();

        let f = Frame::Subscribe { delivery_id: [5; 32] };
        let wire = cs.seal_frame(&f).unwrap();
        let len = frame_len(wire[..4].try_into().unwrap()).unwrap();
        assert_eq!(ns.open_frame(&wire[4..4 + len]).unwrap(), f);
        let pad = ns.seal_frame(&Frame::Padding(Lane::Small)).unwrap();
        assert_eq!(pad.len(), wire.len(), "padding and real frames have one size");
        assert_eq!(cs.open_frame(&pad[4..]).unwrap(), Frame::Padding(Lane::Small));
        // Out-of-order or replayed frames fail.
        let _skipped = cs.seal_frame(&f).unwrap();
        let next = cs.seal_frame(&f).unwrap();
        assert!(ns.open_frame(&next[4..]).is_err());
    }

    #[test]
    fn rejects_wrong_exporter_epoch_and_signer() {
        let (kem, sig) = node();
        let (_, hello) = ClientHandshake::start(kem.public(), &[1; 64], 100).unwrap();
        assert!(accept(&kem, &sig, &[2; 64], &hello, 100).is_err(), "replayed into another TLS session");
        assert!(accept(&kem, &sig, &[1; 64], &hello, 102).is_err(), "stale epoch");
        let other = KemKeyPair::from_seed([3; 64]);
        assert!(accept(&other, &sig, &[1; 64], &hello, 100).is_err(), "wrong node key");

        let (hs, hello) = ClientHandshake::start(kem.public(), &[1; 64], 100).unwrap();
        let (_, acc) = accept(&kem, &sig, &[1; 64], &hello, 100).unwrap();
        let impostor = SigKeyPair::from_seed([4; 32]);
        assert_eq!(hs.finish(&acc, impostor.public()).err(), Some(Error::Handshake));
    }
}
