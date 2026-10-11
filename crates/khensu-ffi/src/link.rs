// SPDX-License-Identifier: Apache-2.0
//! The inner handshake and sealed frames for apps that do QUIC themselves
//! (Network.framework). Every message on the stream is `uint32 length || bytes`;
//! values returned for sending already carry the prefix, values passed in don't.

use std::sync::{Arc, Mutex};

use khensu_crypto::{KemPublicKey, SigPublicKey};
use khensu_net::inner::{self, EXPORTER_LABEL, EXPORTER_LEN};
use khensu_net::{ClientHandshake, Frame, Session};
use khensu_outfox::Lane;

use crate::KhensuError;

fn prefixed(bytes: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// TLS exporter label (RFC 8446 7.5) for the channel binding; export 64 bytes, empty context.
#[uniffi::export]
pub fn link_exporter_label() -> Vec<u8> {
    EXPORTER_LABEL.to_vec()
}

/// Length of the node's `InnerAccept`; it arrives as `uint32 length || accept`.
#[uniffi::export]
pub fn link_accept_length() -> u32 {
    inner::ACCEPT_LEN as u32
}

/// Validates a sealed-frame length prefix and returns the length to read.
#[uniffi::export]
pub fn link_frame_length(prefix: Vec<u8>) -> Result<u32, KhensuError> {
    let p: [u8; 4] = prefix.try_into().map_err(|_| KhensuError::Invalid { msg: "prefix is 4 bytes".into() })?;
    Ok(inner::frame_len(p)? as u32)
}

#[derive(uniffi::Object)]
pub struct LinkHandshake {
    state: Mutex<Option<ClientHandshake>>,
    node_sig: SigPublicKey,
    hello: Vec<u8>,
}

#[uniffi::export]
impl LinkHandshake {
    /// Starts the handshake with an entry node's directory keys and the outer
    /// session's exporter (`link_exporter_label()`, 64 bytes).
    #[uniffi::constructor]
    pub fn new(node_kem_public_key: Vec<u8>, node_sig_public_key: Vec<u8>, tls_exporter: Vec<u8>, network_epoch: u64) -> Result<Arc<Self>, KhensuError> {
        let exporter: [u8; EXPORTER_LEN] =
            tls_exporter.try_into().map_err(|_| KhensuError::Invalid { msg: "exporter is 64 bytes".into() })?;
        let (hs, hello) = ClientHandshake::start(&KemPublicKey::from_slice(&node_kem_public_key)?, &exporter, network_epoch)?;
        Ok(Arc::new(Self { state: Mutex::new(Some(hs)), node_sig: SigPublicKey(node_sig_public_key), hello: prefixed(hello) }))
    }

    /// `InnerHello`, length-prefixed: the first bytes on the stream.
    pub fn hello(&self) -> Vec<u8> {
        self.hello.clone()
    }

    /// Verifies the node's `InnerAccept` (without prefix). Single use.
    pub fn finish(&self, accept: Vec<u8>) -> Result<Arc<LinkSession>, KhensuError> {
        let hs = lock(&self.state).take().ok_or(KhensuError::State { msg: "handshake already finished".into() })?;
        Ok(Arc::new(LinkSession { session: Mutex::new(hs.finish(&accept, &self.node_sig)?) }))
    }
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum LinkFrame {
    /// A SURB reply for `KhensuClient::process_incoming`.
    Deliver { payload_key_ref: Vec<u8>, payload: Vec<u8> },
    Packet { bytes: Vec<u8> },
    Subscribe { delivery_id: Vec<u8> },
    Padding,
}

#[derive(uniffi::Object)]
pub struct LinkSession {
    session: Mutex<Session>,
}

impl LinkSession {
    fn seal(&self, f: &Frame) -> Result<Vec<u8>, KhensuError> {
        Ok(lock(&self.session).seal_frame(f)?)
    }
}

#[uniffi::export]
impl LinkSession {
    /// A mix packet from `KhensuClient::tick`, sealed and length-prefixed.
    pub fn seal_packet(&self, packet: Vec<u8>) -> Result<Vec<u8>, KhensuError> {
        if packet.len() != khensu_outfox::SMALL_PACKET && packet.len() != khensu_outfox::BULK_PACKET {
            return Err(KhensuError::Invalid { msg: "not a mix packet".into() });
        }
        self.seal(&Frame::Packet(packet))
    }

    /// Asks the entry node to deliver SURB replies for `delivery_id` on this link.
    pub fn seal_subscribe(&self, delivery_id: Vec<u8>) -> Result<Vec<u8>, KhensuError> {
        let delivery_id = delivery_id.try_into().map_err(|_| KhensuError::Invalid { msg: "delivery id is 32 bytes".into() })?;
        self.seal(&Frame::Subscribe { delivery_id })
    }

    pub fn seal_padding(&self, bulk: bool) -> Result<Vec<u8>, KhensuError> {
        self.seal(&Frame::Padding(if bulk { Lane::Bulk } else { Lane::Small }))
    }

    /// Opens one sealed frame (the bytes after its length prefix), in stream order.
    pub fn open_frame(&self, sealed: Vec<u8>) -> Result<LinkFrame, KhensuError> {
        Ok(match lock(&self.session).open_frame(&sealed)? {
            Frame::Deliver { payload_key_ref, payload } => LinkFrame::Deliver { payload_key_ref: payload_key_ref.to_vec(), payload },
            Frame::Packet(bytes) => LinkFrame::Packet { bytes },
            Frame::Subscribe { delivery_id } => LinkFrame::Subscribe { delivery_id: delivery_id.to_vec() },
            Frame::Padding(_) => LinkFrame::Padding,
        })
    }
}
