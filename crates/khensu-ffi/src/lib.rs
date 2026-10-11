// SPDX-License-Identifier: Apache-2.0
//! khensu.nu client core, exported to Swift with UniFFI. The Swift surface is
//! documented in `ffi/SWIFT-API.md`.
//!
//! The app owns networking and time: it connects to the entry node over QUIC,
//! runs the inner handshake with [`LinkHandshake`], calls
//! [`KhensuClient::tick`] every `tick_ms` (±100 ms jitter) and sends the
//! returned packets, and passes every `Deliver` frame to
//! [`KhensuClient::process_incoming`].

uniffi::setup_scaffolding!();

mod core;
mod identity;
mod link;
mod state;
mod wire;

use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use khensu_net::Directory;

pub use link::{LinkFrame, LinkHandshake, LinkSession, link_exporter_label, link_frame_length};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KhensuError {
    #[error("invalid input: {msg}")]
    Invalid { msg: String },
    #[error("crypto: {msg}")]
    Crypto { msg: String },
    #[error("mls: {msg}")]
    Mls { msg: String },
    #[error("network: {msg}")]
    Network { msg: String },
    #[error("not found: {msg}")]
    NotFound { msg: String },
    #[error("state: {msg}")]
    State { msg: String },
}

impl From<khensu_crypto::Error> for KhensuError {
    fn from(e: khensu_crypto::Error) -> Self {
        KhensuError::Crypto { msg: e.to_string() }
    }
}

impl From<khensu_mls::Error> for KhensuError {
    fn from(e: khensu_mls::Error) -> Self {
        KhensuError::Mls { msg: e.to_string() }
    }
}

impl From<khensu_outfox::Error> for KhensuError {
    fn from(e: khensu_outfox::Error) -> Self {
        KhensuError::Network { msg: e.to_string() }
    }
}

impl From<khensu_net::Error> for KhensuError {
    fn from(e: khensu_net::Error) -> Self {
        KhensuError::Network { msg: e.to_string() }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct IdentityInfo {
    /// `khensu1...`
    pub address: String,
    pub address_hex: String,
    pub display_name: String,
    pub device_index: u16,
    /// ML-DSA-87 identity public key (2,592 bytes).
    pub identity_public_key: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct MemberInfo {
    pub address: String,
    pub device_index: u16,
    pub leaf_index: u32,
    pub is_self: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ConversationInfo {
    /// Hex MLS group ID.
    pub conversation_id: String,
    pub title: String,
    pub direct: bool,
    pub epoch: u64,
    pub active: bool,
    pub members: Vec<MemberInfo>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct GatewayInfo {
    pub name: String,
    pub node_id: String,
    /// `host:port` (QUIC, ALPN `h3`).
    pub endpoint: String,
    pub kem_public_key: Vec<u8>,
    pub sig_public_key: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct OutgoingPacket {
    /// Hex node ID of the entry node; always the configured gateway.
    pub first_hop: String,
    pub endpoint: String,
    /// One mix packet (10,248 or 73,736 bytes) for `LinkSession::seal_packet`.
    pub bytes: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct EncryptedMessage {
    pub message_id: String,
    pub packets: Vec<OutgoingPacket>,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    MessageReceived {
        conversation_id: String,
        message_id: String,
        sender_address: String,
        sender_device: u16,
        text: String,
        sent_at_ms: u64,
    },
    ConversationJoined {
        conversation_id: String,
        title: String,
        direct: bool,
    },
    MembersChanged {
        conversation_id: String,
    },
    RemovedFromConversation {
        conversation_id: String,
    },
}

fn gid(conversation_id: &str) -> Result<Vec<u8>, KhensuError> {
    hex::decode(conversation_id).map_err(|_| KhensuError::Invalid { msg: "conversation id".into() })
}

fn card(contact_card: &str) -> Result<Vec<u8>, KhensuError> {
    B64.decode(contact_card.trim()).map_err(|_| KhensuError::Invalid { msg: "contact card is not base64".into() })
}

/// One device of one account. Thread-safe; every call takes an internal lock.
#[derive(uniffi::Object)]
pub struct KhensuClient {
    core: Mutex<core::Core>,
}

impl KhensuClient {
    fn core(&self) -> MutexGuard<'_, core::Core> {
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl KhensuClient {
    /// New identity (ML-DSA-87 identity key, inception entry, address) and
    /// device (credential `device_index` 0).
    #[uniffi::constructor]
    pub fn new(display_name: String, now_ms: u64) -> Result<Arc<Self>, KhensuError> {
        Ok(Arc::new(Self { core: Mutex::new(core::Core::new(display_name, now_ms)?) }))
    }

    /// Restores a client from `export_state`. Load the directory again afterwards.
    #[uniffi::constructor]
    pub fn import_state(blob: Vec<u8>, key: Vec<u8>) -> Result<Arc<Self>, KhensuError> {
        Ok(Arc::new(Self { core: Mutex::new(state::import(&blob, &key)?) }))
    }

    /// Everything (keys, MLS state, outbox, partial messages), sealed with a
    /// 32-byte key under AES-256-GCM.
    pub fn export_state(&self, key: Vec<u8>) -> Result<Vec<u8>, KhensuError> {
        state::export(&self.core(), &key)
    }

    pub fn identity(&self) -> IdentityInfo {
        let c = self.core();
        IdentityInfo {
            address: identity::display_address(&c.identity.address),
            address_hex: hex::encode(c.identity.address),
            display_name: c.display_name.clone(),
            device_index: c.device_index,
            identity_public_key: c.identity.key.public().0.clone(),
        }
    }

    /// Loads `devnet.json` (or a node list in the same format). `gateway`
    /// picks the entry node by name; `None` takes the first gateway.
    pub fn load_directory(&self, json: String, gateway: Option<String>) -> Result<(), KhensuError> {
        let d = Directory::from_json(&json)?;
        let mut c = self.core();
        c.directory = Some(Arc::new(d));
        c.gateway = gateway;
        let dir = c.dir()?;
        c.gateway_entry(&dir)?;
        Ok(())
    }

    pub fn gateway(&self) -> Result<GatewayInfo, KhensuError> {
        let c = self.core();
        let dir = c.dir()?;
        let g = c.gateway_entry(&dir)?;
        Ok(GatewayInfo {
            name: g.name.clone(),
            node_id: g.node_id.clone(),
            endpoint: g.endpoint.clone(),
            kem_public_key: g.kem_public().0.to_vec(),
            sig_public_key: g.sig_public().0,
        })
    }

    pub fn network_epoch(&self, now_ms: u64) -> u64 {
        self.core().epoch(now_ms)
    }

    /// Tick length and burst size from the directory.
    pub fn tick_interval_ms(&self) -> Result<u64, KhensuError> {
        Ok(self.core().dir()?.params.tick_ms)
    }

    /// 32 bytes the entry node uses to deliver this client's SURB replies.
    pub fn delivery_id(&self) -> Vec<u8> {
        self.core().delivery_id.to_vec()
    }

    /// A one-time contact card (KeyPackage, intro key, display name, signed),
    /// base64. Share it out of band; whoever imports it can start a chat.
    pub fn create_contact_card(&self, now_ms: u64) -> Result<String, KhensuError> {
        Ok(B64.encode(self.core().create_contact_card(now_ms)?))
    }

    pub fn create_group(&self, title: String) -> Result<String, KhensuError> {
        Ok(hex::encode(self.core().create_group(title, false)?))
    }

    /// 1:1 conversation with the owner of `contact_card`.
    pub fn create_direct_conversation(&self, contact_card: String, now_ms: u64) -> Result<String, KhensuError> {
        let bytes = card(&contact_card)?;
        let peer = wire::ContactCard::decode(&bytes)?.display_name;
        let mut c = self.core();
        let id = c.create_group(peer, true)?;
        c.add_member(&id, &bytes, now_ms)?;
        Ok(hex::encode(id))
    }

    pub fn add_member(&self, conversation_id: String, contact_card: String, now_ms: u64) -> Result<(), KhensuError> {
        self.core().add_member(&gid(&conversation_id)?, &card(&contact_card)?, now_ms)
    }

    pub fn conversations(&self) -> Vec<ConversationInfo> {
        self.core().conversations()
    }

    /// Queues a text message in the outbox; it leaves in the next ticks in
    /// place of cover packets. Returns the hex message ID.
    pub fn send_text(&self, conversation_id: String, text: String, now_ms: u64) -> Result<String, KhensuError> {
        Ok(hex::encode(self.core().send_text(&gid(&conversation_id)?, &text, now_ms)?))
    }

    /// Encrypts a message and returns its mix packets now, each on its own
    /// route from the directory, bypassing the outbox and the tick schedule.
    /// For tests and tools; apps should use `send_text`.
    pub fn encrypt_message(&self, conversation_id: String, text: String, now_ms: u64) -> Result<EncryptedMessage, KhensuError> {
        let mut c = self.core();
        let (small, bulk) = (c.small_out.len(), c.bulk_out.len());
        let id = c.send_text(&gid(&conversation_id)?, &text, now_ms)?;
        let dir = c.dir()?;
        let gw = c.gateway_entry(&dir)?;
        let epoch = c.epoch(now_ms);
        let new_small: Vec<_> = c.small_out.drain(small..).collect();
        let new_bulk: Vec<_> = c.bulk_out.drain(bulk..).collect();
        let mut packets = Vec::new();
        for (o, lane) in new_bulk.into_iter().map(|o| (o, khensu_outfox::Lane::Bulk)).chain(new_small.into_iter().map(|o| (o, khensu_outfox::Lane::Small))) {
            packets.push(c.build(&dir, &gw, o, lane, epoch)?);
        }
        Ok(EncryptedMessage { message_id: hex::encode(id), packets })
    }

    /// One burst for the entry node: a bulk packet (fetch or queued bulk
    /// request) then the small packets, cover where nothing is queued.
    pub fn tick(&self, now_ms: u64) -> Result<Vec<OutgoingPacket>, KhensuError> {
        self.core().tick(now_ms)
    }

    /// A `Deliver` frame from the entry node. Unknown references (cover) yield
    /// no events.
    pub fn process_incoming(&self, payload_key_ref: Vec<u8>, payload: Vec<u8>, now_ms: u64) -> Result<Vec<ClientEvent>, KhensuError> {
        self.core().process_incoming(&payload_key_ref, payload, now_ms)
    }

    /// Requests waiting in the outbox.
    pub fn pending_outgoing(&self) -> u32 {
        self.core().pending()
    }
}
