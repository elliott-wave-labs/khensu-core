// SPDX-License-Identifier: Apache-2.0
//! The khensu.nu link layer without I/O, shared by the apps (through
//! khensu-ffi) and tatenan nodes.
//!
//! - [`inner`]: the inner handshake of `design/camouflage.md` section 4
//!   (ML-KEM-1024 to the node's directory key, ML-DSA-87 node proof, bound to
//!   the outer TLS exporter) and the AES-256-GCM session it yields.
//! - [`frame`]: fixed-size link frames, so padding, packets and deliveries look
//!   alike once sealed.
//! - [`directory`]: the node list (`devnet.json` for devnets) and route choice.

pub mod directory;
pub mod frame;
pub mod inner;

pub use directory::{Directory, NodeEntry, Params, Role};
pub use frame::Frame;
pub use inner::{ClientHandshake, Session};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid length")]
    Length,
    #[error("decode error")]
    Decode,
    #[error("handshake failed")]
    Handshake,
    #[error("frame failed to decrypt")]
    Decrypt,
    #[error("directory: {0}")]
    Directory(String),
    #[error("no route: {0}")]
    NoRoute(&'static str),
    #[error(transparent)]
    Outfox(#[from] khensu_outfox::Error),
}

impl From<khensu_crypto::Error> for Error {
    fn from(e: khensu_crypto::Error) -> Self {
        match e {
            khensu_crypto::Error::Length => Error::Length,
            _ => Error::Handshake,
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// `node_id = H256(Label("node") || node_sig_pk)` (PROTOCOL.md 12.1).
pub fn node_id(node_sig_pk: &[u8]) -> [u8; 32] {
    khensu_crypto::sym::h256("node", &[node_sig_pk])
}
