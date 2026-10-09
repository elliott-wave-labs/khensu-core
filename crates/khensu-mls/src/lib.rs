// SPDX-License-Identifier: Apache-2.0
//! The khensu.nu MLS profile (PROTOCOL.md section 4) on OpenMLS.

pub mod content;
pub mod credential;
pub mod fragment;
pub mod mailbox;
pub mod provider;
pub mod rotation;
pub mod tree;

use openmls::prelude::{
    Capabilities, CredentialType, ExtensionType, MlsGroupCreateConfig, MlsGroupJoinConfig,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ProposalType, ProtocolVersion, SenderRatchetConfiguration,
};

pub use credential::KhensuCredential;
pub use provider::{KhensuProvider, MlDsaSigner, SUITE};

/// Largest group, in leaves (devices).
pub const MAX_GROUP_LEAVES: u32 = 1000;
/// Skipped message keys kept per sender.
pub const MAX_SKIPPED_GENERATIONS: u32 = 1000;
/// Earlier epochs whose application messages are still accepted.
pub const MAX_PAST_EPOCHS: usize = 3;
/// Skipped keys and past-epoch secrets are purged by the app after this.
pub const SKIPPED_KEY_TTL_SECS: u64 = 7 * 24 * 3600;
/// MLS content padding granularity; the fragment bucket hides the rest.
pub const PADDING: usize = 256;

pub const EXT_DELAYED_REVEAL: u16 = 0xF0B1;
pub const EXT_TREE_MANIFEST: u16 = 0xF0B2;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("decode error")]
    Decode,
    #[error("message too large for the small lane")]
    TooLarge,
    #[error("random number generator failed")]
    Rng,
    #[error("credential is not a khensu credential")]
    WrongCredentialType,
    #[error("credential does not match the log entry")]
    CredentialMismatch,
    #[error("device key revoked")]
    Revoked,
    #[error("device key binding expired")]
    Expired,
    #[error("log entry not found or unverified")]
    NotInLog,
    #[error("MLS error")]
    Mls,
}

impl From<khensu_crypto::Error> for Error {
    fn from(e: khensu_crypto::Error) -> Self {
        match e {
            khensu_crypto::Error::Rng => Error::Rng,
            _ => Error::Decode,
        }
    }
}

/// Leaf capabilities every khensu device advertises.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[SUITE]),
        Some(&[ExtensionType::Unknown(EXT_DELAYED_REVEAL), ExtensionType::Unknown(EXT_TREE_MANIFEST)]),
        Some(&[] as &[ProposalType]),
        Some(&[KhensuCredential::credential_type()]),
    )
}

fn ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(MAX_SKIPPED_GENERATIONS, MAX_SKIPPED_GENERATIONS)
}

/// Group creation settings: ciphertext-only wire format, no tree in Welcome.
pub fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(PADDING)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(ratchet())
        .use_ratchet_tree_extension(false)
        .capabilities(capabilities())
        .build()
}

pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(PADDING)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(ratchet())
        .use_ratchet_tree_extension(false)
        .build()
}

pub fn is_khensu_credential(t: CredentialType) -> bool {
    t == KhensuCredential::credential_type()
}
