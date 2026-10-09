//! `KhensuCredential` (PROTOCOL.md 3.4): a pointer into the transparency log.

use khensu_crypto::{Reader, write_vec};
use openmls::prelude::{Credential, CredentialType, CredentialWithKey};

use crate::Error;

pub const CREDENTIAL_TYPE: u16 = 0xF0B0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KhensuCredential {
    pub address: [u8; 32],
    pub device_index: u16,
    pub log_index: u64,
}

impl KhensuCredential {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(42);
        out.extend_from_slice(&self.address);
        out.extend_from_slice(&self.device_index.to_be_bytes());
        out.extend_from_slice(&self.log_index.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let c = Self { address: r.array()?, device_index: r.u16()?, log_index: r.u64()? };
        r.finish()?;
        Ok(c)
    }

    pub fn credential_type() -> CredentialType {
        CredentialType::Other(CREDENTIAL_TYPE)
    }

    pub fn to_mls(&self) -> Credential {
        // MLS wraps the credential body as opaque<V>.
        let mut body = Vec::new();
        write_vec(&mut body, &self.encode());
        Credential::new(Self::credential_type(), body)
    }

    pub fn with_key(&self, signature_public_key: &[u8]) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.to_mls(),
            signature_key: signature_public_key.to_vec().into(),
        }
    }

    pub fn from_mls(credential: &Credential) -> Result<Self, Error> {
        if credential.credential_type() != Self::credential_type() {
            return Err(Error::WrongCredentialType);
        }
        let mut r = Reader::new(credential.serialized_content());
        let body = r.vec()?;
        r.finish()?;
        Self::decode(body)
    }
}

/// A `bind_device_key` entry as returned by the log client after it has checked
/// the inclusion proof against a witnessed checkpoint and the signer's authority.
#[derive(Clone, Debug)]
pub struct BoundDeviceKey {
    pub address: [u8; 32],
    pub device_index: u16,
    pub mls_signature_pk: Vec<u8>,
    pub not_after_epoch: u64,
    pub revoked: bool,
}

/// Lookup of verified log entries (implemented by the khensu-log client).
pub trait DeviceKeyDirectory {
    fn bound_device_key(&self, address: &[u8; 32], log_index: u64) -> Result<BoundDeviceKey, Error>;
}

/// Checks a leaf's credential and signature key against the log.
pub fn validate(
    credential: &Credential,
    leaf_signature_key: &[u8],
    network_epoch: u64,
    directory: &impl DeviceKeyDirectory,
) -> Result<KhensuCredential, Error> {
    let c = KhensuCredential::from_mls(credential)?;
    let bound = directory.bound_device_key(&c.address, c.log_index)?;
    if bound.address != c.address || bound.device_index != c.device_index {
        return Err(Error::CredentialMismatch);
    }
    if bound.mls_signature_pk != leaf_signature_key {
        return Err(Error::CredentialMismatch);
    }
    if bound.revoked {
        return Err(Error::Revoked);
    }
    if network_epoch > bound.not_after_epoch {
        return Err(Error::Expired);
    }
    Ok(c)
}
