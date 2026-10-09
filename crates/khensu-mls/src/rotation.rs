//! Update cadence and signature-key rotation with delayed reveal (PROTOCOL.md 4, 4.1).

use khensu_crypto::{Reader, write_vec};

use crate::Error;
use crate::provider::MlDsaSigner;

pub const UPDATE_INTERVAL_SECS: u64 = 24 * 3600;
pub const UPDATE_EVERY_MESSAGES: u32 = 1000;
pub const REVEAL_DELAY_SECS: u64 = 7 * 24 * 3600;

/// Decides when this device must send a full-path update commit.
#[derive(Clone, Debug)]
pub struct UpdatePolicy {
    last_update_at: u64,
    sent_since_update: u32,
    others_changed_membership: bool,
}

impl UpdatePolicy {
    pub fn new(now: u64) -> Self {
        Self { last_update_at: now, sent_since_update: 0, others_changed_membership: false }
    }

    pub fn on_sent(&mut self) {
        self.sent_since_update = self.sent_since_update.saturating_add(1);
    }

    /// Someone else added or removed a member: we must refresh our path.
    pub fn on_membership_change_by_other(&mut self) {
        self.others_changed_membership = true;
    }

    pub fn update_due(&self, now: u64) -> bool {
        self.others_changed_membership
            || self.sent_since_update >= UPDATE_EVERY_MESSAGES
            || now.saturating_sub(self.last_update_at) >= UPDATE_INTERVAL_SECS
    }

    pub fn on_updated(&mut self, now: u64) {
        *self = Self::new(now);
    }
}

/// A signature key that has been replaced and must never sign again.
struct Retired {
    leaf_index: u32,
    retired_epoch: u64,
    retired_at: u64,
    signer: MlDsaSigner,
}

/// Holds the current signer and the retired ones awaiting reveal.
pub struct SignerRotation {
    current: MlDsaSigner,
    retired: Vec<Retired>,
}

/// `struct { uint32 leaf_index; uint64 retired_epoch; opaque retired_sk<V>; } KeyReveal;`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyReveal {
    pub leaf_index: u32,
    pub retired_epoch: u64,
    pub retired_seed: [u8; 32],
}

impl KeyReveal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.leaf_index.to_be_bytes());
        out.extend_from_slice(&self.retired_epoch.to_be_bytes());
        write_vec(&mut out, &self.retired_seed);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let leaf_index = r.u32()?;
        let retired_epoch = r.u64()?;
        let seed = r.vec()?;
        r.finish()?;
        Ok(Self { leaf_index, retired_epoch, retired_seed: seed.try_into().map_err(|_| Error::Decode)? })
    }

    /// The public key the revealed seed belongs to, so receivers can match it
    /// against the leaf key they saw in `retired_epoch`.
    pub fn public_key(&self) -> Vec<u8> {
        MlDsaSigner::from_seed(self.retired_seed).public_key().to_vec()
    }
}

impl SignerRotation {
    pub fn new(current: MlDsaSigner) -> Self {
        Self { current, retired: Vec::new() }
    }

    pub fn current(&self) -> &MlDsaSigner {
        &self.current
    }

    /// Installs `next` after its update commit has been merged. The old key is
    /// kept only until its reveal is due.
    pub fn rotate(&mut self, next: MlDsaSigner, leaf_index: u32, group_epoch: u64, now: u64) {
        let old = std::mem::replace(&mut self.current, next);
        self.retired.push(Retired { leaf_index, retired_epoch: group_epoch, retired_at: now, signer: old });
    }

    /// Returns reveals that are due and erases those keys (dropping a signer
    /// zeroizes its seed).
    pub fn take_due_reveals(&mut self, now: u64) -> Vec<KeyReveal> {
        let (due, keep): (Vec<_>, Vec<_>) =
            self.retired.drain(..).partition(|r| now.saturating_sub(r.retired_at) >= REVEAL_DELAY_SECS);
        self.retired = keep;
        due.into_iter()
            .map(|r| KeyReveal {
                leaf_index: r.leaf_index,
                retired_epoch: r.retired_epoch,
                retired_seed: *r.signer.key().seed(),
            })
            .collect()
    }

    pub fn retired_count(&self) -> usize {
        self.retired.len()
    }
}

/// Receiver-side record of revealed keys. Messages signed by a revealed key are
/// rejected from then on; old transcripts signed by it become non-attributable.
#[derive(Default)]
pub struct RevealedKeys {
    keys: std::collections::HashSet<Vec<u8>>,
}

impl RevealedKeys {
    pub fn insert(&mut self, reveal: &KeyReveal) {
        self.keys.insert(reveal.public_key());
    }

    pub fn is_revealed(&self, signature_public_key: &[u8]) -> bool {
        self.keys.contains(signature_public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_triggers() {
        let mut p = UpdatePolicy::new(0);
        assert!(!p.update_due(10));
        assert!(p.update_due(UPDATE_INTERVAL_SECS));
        for _ in 0..UPDATE_EVERY_MESSAGES {
            p.on_sent();
        }
        assert!(p.update_due(1));
        p.on_updated(5);
        assert!(!p.update_due(6));
        p.on_membership_change_by_other();
        assert!(p.update_due(6));
    }

    #[test]
    fn reveal_after_seven_days_and_erase() {
        let first = MlDsaSigner::generate().unwrap();
        let first_pk = first.public_key().to_vec();
        let mut rot = SignerRotation::new(first);
        rot.rotate(MlDsaSigner::generate().unwrap(), 3, 10, 1000);
        assert!(rot.take_due_reveals(1000 + REVEAL_DELAY_SECS - 1).is_empty());
        let reveals = rot.take_due_reveals(1000 + REVEAL_DELAY_SECS);
        assert_eq!(reveals.len(), 1);
        assert_eq!(rot.retired_count(), 0);
        let r = KeyReveal::decode(&reveals[0].encode()).unwrap();
        assert_eq!(r.public_key(), first_pk);
        let mut seen = RevealedKeys::default();
        seen.insert(&r);
        assert!(seen.is_revealed(&first_pk));
    }
}
