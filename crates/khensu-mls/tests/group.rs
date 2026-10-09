// SPDX-License-Identifier: Apache-2.0
//! End-to-end group lifecycle on the khensu suite: create, add with a Welcome
//! that carries no tree, message, rotate signature key, reject the retired key,
//! remove, and derive matching mailbox IDs.

use std::collections::HashMap;

use khensu_mls::credential::{BoundDeviceKey, DeviceKeyDirectory, validate};
use khensu_mls::fragment::{Reassembler, split};
use khensu_mls::mailbox::{mailbox_id, mailbox_seed};
use khensu_mls::{Error, KhensuCredential, KhensuProvider, MlDsaSigner, SUITE, capabilities, create_config, join_config};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls::treesync::RatchetTree;
use openmls_traits::OpenMlsProvider;

struct Device {
    provider: KhensuProvider,
    signer: MlDsaSigner,
    cred: KhensuCredential,
}

impl Device {
    fn new(address_byte: u8, log_index: u64) -> Self {
        Self {
            provider: KhensuProvider::in_memory().unwrap(),
            signer: MlDsaSigner::generate().unwrap(),
            cred: KhensuCredential { address: [address_byte; 32], device_index: 0, log_index },
        }
    }

    fn cwk(&self) -> CredentialWithKey {
        self.cred.with_key(self.signer.public_key())
    }

    fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(SUITE, &self.provider, &self.signer, self.cwk())
            .unwrap()
            .key_package()
            .clone()
    }
}

fn wire(m: &MlsMessageOut) -> Vec<u8> {
    m.tls_serialize_detached().unwrap()
}

fn incoming(bytes: &[u8]) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(bytes).unwrap()
}

fn join(d: &Device, welcome: &MlsMessageOut, tree: RatchetTree) -> MlsGroup {
    let MlsMessageBodyIn::Welcome(w) = incoming(&wire(welcome)).extract() else { panic!("not a welcome") };
    StagedWelcome::new_from_welcome(&d.provider, &join_config(), w, Some(tree.into()))
        .unwrap()
        .into_group(&d.provider)
        .unwrap()
}

/// Processes a message; merges commits; returns application bytes if any.
fn receive(d: &Device, g: &mut MlsGroup, bytes: &[u8]) -> Option<Vec<u8>> {
    let pm = incoming(bytes).try_into_protocol_message().unwrap();
    match g.process_message(&d.provider, pm).unwrap().into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => Some(m.into_bytes()),
        ProcessedMessageContent::StagedCommitMessage(c) => {
            g.merge_staged_commit(&d.provider, *c).unwrap();
            None
        }
        _ => None,
    }
}

struct Dir(HashMap<u64, BoundDeviceKey>);

impl DeviceKeyDirectory for Dir {
    fn bound_device_key(&self, _address: &[u8; 32], log_index: u64) -> Result<BoundDeviceKey, Error> {
        self.0.get(&log_index).cloned().ok_or(Error::NotInLog)
    }
}

#[test]
fn group_lifecycle() {
    let alice = Device::new(0xA1, 1);
    let mut bob = Device::new(0xB0, 2);
    let carol = Device::new(0xC0, 3);

    let mut ga = MlsGroup::new(&alice.provider, &alice.signer, &create_config(), alice.cwk()).unwrap();
    assert_eq!(ga.ciphersuite(), SUITE);

    let (_commit, welcome, group_info) = ga
        .add_members(&alice.provider, &alice.signer, &[bob.key_package(), carol.key_package()])
        .unwrap();
    assert!(group_info.is_none(), "no GroupInfo with the tree");
    ga.merge_pending_commit(&alice.provider).unwrap();

    // The tree travels separately (content-addressed chunks), not in the Welcome.
    let welcome_bytes = wire(&welcome);
    let tree = ga.export_ratchet_tree();
    let tree_bytes = tree.tls_serialize_detached().unwrap();
    assert!(welcome_bytes.len() < tree_bytes.len() + 20_000);
    let mut gb = join(&bob, &welcome, tree.clone());
    let mut gc = join(&carol, &welcome, tree);

    // Application message: PrivateMessage only, fits a 3-fragment bucket.
    let out = ga.create_message(&alice.provider, &alice.signer, b"first light").unwrap();
    assert!(matches!(out.body(), MlsMessageBodyOut::PrivateMessage(_)));
    let bytes = wire(&out);
    eprintln!("welcome {} B, tree {} B, private message {} B", welcome_bytes.len(), tree_bytes.len(), bytes.len());
    let frags = split(&bytes).unwrap();
    assert_eq!(frags.len(), 3, "a short message with an ML-DSA-87 signature fits bucket 3 ({} B)", bytes.len());
    let mut r = Reassembler::default();
    let rebuilt = frags.into_iter().find_map(|f| r.push(f, 0).unwrap()).unwrap();
    assert_eq!(receive(&bob, &mut gb, &rebuilt).unwrap(), b"first light");
    assert_eq!(receive(&carol, &mut gc, &bytes).unwrap(), b"first light");

    // Credentials resolve against the log.
    let mut dir = Dir(HashMap::new());
    for d in [&alice, &bob, &carol] {
        dir.0.insert(d.cred.log_index, BoundDeviceKey {
            address: d.cred.address,
            device_index: 0,
            mls_signature_pk: d.signer.public_key().to_vec(),
            not_after_epoch: 100,
            revoked: false,
        });
    }
    for m in ga.members() {
        validate(&m.credential, &m.signature_key, 10, &dir).unwrap();
    }

    // Bob rotates his signature key with a full-path update.
    let old_signer = std::mem::replace(&mut bob.signer, MlDsaSigner::generate().unwrap());
    let bundle = gb
        .self_update_with_new_signer(
            &bob.provider,
            &old_signer,
            NewSignerBundle { signer: &bob.signer, credential_with_key: bob.cwk() },
            LeafNodeParameters::default(),
        )
        .unwrap();
    let (commit, _, _) = bundle.into_messages();
    gb.merge_pending_commit(&bob.provider).unwrap();
    let commit_bytes = wire(&commit);
    receive(&alice, &mut ga, &commit_bytes);
    receive(&carol, &mut gc, &commit_bytes);
    assert_eq!(ga.epoch(), gb.epoch());

    let out = gb.create_message(&bob.provider, &bob.signer, b"new key").unwrap();
    assert_eq!(receive(&alice, &mut ga, &wire(&out)).unwrap(), b"new key");

    // A message signed with the retired key is rejected.
    let forged = gb.create_message(&bob.provider, &old_signer, b"old key").unwrap();
    let pm = incoming(&wire(&forged)).try_into_protocol_message().unwrap();
    assert!(ga.process_message(&alice.provider, pm).is_err());

    // The old binding no longer matches Bob's leaf.
    let bob_leaf = ga.members().find(|m| m.index == gb.own_leaf_index()).unwrap();
    assert_eq!(validate(&bob_leaf.credential, &bob_leaf.signature_key, 10, &dir), Err(Error::CredentialMismatch));

    // Mailbox IDs agree across members for the same leaf and epoch.
    let sa = mailbox_seed(&ga, alice.provider.crypto()).unwrap();
    let sb = mailbox_seed(&gb, bob.provider.crypto()).unwrap();
    assert_eq!(mailbox_id(&sa, 1, 42), mailbox_id(&sb, 1, 42));
    assert_ne!(mailbox_id(&sa, 1, 42), mailbox_id(&sa, 1, 43));

    // Alice removes Carol; Carol's state goes inactive.
    let carol_leaf = gc.own_leaf_index();
    let (commit, _, _) = ga.remove_members(&alice.provider, &alice.signer, &[carol_leaf]).unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    let commit_bytes = wire(&commit);
    receive(&bob, &mut gb, &commit_bytes);
    receive(&carol, &mut gc, &commit_bytes);
    assert!(!gc.is_active());
    assert_eq!(ga.members().count(), 2);
    assert_ne!(mailbox_seed(&ga, alice.provider.crypto()).unwrap(), sa);
}

#[test]
fn other_suites_refused() {
    let p = KhensuProvider::in_memory().unwrap();
    use openmls_traits::crypto::OpenMlsCrypto;
    assert_eq!(p.crypto().supported_ciphersuites(), vec![SUITE]);
    assert!(p.crypto().supports(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).is_err());
}
