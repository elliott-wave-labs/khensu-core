//! TreeKEM at scale on the khensu suite. The default run uses 100 devices;
//! `cargo test --release -- --ignored` runs the 1,000-device maximum.

use khensu_mls::tree::{assemble, chunk_tree};
use khensu_mls::{KhensuCredential, KhensuProvider, MlDsaSigner, SUITE, capabilities, create_config, join_config};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use std::collections::HashMap;
use std::time::Instant;

fn run(n: usize) {
    let mk = |i: usize| {
        let p = KhensuProvider::in_memory().unwrap();
        let s = MlDsaSigner::generate().unwrap();
        let c = KhensuCredential { address: [(i % 251) as u8; 32], device_index: (i / 251) as u16, log_index: i as u64 };
        (p, s, c)
    };
    let (pa, sa, ca) = mk(0);
    let mut g = MlsGroup::new(&pa, &sa, &create_config(), ca.with_key(sa.public_key())).unwrap();

    let t = Instant::now();
    let members: Vec<_> = (1..n).map(mk).collect();
    let kps: Vec<KeyPackage> = members
        .iter()
        .map(|(p, s, c)| {
            KeyPackage::builder()
                .leaf_node_capabilities(capabilities())
                .build(SUITE, p, s, c.with_key(s.public_key()))
                .unwrap()
                .key_package()
                .clone()
        })
        .collect();
    let (_, welcome, _) = g.add_members(&pa, &sa, &kps).unwrap();
    g.merge_pending_commit(&pa).unwrap();
    let add_time = t.elapsed();

    let tree = g.export_ratchet_tree().tls_serialize_detached().unwrap();
    let (manifest, chunks) = chunk_tree(&tree);
    let store: HashMap<_, _> = manifest.chunk_hashes.iter().copied().zip(chunks).collect();

    // The last member joins from the Welcome plus chunks fetched by address.
    let (pl, sl, _) = members.last().unwrap();
    let fetched = assemble(&manifest, |a| store.get(a).cloned()).unwrap();
    let tree_in = RatchetTreeIn::tls_deserialize_exact(&fetched).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) =
        MlsMessageIn::tls_deserialize_exact(&welcome.tls_serialize_detached().unwrap()).unwrap().extract()
    else {
        panic!("not a welcome")
    };
    let mut gl = StagedWelcome::new_from_welcome(pl, &join_config(), welcome, Some(tree_in))
        .unwrap()
        .into_group(pl)
        .unwrap();
    assert_eq!(gl.members().count(), n);

    // A full-path update from the newest member reaches the creator.
    let t = Instant::now();
    let (commit, _, _) = gl.self_update(pl, sl, LeafNodeParameters::default()).unwrap().into_messages();
    gl.merge_pending_commit(pl).unwrap();
    let pm = MlsMessageIn::tls_deserialize_exact(&commit.tls_serialize_detached().unwrap())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(c) = g.process_message(&pa, pm).unwrap().into_content() else {
        panic!("expected commit")
    };
    g.merge_staged_commit(&pa, *c).unwrap();
    assert_eq!(g.epoch(), gl.epoch());
    eprintln!(
        "{n} devices: add {:?}, tree {} KB in {} chunks, update commit {} KB processed in {:?}",
        add_time,
        tree.len() / 1024,
        manifest.chunk_hashes.len(),
        commit.tls_serialize_detached().unwrap().len() / 1024,
        t.elapsed()
    );
}

#[test]
fn hundred_devices() {
    run(100);
}

#[test]
#[ignore = "slow: run with --release -- --ignored"]
fn thousand_devices() {
    run(khensu_mls::MAX_GROUP_LEAVES as usize);
}
