// SPDX-License-Identifier: Apache-2.0
//! Encrypted state blob: `"KHNS" || uint8 version || nonce[12] || AES-256-GCM(key, nonce, state, aad = "khensu state v1")`.
//! The key comes from the app (wrapped by the Secure Enclave there).

use std::collections::BTreeMap;

use khensu_crypto::sym::{open, seal};
use khensu_crypto::{Reader, SigKeyPair, random, write_vec};
use khensu_mls::fragment::Reassembler;
use khensu_mls::tree::TreeManifest;
use khensu_outfox::SurbKeys;
use khensu_outfox::delivery::MailboxRequest;
use openmls::prelude::{GroupId, MlsGroup};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use zeroize::Zeroize;

use crate::KhensuError;
use crate::core::{BlobPurpose, Core, Group, Held, Outgoing, PendingBlob, PendingKp, PendingSurb, SurbPurpose, mls_err};
use crate::identity::Identity;

const MAGIC: &[u8; 4] = b"KHNS";
const VERSION: u8 = 2;
const AAD: &[u8] = b"khensu state v1";

fn bad(_: impl core::fmt::Debug) -> KhensuError {
    KhensuError::State { msg: "corrupt state".into() }
}

fn key32(key: &[u8]) -> Result<[u8; 32], KhensuError> {
    key.try_into().map_err(|_| KhensuError::Invalid { msg: "state key must be 32 bytes".into() })
}

fn put_u32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_be_bytes());
}

fn put_outgoing(out: &mut Vec<u8>, o: &Outgoing) {
    match o {
        Outgoing::Request { rendezvous, request, replica, receipt } => {
            out.push(1);
            out.extend_from_slice(rendezvous);
            write_vec(out, &request.encode());
            out.push(*replica);
            out.push(*receipt as u8);
        }
        Outgoing::TreeGet(h) => {
            out.push(2);
            out.extend_from_slice(h);
        }
        Outgoing::Loop => out.push(3),
    }
}

fn get_outgoing(r: &mut Reader<'_>) -> Result<Outgoing, KhensuError> {
    Ok(match r.u8().map_err(bad)? {
        1 => Outgoing::Request {
            rendezvous: r.array().map_err(bad)?,
            request: MailboxRequest::decode(r.vec().map_err(bad)?).map_err(bad)?,
            replica: r.u8().map_err(bad)?,
            receipt: r.u8().map_err(bad)? == 1,
        },
        2 => Outgoing::TreeGet(r.array().map_err(bad)?),
        3 => Outgoing::Loop,
        _ => return Err(bad(())),
    })
}

pub fn export(core: &Core, key: &[u8]) -> Result<Vec<u8>, KhensuError> {
    let mut key = key32(key)?;
    let mut s = Vec::new();
    s.extend_from_slice(core.identity.key.seed());
    write_vec(&mut s, &core.identity.inception);
    write_vec(&mut s, core.display_name.as_bytes());
    s.extend_from_slice(&core.device_index.to_be_bytes());
    s.extend_from_slice(&core.delivery_id);
    write_vec(&mut s, core.gateway.as_deref().unwrap_or("").as_bytes());

    let values = core.provider.storage().values.read().map_err(|_| bad(()))?;
    put_u32(&mut s, values.len());
    for (k, v) in values.iter() {
        write_vec(&mut s, k);
        write_vec(&mut s, v);
    }
    drop(values);

    put_u32(&mut s, core.groups.len());
    for (gid, g) in &core.groups {
        write_vec(&mut s, gid);
        s.extend_from_slice(&g.signer_seed);
        write_vec(&mut s, g.title.as_bytes());
        s.push(g.direct as u8);
        match g.prev_seed {
            Some(p) => {
                s.push(1);
                s.extend_from_slice(&p);
            }
            None => s.push(0),
        }
    }
    put_u32(&mut s, core.key_packages.len());
    for (r, k) in &core.key_packages {
        write_vec(&mut s, r);
        s.extend_from_slice(&k.signer_seed);
        s.extend_from_slice(&k.intro_seed);
        s.extend_from_slice(&k.created_epoch.to_be_bytes());
    }
    put_u32(&mut s, core.surbs.len());
    for p in core.surbs.values() {
        write_vec(&mut s, &p.keys.encode());
        let (t, h) = match p.purpose {
            SurbPurpose::Fetch(h) => (1, h),
            SurbPurpose::TreeGet(h) => (2, h),
            SurbPurpose::Loop(sent_ms) => {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&sent_ms.to_be_bytes());
                (3, h)
            }
            SurbPurpose::StoreReceipt(h) => (4, h),
        };
        s.push(t);
        s.extend_from_slice(&h);
        s.extend_from_slice(&p.epoch.to_be_bytes());
    }
    for q in [&core.small_out, &core.bulk_out] {
        put_u32(&mut s, q.len());
        for o in q {
            put_outgoing(&mut s, o);
        }
    }
    put_u32(&mut s, core.acks.len());
    for (m, ids) in &core.acks {
        s.extend_from_slice(m);
        write_vec(&mut s, &ids.concat());
    }
    write_vec(&mut s, &core.reassembler.encode());
    put_u32(&mut s, core.seen.len());
    for (id, t) in &core.seen {
        s.extend_from_slice(id);
        s.extend_from_slice(&t.to_be_bytes());
    }
    put_u32(&mut s, core.held.len());
    for h in &core.held {
        write_vec(&mut s, &h.group_id);
        write_vec(&mut s, &h.message);
        s.extend_from_slice(&h.since.to_be_bytes());
    }
    put_u32(&mut s, core.blobs.len());
    for b in &core.blobs {
        write_vec(&mut s, &b.manifest.encode());
        put_u32(&mut s, b.chunks.len());
        for (a, c) in &b.chunks {
            s.extend_from_slice(a);
            write_vec(&mut s, c);
        }
        match &b.purpose {
            BlobPurpose::Join { kp_ref, welcome, tree_key, title } => {
                s.push(1);
                write_vec(&mut s, kp_ref);
                write_vec(&mut s, welcome);
                s.extend_from_slice(tree_key);
                write_vec(&mut s, title.as_bytes());
            }
            BlobPurpose::Message { group_id } => {
                s.push(2);
                write_vec(&mut s, group_id);
            }
        }
        s.extend_from_slice(&b.since.to_be_bytes());
    }
    s.extend_from_slice(&core.cursor.to_be_bytes());
    s.extend_from_slice(&core.ticks.to_be_bytes());

    let nonce: [u8; 12] = random()?;
    let ct = seal(&key, &nonce, &s, AAD);
    s.zeroize();
    key.zeroize();
    let mut out = Vec::with_capacity(17 + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn string(r: &mut Reader<'_>) -> Result<String, KhensuError> {
    String::from_utf8(r.vec().map_err(bad)?.to_vec()).map_err(bad)
}

pub fn import(blob: &[u8], key: &[u8]) -> Result<Core, KhensuError> {
    let mut key = key32(key)?;
    if blob.len() < 17 || &blob[..4] != MAGIC || blob[4] != VERSION {
        return Err(KhensuError::State { msg: "not a khensu state blob".into() });
    }
    let nonce: [u8; 12] = blob[5..17].try_into().expect("12 bytes");
    let plain = open(&key, &nonce, &blob[17..], AAD).map_err(|_| KhensuError::Crypto { msg: "wrong state key".into() });
    key.zeroize();
    let mut plain = plain?;
    let core = decode(&plain);
    plain.zeroize();
    core
}

fn decode(plain: &[u8]) -> Result<Core, KhensuError> {
    let mut r = Reader::new(plain);
    let seed: [u8; 32] = r.array().map_err(bad)?;
    let inception = r.vec().map_err(bad)?.to_vec();
    let display_name = string(&mut r)?;
    let device_index = r.u16().map_err(bad)?;
    let delivery_id = r.array().map_err(bad)?;
    let gateway = string(&mut r)?;
    let identity = Identity::from_parts(SigKeyPair::from_seed(seed), inception);

    let mut values = std::collections::HashMap::new();
    for _ in 0..r.u32().map_err(bad)? {
        values.insert(r.vec().map_err(bad)?.to_vec(), r.vec().map_err(bad)?.to_vec());
    }
    let storage = MemoryStorage { values: std::sync::RwLock::new(values) };
    let mut core = Core::with_identity(identity, display_name, delivery_id)?;
    core.provider = khensu_mls::KhensuProvider::with_storage(storage).map_err(mls_err)?;
    core.device_index = device_index;
    core.gateway = (!gateway.is_empty()).then_some(gateway);

    for _ in 0..r.u32().map_err(bad)? {
        let gid = r.vec().map_err(bad)?.to_vec();
        let signer_seed = r.array().map_err(bad)?;
        let title = string(&mut r)?;
        let direct = r.u8().map_err(bad)? == 1;
        let prev_seed = match r.u8().map_err(bad)? {
            1 => Some(r.array().map_err(bad)?),
            _ => None,
        };
        let mls = MlsGroup::load(core.provider.storage(), &GroupId::from_slice(&gid))
            .map_err(mls_err)?
            .ok_or_else(|| bad("group missing from storage"))?;
        core.groups.insert(gid, Group { mls, signer_seed, title, direct, prev_seed });
    }
    for _ in 0..r.u32().map_err(bad)? {
        let kp_ref = r.vec().map_err(bad)?.to_vec();
        let k = PendingKp { signer_seed: r.array().map_err(bad)?, intro_seed: r.array().map_err(bad)?, created_epoch: r.u64().map_err(bad)? };
        core.key_packages.insert(kp_ref, k);
    }
    for _ in 0..r.u32().map_err(bad)? {
        let keys = SurbKeys::decode(r.vec().map_err(bad)?).map_err(bad)?;
        let t = r.u8().map_err(bad)?;
        let h = r.array().map_err(bad)?;
        let purpose = match t {
            1 => SurbPurpose::Fetch(h),
            2 => SurbPurpose::TreeGet(h),
            3 => SurbPurpose::Loop(u64::from_be_bytes(h[..8].try_into().expect("8 bytes"))),
            4 => SurbPurpose::StoreReceipt(h),
            _ => return Err(bad(())),
        };
        let epoch = r.u64().map_err(bad)?;
        core.surbs.insert(keys.payload_key_ref, PendingSurb { keys, purpose, epoch });
    }
    for q in [&mut core.small_out, &mut core.bulk_out] {
        for _ in 0..r.u32().map_err(bad)? {
            q.push_back(get_outgoing(&mut r)?);
        }
    }
    for _ in 0..r.u32().map_err(bad)? {
        let m = r.array().map_err(bad)?;
        let ids = r.vec().map_err(bad)?;
        core.acks.insert(m, ids.chunks(32).map(|c| c.try_into().expect("32 bytes")).collect());
    }
    core.reassembler = Reassembler::decode(r.vec().map_err(bad)?).map_err(bad)?;
    for _ in 0..r.u32().map_err(bad)? {
        core.seen.insert(r.array().map_err(bad)?, r.u64().map_err(bad)?);
    }
    for _ in 0..r.u32().map_err(bad)? {
        core.held.push(Held { group_id: r.vec().map_err(bad)?.to_vec(), message: r.vec().map_err(bad)?.to_vec(), since: r.u64().map_err(bad)? });
    }
    for _ in 0..r.u32().map_err(bad)? {
        let manifest = TreeManifest::decode(r.vec().map_err(bad)?).map_err(bad)?;
        let mut chunks = BTreeMap::new();
        for _ in 0..r.u32().map_err(bad)? {
            chunks.insert(r.array().map_err(bad)?, r.vec().map_err(bad)?.to_vec());
        }
        let purpose = match r.u8().map_err(bad)? {
            1 => BlobPurpose::Join {
                kp_ref: r.vec().map_err(bad)?.to_vec(),
                welcome: r.vec().map_err(bad)?.to_vec(),
                tree_key: r.array().map_err(bad)?,
                title: string(&mut r)?,
            },
            _ => BlobPurpose::Message { group_id: r.vec().map_err(bad)?.to_vec() },
        };
        let since = r.u64().map_err(bad)?;
        core.blobs.push(PendingBlob { manifest, chunks, requested: BTreeMap::new(), purpose, since });
    }
    core.cursor = r.u64().map_err(bad)?;
    core.ticks = r.u64().map_err(bad)?;
    r.finish().map_err(bad)?;
    Ok(core)
}
