# khensu-core

Shared Rust core for khensu.nu: post-quantum primitives, the MLS profile, mixnet packets and the transparency log format. Licensed Apache-2.0. The wire formats are specified in [khensu-specs/PROTOCOL.md](https://github.com/elliott-wave-labs/khensu-specs/blob/main/PROTOCOL.md).

| Crate | Contents |
| --- | --- |
| `khensu-crypto` | ML-KEM-1024 and ML-DSA-87 (libcrux), labelled hashes, HKDF-SHA-512, AES-256-GCM, codec helpers |
| `khensu-mls` | OpenMLS provider for `MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87`, `KhensuCredential`, signature rotation with delayed reveal, mailbox IDs, fragment buckets, content-addressed ratchet trees |
| `khensu-outfox` | Mix packets: ML-KEM-1024 per hop, Lioness payloads, SURBs, replay filters, final payloads and mailbox requests ([README](crates/khensu-outfox/README.md), with the spec decisions) |

Test vectors live in `vectors/`.

## Build and test

```sh
cargo test
cargo test --release -p khensu-mls -- --ignored   # 1,000-device group
```

OpenMLS 0.9.1 already defines our suite (codepoint `0x0906`); its libcrux backend does the ML-KEM-1024 HPKE but signs only with Ed25519, so `khensu-mls` wraps it and adds ML-DSA-87. No fork is needed. ML-KEM HPKE in `hpke-rs-libcrux` is behind the `draft-connolly-cfrg-hpke-mlkem` feature, which `khensu-mls` turns on.
