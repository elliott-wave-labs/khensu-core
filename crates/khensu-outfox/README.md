# khensu-outfox

Mix packets for khensu.nu, as specified in [PROTOCOL.md section 8](https://github.com/elliott-wave-labs/khensu-specs/blob/main/PROTOCOL.md): Outfox-style layered headers with one ML-KEM-1024 encapsulation per hop, Lioness payloads, SURBs, per-epoch replay filters, final payloads and the mailbox request formats of section 6.2.

| Module | Contents |
| --- | --- |
| `packet` | Header building (`forward`) and per-hop processing (`process`) |
| `surb` | Reply blocks: `create`, `Surb::reply`, `SurbKeys::open` |
| `routing` | `RoutingInfo` (56 bytes) and its flags |
| `lioness` | `WBC`: Lioness over AES-256-CTR and HMAC-SHA-512 |
| `delivery` | `FinalPayload`, `MailboxRequest`, `StoreReceipt`, `MailboxReply`, `item_id` |
| `replay` | Bloom filter per mix-key epoch, current and previous only |
| `epoch` | `network_epoch` |

Sizes: hop header 1,640 B, header 8,200 B, small packet 10,248 B, bulk packet 73,736 B, SURB 8,248 B. Vectors: `vectors/outfox-v1.json` (`tests/vectors.rs`).

## Layering

Each hop sees `H = kem_ct[1568] || routing_ct[72] || B[6560]` and:

1. `ss = Decaps(node_mix_ek[epoch], kem_ct)`; `routing_key`, `header_key`, `payload_key` (192 B) and `replay_tag` (16 B) come from `KDF(ss, Label("hop routing" | "hop header" | "hop payload" | "hop replay"))`.
2. Opens `routing_ct` with AES-256-GCM, zero nonce, `B` as associated data, so a change anywhere in the rest of the header fails at the first hop that sees it.
3. Next header: `(B || 0^1640) XOR AES-256-CTR(header_key)`. The last 1,640 keystream bytes are the padding; the sender precomputes them (Sphinx filler).
4. Payload: Lioness decryption under `payload_key`.

Forward final hops carry `H256(Label("payload digest") || payload)[..16]` in `reserved`, so a tagged payload is dropped at the destination. SURB final hops set flag bit 2 (`reply`), put the client's delivery ID in `next_node_id` and `payload_key_ref` in `reserved`; the entry node delivers `(payload_key_ref, payload)` and the client re-encrypts with each hop key, last hop first.

## NOTES: decisions where PROTOCOL.md is open or inconsistent

1. **SURBs don't fit the small lane.** A SURB is 8,248 B (8.7); the small payload is 2,048 B (8.3), yet 8.8 puts a mailbox `fetch` (which carries SURBs) in each small-packet burst, and 6.7 gives every fragment `store` a SURB. Decision: requests that carry SURBs (`fetch`, `tree_get`, `store` with a receipt SURB) travel on the bulk lane. A bulk `fetch` holds at most 7 SURBs (`MAX_FETCH_SURBS`); OPEN-QUESTIONS 8's "exactly 8 SURBs" doesn't fit either (8 × 8,248 > 65,536). Small-lane `store`s carry no SURB.
2. **Store receipts don't fit a small reply.** A `StoreReceipt` holds a 4,627 B ML-DSA-87 signature. Decision: receipts are only sent through bulk SURBs; with note 1, v0.1 clients don't request them, so "Sent" can't yet be confirmed by 2 of 3 replicas.
3. **Fragment size.** 5.3 sizes fragment data as `SMALL_PAYLOAD - 24 = 2,024`, which ignores the `FinalPayload` and `MailboxRequest` framing. Decision: an encoded `Fragment` is the `sealed` field of a small `store` with empty SURB and access token, which leaves 2,008 B (`SMALL_STORE_MAX_SEALED`) and 1,988 B of fragment data. Bucket capacities become 5,964 / 7,952 / 11,928 / 15,904 B; a short ML-DSA-87-signed message still fits bucket 3. `khensu-mls` uses the same numbers.
4. **Bulk chunk size.** Tree chunks (6.5) and attachment chunks (6.4) are 64 KiB, but the bulk payload is exactly 64 KiB before framing (and attachment chunks add a 16-byte AEAD tag). Decision: tree chunks are 65,472 B (`TREE_CHUNK_MAX`, 64 KiB − 64), which fits `tree_put` and the `tree_get` reply. Attachment chunks should use the same bound minus their tag; attachments aren't implemented yet.
5. **Header stream key.** 8.2 names three KDF labels, but re-randomising the header needs a fourth key. Decision: `Label("hop header")`.
6. **Mailbox reply format.** 6.2 says fetch replies "go via SURBs" without a structure. Decision: `MailboxReply` (in `delivery.rs`) with kinds item, empty, store receipt, tree chunk and not found, plus a "more waiting" flag, zero-padded to the lane. The mailbox answers every SURB of a fetch, padding with `empty`.
7. **Reply integrity.** The SURB format has no key for the replier, so the reply is visible to the SURB's first hop and has no digest. Its contents are already end-to-end sealed (MLS) or signed (receipts); the client rejects a reply that doesn't parse with an all-zero tail.
8. **Lioness split.** `L` is 32 bytes (the AES-256 key size); HMAC-SHA-512 is truncated to 32 bytes; keys are K1, K3 (32 B) and K2, K4 (64 B).
9. **AEAD nonce.** Routing info is sealed with a zero nonce: every key is fresh per packet and hop.
10. **`GENESIS_TIME`** isn't defined. Devnets use 2026-10-09T00:00:00Z (`DEVNET_GENESIS_TIME`); the real value belongs in the genesis epoch header.
11. **Tree chunk addresses.** 6.5 writes `H256(chunk)`; section 1 requires labels everywhere, so the address is `H256(Label("tree chunk") || chunk)` (already so in `khensu-mls`).
