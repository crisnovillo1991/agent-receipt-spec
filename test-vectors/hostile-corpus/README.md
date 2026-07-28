> **Historical record.** This table describes results against `75499dc`
> (pre-round-3). Against the round-3 release all 31 entries measure
> **0 CRASH · 0 DIVERGE · 0 HOLE** — see the round-3 report in
> x402-foundation/x402#2922. Preserved verbatim as the regression
> baseline; `SHA256SUMS` covers the entries, not this file.

# AIR hostile corpus — 31 constructed entries (third pass, x402-foundation/x402#2922)

Constructed against `crisnovillo1991/agent-receipt-spec` @ `75499dc6ed53bf724d7233f9c8563c2f99447008`, signed with the published test key (seed `0x01..0x20`) by an independent pure-Python Ed25519 signer (RFC 8032), byte-identical signatures to OpenSSL. Run through two implementations: the repo's `verifier/verify.py` and a second implementation with no shared dependencies (own JSON parser, own §5 canonical serializer, own Ed25519, own base64; only sha256/sha512 shared).

`.raw` files are verbatim settle-response bytes for §8.4 cases. `H34_prev.json` is the predecessor for the `--prev` chain case. `base_receipt.json` is the conforming baseline the entries mutate.

Result key: AGREE = both implementations reject/accept identically per SPEC · DIVERGE = repo verifier accepts, independent verifier rejects (SPEC says reject) · CRASH = repo verifier raises a traceback instead of a verdict · HOLE = both accept, SPEC missing a rule · INFO = observation.

| Entry | Result | What it probes |
|---|---|---|
| H1 | DIVERGE | `key_id` inconsistent with `public_key` (§4.4) |
| H2 | AGREE | signature transplanted from another entry |
| H3 | INFO/obs | attacker signs with own key (trust is out-of-band, §9) |
| H4 | AGREE | non-canonical scalar `S+L` (RFC 8032 malleability) |
| H5 | HOLE | identity-point public key, `R`=identity, `S=0` — verifies with no secret |
| H6 | AGREE | empty `signatures` array |
| H7 | CRASH | `"signatures": ["not-an-object"]` → AttributeError inside the except handler (`verify.py:89`) |
| H9 | CRASH | float inside `signatures` (outside signed payload) → ValueError at `entry_hash` (`verify.py:194`) |
| H10 | CRASH | float anywhere in entry (same class as shipped `invalid/12`) |
| H11 | AGREE* | `body_len` = 2^60 — accepted by both; §5 integer range unspecified |
| H14 | AGREE | attachment `seq` not greater than receipt |
| H15 | AGREE | attachment pointing at a receipt from another session |
| H16 | AGREE* | equivocation: second signed successor at same (session, seq) — both verify, §7 silent |
| H17 | DIVERGE | attachment `final_status: "settled"` with `tx_hash: null` |
| H18 | AGREE | `settled` with `settlement_ref: ""` (receipt leg check exists, `verify.py:102`) |
| H19 | DIVERGE | `pending` receipt carrying `settlement_ref: "0xlookslikesettled"` (§4.3) |
| H20 | AGREE | attachment with `final_status: "pending"` |
| H21 | DIVERGE | receipt with no `request` and no `response` (§4.5 Req) |
| H22 | DIVERGE | `spec_version: "0.2"` with v0.1 `prev_receipt_hash`, `seq: 1`, no `prev_entry_hash` (§4.0) |
| H23 | DIVERGE | missing `meta` object (§4.0 Req) |
| H24 (+raw) | AGREE | settle-response `"transaction": true` → `failed`/`null` |
| H25 (+raw) | AGREE | BOM before an otherwise-settled settle-response → `failed`/`null` |
| H26 (+raw) | INFO→SPEC gap | duplicate key in verbatim settle-response: last-wins vs first-wins parsers derive opposite finality from identical bytes (§8.4) |
| H27 (+raw) | INFO | both flag per §8.4 (control) |
| H28 (+raw) | DIVERGE | `settle_response_len` lying about disclosed length (9999 vs 38) |
| H29 | DIVERGE | duplicate key in the entry file itself — same signature, same `entry_hash`, a field no check ever sees (§5) |
| H30 (+raw) | AGREE | positive control: conforming attachment |
| H31 | AGREE | key order reversed in file — `entry_hash` unchanged (canonicalization control) |
| H32 | CRASH | `"payment": "none"` → AttributeError (`verify.py:100`) |
| H33 | CRASH | `"settlement": "pending"` → AttributeError (`verify.py:106`; `or {}` passes non-empty string) |
| H34 (+prev) | CRASH | predecessor with `"seq": null` on `--prev` path → TypeError (`verify.py:119`) |

Totals: AGREE 14 · DIVERGE 8 · CRASH 6 · HOLE 1 · INFO 2.

Offered as a permanent hostile corpus per the maintainer's request in x402-foundation/x402#2922; each filed issue lists its entries as the regression tests.
