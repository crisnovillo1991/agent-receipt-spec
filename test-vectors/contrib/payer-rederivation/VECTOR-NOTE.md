# AIR draft-2 payer/payTo swap vector

## What this tests

This pair pins the draft-2 x402 payer re-derivation rule in `SPEC-v0.3-draft.md` section 4.3:

- If disclosed settle-response bytes carry `payer`, `payment.payer` MUST equal that value after lowercase address comparison.
- `payment.pay_to` remains issuer-attested in the current profile because the 402 quote leg is not part of the required disclosure.

`air-vector-valid.json` binds the disclosed payer correctly. `air-vector-swapped.json` exchanges only the two embedded role values, `payment.payer` and `payment.pay_to`. The Ed25519 signature is necessarily regenerated because those fields are inside the signed payload. All other receipt fields and all disclosed settle-response bytes are identical.

Expected draft-2 verdicts:

- `air-vector-valid.json`: PASS.
- `air-vector-swapped.json`: FAIL with a payer re-derivation mismatch.

## Why ordinary on-chain reconciliation does not catch it

The chain confirms that a transaction landed and that value moved between two addresses. It does not, by itself, validate the semantic labels used by an AIR receipt. A settlement-ledger verifier that checks only transaction hash, status, network, amount, and signature can accept either labeling of the same two participants.

A ledger implementation can catch the swap only if it adds an explicit role-mapping check against decoded transfer or authorization data. The AIR draft-2 profile instead provides a transport-independent check for the payer role: compare `payment.payer` with the disclosed settle response. The corresponding source for `payTo` is the 402 quote leg, which the current disclosure profile does not require. Consequently, tx-hash reconciliation alone is insufficient, even though richer chain decoding could supply an additional implementation-specific check.

## Construction and anonymization

The structural shape comes from one read-only `payments.db` row satisfying all of the following:

- `chain = base`
- `is_facilitator_mediated = 1`
- July 2026
- `wash_flag IS NULL`
- distinct, non-null payer and recipient

The retained non-identifying shape is 136,470 USDC atomic units (`0.136470` USDC) and the source leg's calendar date. The time of day is synthetic: `2026-07-15T12:00:00.000Z`. An earlier draft carried the source row's real timestamp normalized to milliseconds; a pre-publication audit flagged that amount plus second-precision time resolved to exactly one row in the source ledger, making the pair a quasi-identifier recoverable from public chain data, so the time was re-synthesized and both files re-signed. No database address, transaction hash, submitter, timestamp, or other identifier is copied.

Synthetic identifiers:

- payer: `0xa11ce00000000000000000000000000000000001`
- payTo: `0xb0b0000000000000000000000000000000000002`
- transaction: `0x947da0e7eec1949932d56900eafda936fe4ea295411cb916f4eecfdcb9bb1b19`
- transaction derivation phrase: `air-draft-2:payer-payto-swap:test-transaction`

The transaction value is `0x` followed by SHA-256 of the exact ASCII phrase above. Both addresses and the synthetic transaction hash were checked against the source database in every relevant identifier column; all match counts were zero. Request, response, payment-payload, and settle-response digests are also derived only from synthetic test bytes. Both receipts use the repository's published test-only Ed25519 key.

The shared disclosed settle response is the following exact 169 UTF-8 bytes, with no trailing newline:

```json
{"success":true,"transaction":"0x947da0e7eec1949932d56900eafda936fe4ea295411cb916f4eecfdcb9bb1b19","network":"base","payer":"0xa11ce00000000000000000000000000000000001"}
```

Its SHA-256 is `645e964bc4d3b2fce85e02edf875e2dca620621849744411f99b69d9fade7981`, matching `payment.settle_response_sha256` in both receipts.

Provenance: SmartFlow Observatory (`github.com/smartflowproai-lang`).

## Verification result

Tested against repository commit `6369e51`.

The current reference verifier accepts both files with the disclosure supplied:

- valid: exit 0, signature and existing re-derivation checks pass.
- swapped: exit 0, signature and existing re-derivation checks pass.

This is the useful observation: `verifier/verify.py` currently re-derives settlement status and transaction hash but does not yet enforce the draft-2 payer comparison. A direct draft-2 payer-rule probe passes the valid file and rejects the swapped file. The pair-isolation check also passes: after omitting the necessarily regenerated signature, swapping `payment.payer` and `payment.pay_to` is the only difference.

## File SHA-256

These hashes cover the exact JSON file bytes, including the final line feed:

- `air-vector-valid.json`: `4f51f8e5e38a5c63eddbdc88e8b3ecef42853c9f6d4d4ff3cb05538465c86f92`
- `air-vector-swapped.json`: `25dae1438a24fd9c1e0f1922d69d21c2093a0858c65cbb6fee8cc1f6b0444359`

## Update: rule landed (2026-08-19)

Commit `209a6b4` enforces the §4.3 payer comparison in `verifier/verify.py`. Reproduced against main before this PR was opened:

- `air-vector-valid.json` + disclosure: exit 0, all checks pass.
- `air-vector-swapped.json` + disclosure: exit 1, `payer re-derivation mismatch (§4.3/§8.4)`.
- Both files standalone (no disclosure): exit 0 — the signatures are honest; only the disclosed-bytes comparison catches the swap.

The pair's role therefore changes from documenting a gap to guarding the rule. Vector JSON bytes are unchanged from the #17 publication; the SHA-256 values above still hold.
