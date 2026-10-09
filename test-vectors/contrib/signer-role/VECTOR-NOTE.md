# AIR §4.1 signer-role vectors

Intended path: `test-vectors/contrib/signer-role/` (same layout as `test-vectors/contrib/payer-rederivation/`).

## What this tests

This set pins the three-point scope for `SPEC-v0.3-draft.md` §4.1 (co-signatures) agreed in x402-foundation/x402#2922:

1. **Closed role vocabulary.** `signatures[].signer` (v0.2 §4.4, today "Role of the signing party (`"bridge"`, …)", open) takes values from the vocabulary v0.2 §4.1 already closes for `parties[].role`: `bridge`, `provider`, `payer`.
2. **Signer resolution.** Every signature resolves to exactly one `parties[]` entry with `role == signer` and `key_id == key_id`. `Party.key_id` is already defined in v0.2 §4.1 as "Key identifier if this party signs (§6)"; the pair (role, key_id) is the join the text already provides.
3. **Beneficiary relation, derived.** Resolved party `id` compared with `payment.pay_to` (lowercase). Not a field and not a validity rule. `pay_to` is issuer-attested in the current profile (draft-2 §4.3), so the derived relation carries that status.

All three receipts carry `spec_version: "0.3-draft-3"` (the v0.2 entry shape, inherited by the draft; see "Re-signed" below) with `payment.settlement_status: "pending"`. Every signature covers the same §5/§6 signing payload.

| File | Signatures | Expected under §4.1 (0.3-draft-3) |
|---|---|---|
| `air-vector-valid.json` | bridge, provider, payer, each resolving to its `parties[]` entry | PASS; derived beneficiary: bridge `false`, provider `true`, payer `false` |
| `air-vector-unresolved-signer.json` | as valid, but signature 2 claims `signer: "payer"` under a key that no `parties[]` entry lists | FAIL, reason `signer-unresolved` |
| `air-vector-role-outside-vocabulary.json` | signature 2 has `signer: "auditor"`, resolving to a `parties[]` entry with `role: "auditor"` and the same `key_id` | FAIL, reason `role-outside-vocabulary` |

The primary negative is `air-vector-unresolved-signer.json`. It differs from the valid file in only the `key_id`, `public_key` and `sig` of signature 2, so the signature itself is cryptographically valid over the §6 payload, and resolution is the only rule that fails. `air-vector-role-outside-vocabulary.json` is the optional second negative. It resolves cleanly, so only the vocabulary rule can reject it. Because it adds a `parties[]` entry, all three signatures are regenerated.

The vectors carry no provenance labels (such as "self-attested" or "payer-corroborated"). How much weight a role gets is consumer policy (draft-2 §2.6 line), not something the format records.

## Keys (test-only, public by design, never reuse)

- bridge: repository test key, `test-vectors/KEY.txt` (`ed25519:ebVWLo/mVPlA`).
- provider: seed = SHA-256 of ASCII `air-contrib:signer-role:provider-test-key` → `ed25519:OHiR+EPxUFmX`.
- payer: seed = SHA-256 of ASCII `air-contrib:signer-role:payer-test-key` → `ed25519:t9ST3CNdhk7Q`.
- unlisted: seed = SHA-256 of ASCII `air-contrib:signer-role:unlisted-test-key` → `ed25519:NKXaelm0otOd`.

Each file is the RFC 8785 canonical form of the entry plus a final line feed. To reproduce, build the core (entry without `signatures`), sign `canonical(core)` with each seed, and append the signatures in the order listed above. `canonical()` and `entry_hash()` are the functions in `verifier/verify.py`.

## Synthetic identifiers

- payer: `0xa11ce00000000000000000000000000000000001`, payTo: `0xb0b0000000000000000000000000000000000002` (the synthetic pair from `contrib/payer-rederivation/`).
- Request, response and payment-payload digests are SHA-256 values of synthetic test bytes. Amount `10000` is synthetic. No production row, address or hash is used.

## Verification result (original `0.2` signing, as first opened)

Tested against commit `182fe4d` (`verifier/verify.py`, unchanged):

- `air-vector-valid.json`: exit 0.
- `air-vector-unresolved-signer.json`: exit 0.
- `air-vector-role-outside-vocabulary.json`: exit 0.

Today's verifier passes both negatives. It checks every signature against the payload and checks `key_id` against `public_key`, but it does not read `signer`, and it does not enforce the `parties[].role` values that v0.2 §4.1 already lists. That gap is the reason for the pair. A probe of the three proposed rules, written against the text above and not part of the repository, passes the valid file and rejects each negative with its named reason.

## Re-signed 2026-10-06

Re-signed 2026-10-06 as spec_version 0.3-draft-3 per the maintainer ruling in #20 (verifier at fb70856). Only `spec_version` changed; the keys listed above are unchanged, and every signature was regenerated over the new §6 payload. Under `0.2` the verifier at `fb70856` reports both negatives as a §4.1 note with exit 0; under `0.3-draft-3` it rejects them.

- `air-vector-valid.json`: exit 0, `OK: all requested checks passed`.
- `air-vector-unresolved-signer.json`: exit 1, `FAIL: signature 2: signer 'payer' with key_id 'ed25519:NKXaelm0otOd' resolves to 0 parties[] entries, expected exactly 1 (§4.1)`.
- `air-vector-role-outside-vocabulary.json`: exit 1, `FAIL: signature 2: signer 'auditor' is outside the role vocabulary bridge|provider|payer (§4.1)`.

The verifier on `main` at `3ffe177` predates the 0.3 version dispatch and rejects all three files with `FAIL: unknown spec/spec_version` (exit 1). That is a version-dispatch result, not a §4.1 result.

Cite as: SmartFlow Observatory, github.com/smartflowproai-lang
