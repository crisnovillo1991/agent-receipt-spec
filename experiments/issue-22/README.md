# Interop experiment — issue #22: SAR primitive vectors, AIR-side run

An AIR-side run of the SAR primitive corpus pinned by its author at
`nutstrut/default-settlement-verifier@8efd6528be234e66ff976c0a01dddabbf05671e7`
(`evidence/sar-primitive-vectors-20261006/`, 27 cases).

**Claim ceiling: `PRIMITIVE_COMPATIBILITY_ONLY`.** Nothing here establishes
AIR↔SAR composition, semantic equivalence, native cross-format verification,
interchangeable receipt formats, adoption, deployment or dependency.

## What was run

- `air_side_run.py` reads the corpus's `vectors.json` **as data**. None of
  the capsule's code is executed.
- Every input case goes through the AIR reference verifier's own
  `loads_strict` → `canonical` → SHA-256; every signature case through the
  Ed25519 path the verifier uses (plus its small-order check).
- The corpus is **not vendored**. The runner pins it by SHA-256 and refuses
  to run on any other bytes:
  - `vectors.json` — `9692dfc5bd59cbbf6b8cad8f6a309786b3a07194a718c2952dd7506344db155f`
  - `fixtures/xmandate-generated-sar-receipt-20260605T215954Z.json` — `538b6d7bfd3ff215c3156c3085c47b636ac2c4a473617799f4f96cab682f3236`
- AIR side: `verifier/verify.py` sha256
  `f11798e5e6ed889d6d852973b272de611fcddae5c060222bc732e8016ebd7bf0`
  (commit `e34f491`). The hash is recorded inside `air_side_results.json`.

Two things are reported separately on purpose: what the AIR **primitives** do
with an input, and whether that input would be **admissible inside an AIR
entry** (profile). A profile rejection is not a primitive disagreement.

## Reproduce

```
B=https://raw.githubusercontent.com/nutstrut/default-settlement-verifier/8efd6528be234e66ff976c0a01dddabbf05671e7/evidence/sar-primitive-vectors-20261006
curl -sSO $B/vectors.json
curl -sSO $B/fixtures/xmandate-generated-sar-receipt-20260605T215954Z.json
python3 experiments/issue-22/air_side_run.py verifier/verify.py \
    vectors.json xmandate-generated-sar-receipt-20260605T215954Z.json out.json
cmp out.json experiments/issue-22/air_side_results.json
```

Needs Python 3.10+ and `cryptography` (the verifier's only dependency). The
output is deterministic: no timestamps, no environment data.

## Result

Input cases (16):

| cases | AIR primitive result | vs SAR stack (`jcs 0.2.1`) |
|---|---|---|
| INT-1, INT-2, UTF16-1, SURR-3, NUM-1 | canonical bytes + SHA-256 | identical bytes, identical digests |
| SURR-1, SURR-2 | parse accepts, canonicalization rejects | both reject, same stage |
| DUP-1 | rejected at parse (duplicate key) | different outcome — SAR: silent last-wins |
| NUM-2 … NUM-5 | rejected, integer outside ±(2^53−1) | different outcome — AIR matches the corpus's `rfc8785 0.1.4` column |
| FLOAT-1 … FLOAT-3, REUSE-1 | rejected | profile difference |

Signature cases (11): all 11 agree with the corpus's `expected_verify`. For
ED-2 the AIR side derives the preimage itself (SHA-256 of its own canonical
bytes of INT-2), re-derives test key 1 from the published label, and
re-signing reproduces the corpus signature byte for byte.

**Shared input domain** — integer-only JSON, |n| ≤ 2^53−1, no duplicate keys,
UTF-8-encodable strings. Inside it, canonical bytes, SHA-256 and Ed25519
verification agree on every case exercised (5 canonicalization cases, 11
signature cases). Outside it the two stacks differ, and the differences are
recorded, not normalized away:

- **Duplicate keys** are a parser-policy difference: AIR rejects; the SAR
  Python path keeps the last value.
- **|n| > 2^53−1** is outside the shared domain, not a byte-comparison
  failure. On the SAR stack 2^53 and 2^53+1 produce the same bytes.
- **Floats**: the AIR canonicalizer has no number serializer beyond integers,
  so on the float cases AIR is a reject, **not an independent confirmation**
  of the SAR bytes. The REUSE-2 signature cases were therefore verified over
  the corpus's pinned digest, not over a preimage AIR derived.
  REUSE-2-MUT-FIELD is defined through the SAR portable reader, which was not
  run; the runner checks the byte-level equivalent and labels it as such.
- **Signing convention**: SAR signs the 32-byte SHA-256 digest of the
  canonical bytes; AIR signs the canonical bytes directly. Distinct by
  design; ED-2-MUT-CONVENTION keeps the two from being confused.

## What the corpus found on the AIR side

- **SURR-2 → verifier bug, fixed.** A lone surrogate in an object *key*
  outside the signed payload was accepted with every signature valid and no
  canonical form. Fixed in `e34f491`, pinned as
  `test-vectors/invalid/23-v02-lone-surrogate-key.json`.
- **FLOAT-2 → open spec question (draft 3).** §5 forbids floats without
  saying whether that is defined over source tokens or parsed values: the
  reference verifier rejects `{"v":1.0}`, a `JSON.parse`-based stack cannot
  tell it from `{"v":1}`. No vector pins it yet.

Files: `air_side_run.py`, `air_side_results.json` (per-case output),
`SHA256SUMS`.
