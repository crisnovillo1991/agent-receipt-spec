# AIR pending receipt + settled attachment vectors (§4.3 through `attaches_to`)

Intended path: `test-vectors/contrib/pending-then-attachment/` (same layout as `test-vectors/contrib/payer-rederivation/`).

## What this tests

This is the flow production actually uses: a receipt issued with `payment.settlement_status: "pending"`, followed by a settlement attachment (`seq 1`, `attaches_to` = the receipt's entry hash) whose verbatim settle response carries the true `payer`. Since `182fe4d`, `verify_settle_disclosure` runs the draft-2 §4.3 payer comparison against the **paired receipt's** `payment.payer` when the attachment is checked with `--receipt` and `--settle-response` together.

| Files | Expected |
|---|---|
| `air-vector-attachment-valid.json` + `--receipt air-vector-receipt-valid.json` + `--settle-response settle-response.json` | PASS |
| `air-vector-attachment-swapped.json` + `--receipt air-vector-receipt-swapped.json` + `--settle-response settle-response.json` | FAIL (exit 1), `payer re-derivation mismatch (§4.3/§8.4)` |
| `air-vector-attachment-swapped.json` + `--settle-response settle-response.json`, without `--receipt` | PASS. The rule has nothing to compare against and stays silent. |
| either receipt standalone; either attachment with `--prev` its receipt | PASS (signatures and chain links are honest) |

The swapped receipt differs from the valid one only in `payment.payer` and `payment.pay_to`, which are exchanged. Its signature is regenerated because both fields are in the signed payload, and `parties[]` is unchanged. The two attachments differ only in `attaches_to`, `prev_entry_hash` (each points at its own receipt) and the signature. Both use the same disclosed bytes.

## Keys and synthetic identifiers

- Signing key: the repository test key, `test-vectors/KEY.txt` (`ed25519:ebVWLo/mVPlA`). It is public by design.
- payer `0xa11ce00000000000000000000000000000000001`, payTo `0xb0b0000000000000000000000000000000000002` (the synthetic pair from `contrib/payer-rederivation/`).
- transaction `0x63e25fa8e6705d03f1a812b88eb08a8f398a41615d0daefd4b26d1b8ba7b54d3` = `0x` + SHA-256 of the ASCII phrase `air-contrib:pending-then-attachment:test-transaction`.
- Amount `10000`, timestamps and all body and payload digests are synthetic. No production row, address or hash is used.

`settle-response.json` is the exact 169 UTF-8 bytes below, with no trailing newline. Its SHA-256 is `2632acef3470d6959ab509b54a713be9da0e5e2f2d3c9751b409fc5e7803fbce`, matching `settlement.settle_response_sha256` in both attachments:

```json
{"success":true,"transaction":"0x63e25fa8e6705d03f1a812b88eb08a8f398a41615d0daefd4b26d1b8ba7b54d3","network":"base","payer":"0xa11ce00000000000000000000000000000000001"}
```

Each entry file is the RFC 8785 canonical form (`canonical()` in `verifier/verify.py`) plus a final line feed, signed over the entry without `signatures`.

## Verification result

Against commit `182fe4d`:

- honest pairing (`--receipt` + `--settle-response`): exit 0.
- swapped pairing (`--receipt` + `--settle-response`): exit 1, `payer re-derivation mismatch (§4.3/§8.4): embedded payment.payer '0xb0b0000000000000000000000000000000000002' != disclosed payer '0xa11ce00000000000000000000000000000000001'`.
- swapped attachment with `--settle-response` and no `--receipt`: exit 0 (silent).
- all four entries standalone, and both attachments with `--prev`: exit 0.

Against commit `3d52edb`, before the fix, the swapped pairing with `--receipt` and `--settle-response` exits 0. The pair therefore fails on the code it guards against, so it is a regression guard and not decoration.

Cite as: SmartFlow Observatory, github.com/smartflowproai-lang
