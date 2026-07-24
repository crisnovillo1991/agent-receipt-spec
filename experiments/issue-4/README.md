# Interop experiment — issue #4

Pre-action verdict (invinoveritas, NIP-01 signed event) bound into an AIR
receipt under `meta.authorization`. Artifacts:

- `event.json` — their signed verdict event, as posted on issue #4.
- `verify_their_side.py` — zero-dep independent verification: BIP340 schnorr
  (pure Python), NIP-01 id recompute, decision_ref recompute per their
  declared preimage rule. Run: `python3 verify_their_side.py event.json`
- `air-receipt.json` — the AIR v0.2 receipt for the toy interaction with the
  verdict bound. Verify: `python3 ../../verifier/verify.py air-receipt.json`

Finding log: NIP-01 id not byte-reproducible from comment-transported JSON
(sig + decision_ref verify); awaiting raw event bytes to close 4/4.
