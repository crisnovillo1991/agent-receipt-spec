# Interop experiment — issue #4 (COMPLETED)

Pre-action verdict (invinoveritas, NIP-01 signed event) bound into an AIR
receipt under `meta.authorization`. Both directions verified by both
parties, two independent codebases each. Full report: `REPORT.md`.

- `event.json` — the verdict event, **byte-identical to the relay-native
  file** committed by the issuer (sha256
  `8e6030b4e9f7e6a9cdb4e3f7896f6a37cdf8eed39af4a93e54cec3213f544654`).
  Canonical sources: `wss://nos.lol` / `wss://relay.primal.net` (id
  `279fbf14…`) or the raw URL in their conformance repo.
- `verify_their_side.py` — zero-dep independent verification: BIP340
  schnorr (pure Python), NIP-01 id recompute, decision_ref recompute.
  Result against relay-native bytes: **4/4 PASS**.
- `air-receipt.json` — the AIR v0.2 receipt binding the verdict
  (entry_hash `c697ec06…`). Verify: `python3 ../../verifier/verify.py
  air-receipt.json`.

Finding log (all resolved): three consecutive transport failures taught the
same lesson — (1) truncated transcription (fields dropped), (2) a second
truncated paste, (3) markdown whitespace collapse (`  ·  ` → ` · ` at char
1784: invisible to eyes, fatal to hashes). **Prose is not a transport for
signed artifacts.** See SPEC §9 and issue #6.
