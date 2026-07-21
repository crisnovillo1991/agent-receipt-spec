# Contributing

- **Normative changes** (data model, canonicalization, signing, chaining):
  open an issue first. Discussion happens in the open; changes land with a
  version bump and updated test vectors in the same PR.
- **Typos / clarifications**: PRs welcome directly.
- **Test vectors are part of the contract.** Any change to `SPEC.md` that
  alters bytes on the wire MUST regenerate `test-vectors/` via
  `tools/generate_vectors.py` and update `expected.json`.
- **Versioning promise**: `0.x` may break between minors (draft phase);
  breaking changes always bump `spec_version` inside receipts so verifiers
  can dispatch. From `1.0`, breaking changes require a new major.
- Independent implementations in other languages are the best possible
  contribution — open an issue to get listed.
