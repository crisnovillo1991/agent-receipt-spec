# air-evidence-ref

Reference implementation of the **AIR Evidence Profile 0.1** — the forensic
evidence layer for agent transaction receipts: typed mandates, cross-signed
receipts, a Certificate-Transparency-style custody chain, and a deterministic
claims adjudicator (D1–D6).

All example entities are fictitious (`.example` domains).

## What this demonstrates

A liability claim over an autonomous agent's transaction, resolved **by a
pure function over signed data** — no human interpretation:

```
mandate (typed constraints, principal-signed)
  → receipts (agent + counterparty + witness signed, hash-chained)
  → Merkle-anchored log (tamper-evident, third-party verifiable)
  → claim → adjudicator D1–D6 → signed verdict with machine-readable violations
```

## Layout — spec section to module

| Spec | Module |
|---|---|
| §3 Conventions (JCS, hashing, signatures) | `air_evidence/canonical.py`, `air_evidence/crypto.py` |
| §4 Mandate | `air_evidence/mandate.py` |
| §5–§9 Evidence blocks & envelope | `air_evidence/receipt.py` |
| §10 Chain of custody & anchoring | `air_evidence/chain.py` |
| §11–§12 Adjudication & claims | `air_evidence/adjudicator.py` |
| HTTP facade | `air_evidence/api.py` |
| §13 Worked example, live | `demo/simulate_claim.py` |
| Conformance tests (one per verdict) | `tests/test_adjudication.py` |

## Run it

```bash
pip install cryptography fastapi uvicorn pytest httpx

# the section-13 incident, end to end (3 scenarios)
python -m demo.simulate_claim

# conformance suite
python -m pytest tests/ -q

# HTTP API + visual console
uvicorn air_evidence.api:app --reload
```

## Visual console

With the server running, open **http://127.0.0.1:8000/** — a single-file,
zero-dependency evidence console served by the same process as the API:

- the mandate's typed constraints and a live cumulative-spend bar,
- the receipt chain drawn as an actual chain (each link labeled with its
  `prev_receipt_hash`; tampering visibly breaks the link),
- one-click actions: issue in-mandate / approved / unapproved / §13-incident
  receipts, anchor the log, tamper the last receipt, reset the world,
- a **File claim** button per receipt that runs the real D1–D6 adjudicator
  and renders the signed verdict: checks, stamp, and the violations table
  (expected vs. actual).

Swagger for the raw API stays at `/docs`. The console talks to `/demo/*`
endpoints that hold a fictitious cast server-side (keys never touch the
browser).

Expected demo output (abridged):

```
A (in-mandate)        -> WITHIN_MANDATE
B (section-13 breach) -> EXCEEDED_MANDATE (3 typed violations, auto-resolved)
C (tampered evidence) -> INVALID_EVIDENCE
```

## Design notes

- **No floats anywhere.** Amounts are integers in minor units; the
  canonicalizer *rejects* floats, so a non-conforming object cannot even be
  hashed. This removes the hardest part of RFC 8785 (ECMAScript number
  serialization) while staying exactly JCS for the remaining types.
- **Signatures cover the canonical body without `signatures`**, so agent,
  counterparty and witness all sign the identical message.
- **Fail-safe adjudication**: a constraint field the adjudicator does not
  recognize yields `INDETERMINATE` (human review), never a silent pass.
- **Tampering is triply fatal** (scenario C): mutating a logged receipt breaks
  its own hash, all three signatures, and its anchored Merkle path at once.
- The demo intentionally found that the spec's original worked example
  under-counted: the ARS 780,000 purchase violates the cumulative cap too,
  not just the per-tx cap and the approval threshold. Spec §13 now lists all
  three. Reference implementations exist to catch exactly this.

## Reference-only shortcuts (do not deploy as-is)

- Keys in memory; DID resolution is an in-process registry (no did:web fetch,
  no key validity windows or revocation).
- The anchor is a log-operator-signed local timestamp standing in for
  RFC 3161 TSA responses / a public-ledger transaction (§10.2).
- Stores are in-memory and single-process; the API has no authentication and
  signs claim intake server-side.
- Merkle trees are rebuilt per proof; a real log persists levels
  incrementally and serves consistency proofs between anchors (RFC 6962).

## License

To be defined by the AIR project (suggested: Apache-2.0, matching open
standards practice).
