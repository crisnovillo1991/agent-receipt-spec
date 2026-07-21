# Agent Interaction Receipt (AIR)

**A verifiable, content-free receipt for machine-to-machine interactions.**

Status: **v0.1 draft — request for comments.**

When autonomous agents transact with strangers — over [x402], A2A, MCP or any
other rail — there is no neutral record of what actually happened. AIR is a
small, boring answer to that: one signed JSON document per interaction that
binds together the request digest, the response digest, the payment that
authorized it, and a position in a tamper-evident per-session hash chain.

Design goals, in one breath: **verifiable offline by anyone** (every public
key travels inside the receipt), **content-free** (hashes commit to bodies;
plaintext can stay encrypted elsewhere and be disclosed only in a dispute),
**rail-agnostic** (v0.1 ships an x402 payment profile; others fit the same
structure), and **trivially portable** (a strict, float-free subset of
canonical JSON — reimplementable in any language in an afternoon).

## Verify a receipt in 30 seconds

```bash
pip install cryptography
python verifier/verify.py test-vectors/valid/02-paid-call-seq0.json
python verifier/verify.py test-vectors/valid/03-paid-call-seq1-chained.json \
       --prev test-vectors/valid/02-paid-call-seq0.json
python verifier/verify.py test-vectors/invalid/10-tampered-amount.json  # FAILs
```

The verifier is ~120 lines, imports nothing from any vendor, and never
touches the network. That is the point: trusting a receipt must not require
trusting its issuer's code, database, or continued existence.

## What's in this repo

| Path | What |
|---|---|
| [`SPEC.md`](SPEC.md) | The normative specification (data model, canonicalization, signing, chaining, verification, security considerations). |
| [`verifier/verify.py`](verifier/verify.py) | Reference standalone verifier (MIT). |
| [`test-vectors/`](test-vectors/) | Normative-companion vectors: 3 valid, 3 invalid, with [`expected.json`](test-vectors/expected.json) recording every hash and outcome. Regenerate deterministically with [`tools/generate_vectors.py`](tools/generate_vectors.py). |

Reference gateway implementation (MCP paywall that emits AIR receipts per
call): *link pending — `agentbridge`*.

## What a receipt proves — and what it doesn't

A v0.1 receipt proves that, at issuance, the holder of the issuing key
attested to this exact (request-hash, response-hash, payment) triple at this
chain position. It does **not** prove the response is *true*, that the issuer
is honest, or the real-world identity behind a key. Those belong to the
layers above: validation (re-execution, TEE attestation), reputation, and
identity registries (e.g. ERC-8004-style). AIR is the evidence artifact those
layers consume — deliberately nothing more.

## Feedback wanted (v0.1 → v0.2)

1. **Canonicalization (§5):** we chose a strict float-free subset of RFC 8785
   over full JCS. Is the tradeoff (portability vs. expressiveness) right?
2. **Co-signatures (§6, §11):** the cleanest scheme for provider/payer
   counter-signing without adding a round trip to the hot path.
3. **Salted digests (§9):** should salted body hashing be the default in
   v0.2, given brute-forceable low-entropy bodies?
4. **Anchoring profile (§7):** minimal Merkle-root anchoring format that
   works for both on-chain and RFC 3161 targets.

Open an issue — spec changes happen in the open. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Specification text: CC-BY-4.0. Code (verifier, tools): MIT. Interoperable
receipts are the point — implement this without asking anyone.

[x402]: https://www.x402.org
