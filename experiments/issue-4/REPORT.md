# AIR ↔ invinoveritas — Interop Report (issue #4)

**Dates:** 2026-07-23 → 2026-07-25 · **Status:** completed, 4/4 both ways

## Parties & artifacts

- **invinoveritas** (babyblueviper1): pre-action verdict as signed NIP-01
  event (kind 30078), id `279fbf14…`, verdict `approve_with_concerns`
  over a toy interaction (weather lookup paid via x402), decision_ref
  `sha256:58edaf53…`.
- **AIR** (this repo): receipt `c697ec06…` for the same toy interaction,
  binding the verdict under `meta.authorization` via the gateway's
  `X-AIR-Authorization` feature; mock payment settled.

## Results

| Check | By them | By us |
|---|---|---|
| Verdict: NIP-01 id recompute | 5/5 (their verifier) | PASS (relay-native bytes) |
| Verdict: BIP340 schnorr | PASS | PASS (pure-Python, zero deps) |
| Verdict: decision_ref recompute | PASS | PASS (JCS + nulls-included rule) |
| Receipt: standalone verify | `OK` (our verifier) | PASS |
| Receipt: from-scratch recompute | PASS (own code, `cryptography`) | — |
| Receipt: adversarial tamper (launder verdict) | signature correctly INVALID | signature correctly INVALID |

Both directions verified by both parties, from two different codebases each.

## Findings (all resolved)

1. **Transported-object inconsistency**: first pasted event carried
   truncated `content` with original `id`/`sig` — caught by refusing to
   reproduce the id. Root cause: transcription.
2. **Second truncated paste** while correcting the first.
3. **Markdown whitespace collapse**: double spaces around `·` rendered to
   single (char 1784) — invisible diff, hash-breaking. Root cause:
   comment-thread rendering.

**Lesson promoted to the spec (§9):** prose is not a transport for signed
artifacts; bindings SHOULD carry an exact content hash plus a
checksum-stable retrieval pointer. Resolution path that worked:
relay-fetch → committed raw file → checksum match → 4/4.

## What this establishes — and what it doesn't

Cross-verification between two implementations establishes **agreement and
interop correctness**, not weight: evidence for readers who already have a
path to either party, never a bootstrap (per clai-mach, ERC-8004 thread).
The `meta.authorization` binding is load-bearing under adversarial
verification; a first-class `authorization` field is a v0.3 candidate
(issue #6), with transport discipline fields per 0xbrainkid's proposal.
