# Agent Interaction Receipt (AIR) — Specification v0.3 — DRAFT 2

**Status: DRAFT.** Entries produced against this document MUST use
`spec_version: "0.3-draft-2"`; the value `"0.3"` is reserved for the frozen
release. The freeze is gated by two live dry-runs (§6): the snapshot side
**closed** against the draft-1 rulings (SmartFlow `/quality`, live bytes,
17/17); the verdict side (invinoveritas `/ledger`) remains open and lands
against this draft.

v0.3 entries inherit **§1–§9 of v0.2 unchanged** except as amended here.
Design record: issue #14 plus the anchoring and integration threads in
x402#2922 — every amendment below was purchased with a binding, an
incident, or a shipped production change, credited inline and in §5.
Change process: disagreements become issues; findings become vectors.
Draft-1 → draft-2 delta: nineteen amendments; see the changelog.

---

## 1. Scope of v0.3

| Area | Status in draft 2 |
|---|---|
| First-class `authorizations` field | **Specified** (§2) — restructured per trust model |
| Anchoring profile | **Specified** (§3) — graduated from skeleton; A1–A3 resolved |
| x402 profile amendments (§8.4 payer rule) | **Specified now** (§4.3) |
| Provider/payer co-signatures | Scoped, design pending (§4.1) |
| No-omission interface | Scoped, design pending (§4.2) |

---

## 2. The `authorizations` field

### 2.1 Placement and envelope

A v0.3 entry MAY carry a top-level field `authorizations`: an **array** of
binding objects, included in the signed core (canonicalized and signed per
v0.2 §5–§6). Entries without it remain valid.

- The array, when present, MUST contain **at least one element**. "No
  bindings" has exactly one encoding: the absent field. An empty array is
  non-conforming — two canonical forms for the same claim is the disease
  this format exists to not have.
- Two elements MUST NOT carry the same `authorization_sha256` — the same
  verified bytes bound twice is one claim wearing two entries. The same
  `scheme` with different `decision_ref`s is legal: two judgments from one
  system are two artifacts.
- Array rather than single object because one interaction may bind
  artifacts of different classes under one discipline — proven by a
  dry-run entry binding a trust-score snapshot and a pre-action verdict
  together, 34/34 checks (E8).

Migration: v0.2 `meta.authorization` maps field-for-field into one element
(with `trust_model` added and `verifier_key_ref` renamed — see §2.2).
Verifiers targeting 0.3 MUST accept both during the draft period.

### 2.2 Binding object — common core + per-trust-model set

Every binding carries the **common core**:

| Field | Type | Meaning |
|---|---|---|
| `scheme` | string | Verifier/schema name of the bound artifact (e.g. `invinoveritas.verdict_proof.v1`). |
| `decision_ref` | string | Content-addressed identifier of the artifact, as defined by `scheme`. |
| `trust_model` | string | `issuer_signed` \| `qtsp_qualified` \| `chain_anchored`. **Required.** Declares the verification obligation and the authority surface (§2.6). |
| `authority_ref` | string \| null | The authority reference, interpreted per `trust_model`: a signing-key reference (`issuer_signed`), a trusted-list entry reference (`qtsp_qualified`), or a chain+registry pair in CAIP-style form, e.g. `eip155:8453:0x49fe…` (`chain_anchored`). Replaces draft-1's `verifier_key_ref`; never an authority *claim* (§2.6). |
| `axes` | object | Axis declaration — §2.4. |

Plus the **conditional set, keyed on `trust_model`** — never on transport,
because two transports can share a trust model and one transport can carry
two, and because the required set is a function of the *verification
obligation*, which is a function of the trust model, never of how bytes
happened to move:

**`issuer_signed` and `qtsp_qualified`** (artifact-byte models — the
verifier obtains and checks the artifact's own bytes):

| Field | Type | Req |
|---|---|---|
| `authorization_sha256` | string (64 **lowercase** hex) | yes — MUST. SHA-256 of the exact bytes the binding party verified at binding time (§2.3). |
| `authorization_uri` | string \| null | yes unless bundled — checksum-stable retrieval pointer; `null` only with `transport_hint: "bundle"`. |
| `transport_hint` | string | `raw_url` \| `relay_event` \| `bundle` \| `other` — a retrieval detail, existing only where retrieval exists. |

**`chain_anchored`** (envelope model — the artifact is a locally
constructed statement about chain state):

| Field | Type | Req |
|---|---|---|
| `anchor` | object | yes — the canonical envelope (§3.2): `{chain_id, registry, tx_hash, ref, anchored_by, block, timestamp, mechanism}`. |
| `locator` | string \| null | optional — courtesy pointer (e.g. an explorer URL) for humans; carries no verification weight. |

`authorization_uri`, `authorization_sha256` and `transport_hint` are
**excluded** for `chain_anchored`: their presence is non-conforming.
Hashing bytes you constructed and carry inside your own signature is
self-attestation with no verification value — the entry signature already
covers the envelope. A conforming checker rejecting a valid anchor for a
"missing hash" would be a false-invalid manufactured by table uniformity;
this table exists so that bug is impossible, and so the conflicting pair
(`transport_hint` present with `trust_model: "chain_anchored"`) is not
ambiguous but **illegal**, checkable in those words.

(Original schema shape: 0xbrainkid. Trust-model keying: vaaraio, with the
mechanical two-answers argument by SmartFlow. Envelope split: giskard09,
completed by SmartFlow.)

### 2.3 Transport discipline (artifact-byte models)

Content-addressing at issuance and byte-integrity at point of use are
different failure modes: all three documented transport failures happened
to artifacts *already correctly content-addressed at the source*.
`authorization_sha256` therefore attests **"these are the bytes I verified
before binding"** — never "this is what the issuer published" — and is
MUST for both artifact-byte models. Prior art, live: `content_sha256`
(invinoveritas, `proof_signing.py` @ `dc12cb2`). Prose remains not a
transport (v0.2 §9); inline copies are illustrative only.

### 2.4 Axis declaration

Every documented failure in this project's record is a **cross-axis
substitution** wearing a plausible field name: issuance time answering a
freshness question; processing status answering a settlement question;
structural validity answering an authority question; "verdict issued"
answering "verdict still holds". A bound artifact MUST declare its
coverage of all three axes; an undeclared axis is an invitation to
substitute.

- **precedence** — *did this exist no later than T?* Frozen on landing.
  Encoding: `null` or `{"field": "<artifact field>"}`.
- **freshness** — *is this still good now?* Consumer-side, and it carries
  **its own named inputs** (a single `field` slot cannot express a
  three-input function — proven by binding E11, which was fully
  conformant under draft 1 with freshness uncomputable from its own
  declaration). Encoding: `null`, or
  `{"observed_at_field": "...", "max_age_field": "...", "flavor": "computable"}`, or
  `{"query_field": "...", "flavor": "re_verifiable"}` (the live-query
  target; `observed_at_field` optional). The two flavors want different
  shapes — the argument that settles per-axis objects over a flat list.
- **correctness** — *was the claim right?* Encoding: `null` or
  `{"field": "<outcome-evidence field>"}`.

All three keys MUST be present. Omission is not a declaration: only
**present-and-null** is visible non-coverage; an absent key is a different
canonical form and a different entry hash for the same claim, and it
fails. (Axes and declaration rule: SmartFlow. Precedence/freshness frame
and the two-flavor distinction: invinoveritas, ref. liveness-bench.)

### 2.5 Artifact-class requirements

**Point-in-time artifacts** (verdicts, one-shot judgments): MUST cover
`precedence`; freshness and correctness MAY be null — a verdict that
cannot say "still holds" must say so visibly.

**Rolling-snapshot artifacts** (trust scores, quality metrics): the bound
bytes MUST carry, as fields of the artifact itself:

- (a) an **observation timestamp** distinct from issuance and serving
  time;
- (b) the **declared cadence** (maximum age);
- (c) a **named state field** with the closed vocabulary
  `fresh | stale | unavailable`. Cause (e.g. `error`, `not_found`) stays
  in scheme-specific fields: freshness class and failure cause are
  different questions — the axis discipline one level down.

The (a) and (b) slots MUST be **present in every state**, holding null
when there is no observation: present-and-null is what makes non-coverage
visible; absent is what makes a consumer reach for the nearest timestamp.
Reference shapes (shipped, live): the `/quality` degraded and stale
payloads — `fetched_at` / `max_age_seconds` / `served_at` distinct, state
named — whose capture-specific hashes are the (a)-distinct-from-serving
slot doing its job. (Requirements, incident evidence and reference
payloads: SmartFlow. The stale case was unimplemented in production until
writing the binding surfaced it — the gate working on both sides of the
seam.)

### 2.6 Authority is consumer-side — three surfaces

`authority_ref` carries identification and discovery, never an authority
claim. Authority is a downstream consumer-policy lookup keyed by the
**scheme-defined authority surface**, selected by `trust_model`:

- `issuer_signed` → a signing key;
- `qtsp_qualified` → a trusted-list entry, resolved against the
  applicable published list;
- `chain_anchored` → the `(chain_id, registry)` pair — there is no key,
  and there is nothing of the operator's to trust.

Consumers MUST distinguish, and MUST NOT collapse:
`structurally_invalid` · `structurally_valid_zero_authority` ·
`valid_and_authorized`. The middle state is REQUIRED to be representable.
The fixture-flip generalizes across all three surfaces: identical bundle,
classification flips solely when the consumer's policy lists the key /
list entry / registry pair. Each surface owes a fixture, not just the
first. **Recomputability rule** (after pipavlo82): any published
classification MUST carry the trust-policy identifier it was computed
against.

### 2.7 Verification procedure

**Steps 1–5 — structural, deterministic, offline for every trust model,
and MANDATORY for entry validity whenever `authorizations` is present**
(the field lives in the signed core; a malformed binding is a
non-conforming entry):

1. Obtain the artifact: retrieve bytes per the conditional set
   (`issuer_signed` / `qtsp_qualified`), or construct the canonical
   envelope locally from the binding's declared fields
   (`chain_anchored`, §3.2). No network access in either case — retrieval
   for artifact-byte models happens against bytes the verifier already
   holds or fetched out-of-band.
2. For artifact-byte models: `SHA-256(bytes)` MUST equal
   `authorization_sha256` — mismatch is a **transport failure, not a
   signing failure**. For `chain_anchored`: recompute the envelope's
   canonical bytes from its declared fields (pure local recompute).
3. Verify the artifact per `scheme` (its own signature/id rules), where
   the scheme defines any.
4. Check the `axes` declaration: every declared field MUST exist in the
   artifact. A declared axis may reference a **null-valued** field only
   when the artifact's `state` is a degraded state that licenses the null
   (§2.5) — so an issuer overclaiming coverage is mechanically
   distinguishable from an honest all-null declaration.
5. **Coherence table** — the verifier reads `state` directly (format,
   not consumer policy: everything computable from the bytes belongs to
   the format; a closed vocabulary verification doesn't read is
   decoration):
   - `state: "fresh"` ⇒ (a) and (b) MUST be value-bearing;
   - `state: "stale"` ⇒ (a) and (b) MUST be value-bearing (staleness must
     be recomputable from the observation);
   - `state: "unavailable"` ⇒ (a) and (b) MUST be present-and-null.
   Step 5 checks structural coherence only — never the freshness
   inequality itself.

**Step 6 — the consumer-judgment step.** Everything network- and
policy-shaped, consolidated and named: compute declared freshness
(`computable`: a pure function of observation, cadence and the consumer's
clock; `re_verifiable`: a live round trip to the declared query target);
check **anchoring existence** for `chain_anchored` (§3.4), with
`confirmation_window` as a consumer-policy input — an entry resolving
differently before and after inclusion is a policy evaluation changing
with the world, not verification instability; classify **authority** per
§2.6 against the consumer's own policy. Step 6 is never part of format
validity, and it is the only step that may touch a network. The v0.2
offline claim is thereby a theorem, not a promise: structural
verification never touches a network, for any trust model.

**Insertion into §8**: verifiers following v0.2 §8 run this procedure as
a named sub-procedure **between §8 steps 7 and 8** (after signature and
chain checks, before the x402 mapping), so a §8 verifier reaches it by
construction.

### 2.8 Worked examples

**(1) Point-in-time verdict** — the issue-4 interop binding, upgraded
(real artifacts):

```json
"authorizations": [{
  "scheme": "invinoveritas.verdict_proof.v1",
  "decision_ref": "sha256:58edaf5325483774affa674f294675b796ff30a332acca10f889125564d371ef",
  "trust_model": "issuer_signed",
  "authority_ref": "nostr:6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7",
  "authorization_uri": "https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/main/events/279fbf14007edf171d58a1876f036ef6564bd6316a00d1c10d6495c9cdc60ef6.json",
  "authorization_sha256": "8e6030b4e9f7e6a9cdb4e3f7896f6a37cdf8eed39af4a93e54cec3213f544654",
  "transport_hint": "raw_url",
  "axes": {
    "precedence": {"field": "created_at"},
    "freshness": null,
    "correctness": null
  }
}]
```

**(2) Rolling snapshot** — `/quality`-shaped, against the shipped
reference payloads:

```json
{
  "scheme": "smartflow.quality_score.v1",
  "decision_ref": "sha256:<snapshot-preimage-hash>",
  "trust_model": "issuer_signed",
  "authority_ref": "ed25519:<key-id>",
  "authorization_uri": "https://<host>/quality/snapshots/<id>.json",
  "authorization_sha256": "<lowercase sha256 of the exact capture bytes>",
  "transport_hint": "raw_url",
  "axes": {
    "precedence": {"field": "fetched_at"},
    "freshness": {"observed_at_field": "fetched_at",
                   "max_age_field": "max_age_seconds",
                   "flavor": "computable"},
    "correctness": null
  }
}
```

**(3) Chain anchor** — the envelope model, with the real Base mainnet
anchor (independently verified: status success, block 48545657):

```json
{
  "scheme": "giskard09.anchor_registry.v1",
  "decision_ref": "sha256:e2883741562df2096aec27ce2ffa26e157d2898ac9ec444d245b39b6c8f0efea",
  "trust_model": "chain_anchored",
  "authority_ref": "eip155:8453:0x49feca52bc634a9ab773226d16619dec547794aa",
  "anchor": {
    "chain_id": "eip155:8453",
    "registry": "0x49feca52bc634a9ab773226d16619dec547794aa",
    "tx_hash": "0x8702287dca01fb5faa76ec8c95b67322d2f685e634747ba9177082bd72c50a39",
    "ref": "0xe2883741562df2096aec27ce2ffa26e157d2898ac9ec444d245b39b6c8f0efea",
    "anchored_by": "0xdcc84e97 — truncated; full address in the registry event log",
    "block": 48545657,
    "timestamp": 1783880661,
    "mechanism": "anchor_registry_v1"
  },
  "locator": "https://basescan.org/tx/0x8702287dca01fb5faa76ec8c95b67322d2f685e634747ba9177082bd72c50a39",
  "axes": {
    "precedence": {"field": "timestamp"},
    "freshness": null,
    "correctness": null
  }
}
```

The two nulls are load-bearing in (1) and (3): a precedence-only artifact
visibly claims nothing about "still holds" or "turned out right".

---

## 3. Anchoring profile

### 3.1 Purpose and limits

Anchoring turns equivocation (v0.2 §7) from "detectable when surfaced"
into "concealable never". An anchor is **precedence-only**: it proves an
identifier existed no later than a block, and MUST NOT be read as
freshness or correctness — consumer-side in every design (pin held by
three implementations). Precedence itself comes in **trust models**, not
just transports: a qualified timestamp (supervised QTSP, statutory
presumption, offline verification against a published list) and an
on-chain anchor (no named party, no jurisdiction) answer the same axis
question under different failure modes and different dispute venues —
*neither dominates; court vs. protocol* (invinoveritas). `trust_model`
carries that declaration.

### 3.2 The canonical envelope

For `chain_anchored`, the bound artifact is the **canonical envelope**: a
locally constructed statement, carried inline in the binding (§2.2),
recomputable by any third party from the transaction receipt alone.
Encoding profile — the lesson from one layer up applied down:

- JCS per §5's RFC 8785 profile over the fixed field table
  `{chain_id, registry, tx_hash, ref, anchored_by, block, timestamp, mechanism}`;
- all hex **lowercase**, `0x`-prefixed; addresses lowercased (EIP-55 is a
  display checksum, not a canonical form — exactly as mixed-case sha256
  was a display habit and not a digest);
- integers as JSON integers under the §5 2^53−1 bound (block heights and
  unix timestamps sit comfortably inside it);
- `mechanism` from a closed vocabulary (`anchor_registry_v1`;
  extensions register here).

Prior art cited, not paraphrased: `anchoring-precedence-ref-v1`
(argentum-core, stable v1.0) — `canonical_envelope` as a pure JCS/SHA-256
recompute over declared fields, `anchoring_existence` as the separate,
explicitly network-dependent invariant, never conflated.

### 3.3 Granularity — the two-layer pattern

`anchor(bytes32)` accepts a single ref or a Merkle root over a batch —
the primitive is indifferent, so the profile specifies **both layers**
rather than choosing: an immediate per-action anchor, plus an optional
epoch-level Merkle rollup. Cost/granularity is a deployment choice
(measured per-action fee on Base: $0.000255).

### 3.4 Anchoring existence (step 6)

The verification surface is the registry address plus the transaction
hash — a direct chain query, `status == 1` confirming inclusion, nothing
of any operator's to trust. No receipt within the consumer's
`confirmation_window` resolves to FAILED *as a policy outcome*, never as
format invalidity. Envelope coherence is checkable without a node;
anchoring existence is not, and the text says so plainly: a precedence
claim about a chain is checked against the chain, or the consumer is
trusting someone's attestation of the chain — a different trust model,
and it MUST be declared as one.

### 3.5 Circularity

An entry cannot carry the anchor of its own `entry_hash` — the hash
covers the field that would carry it. Self-anchoring references travel in
the **successor entry** (the session chain doubles as the
anchor-reference transport: seq N+1 binds the anchor of seq N) or in an
external index.

---

## 4. Scoped, design pending — plus amendments effective now

**4.1 Co-signatures.** Provider/payer signatures over the same payload
(v0.2 §6 admits appended co-signatures); open design: contract signers
(ERC-1271-style) carrying **account references instead of raw keys** —
the same authority-surface generalization as §2.6, arriving at the
signature layer. §4.4's `alg: "ed25519"` and §6's raw-key `key_id`
consistency cannot hold for contract signatures; an alg registry is the
anticipated shape. First reviewer committed: SmartFlow Observatory.

**4.2 No-omission interface.** Per v0.2 §7, interfacing with — not
reinventing — the obligation-record prior art (`issuance_record.v0` +
skip records, pipavlo82), including the answered / provably-overdue /
undeterminable trichotomy. The evidence-class taxonomy now has three
named members (credit: KKallias): what a payment bought (receipts), what
policy did and why (pre-decision guardrails — out of scope as a section,
bindable via §2 the moment such decisions are signed), what was owed and
what was skipped (obligation records). A receipt corpus structurally
cannot contain the payments that were correctly prevented; that evidence
lives in the adjacent layers, reached through these interfaces.

**4.3 x402 profile amendments — effective in draft 2, carried into the
v2 profile:**

- **Payer re-derivation.** When the disclosed settle response carries a
  `payer` field, the embedded `payment.payer` MUST match it (addresses
  compared lowercase). Mismatch is a re-derivation failure (§8.4).
  Evidence: a shipped allowlist bug in which the settle response's
  `payer` — the sender, one's own wallet — was read as the counterparty,
  so the check compared one's own address against one's own trust list
  and validated nothing (KKallias, guardrail-core).
- **payTo epistemics, named in text.** `payTo` is issuer-attested in
  v0.2: the leg that could re-derive it is the 402 quote (payment
  requirements), whose disclosure is not currently required. A dispute
  process MUST NOT conclude "counterparty bound correctly" about a field
  nothing re-derived; quote-leg disclosure is the marked upgrade path.
- **Vector**: a payTo/payer swap entry, everything else re-deriving
  cleanly, joins the invalid set — failing under the payer rule above.

---

## 5. Design record and credits

Every amendment traces to a source: **SmartFlow Observatory** — the
#2814 data; three production dry-runs; the second implementation; the
31-entry corpus (#6–#13); the surrogate find (#15); the draft-1 dry-run
(13 bindings): array proof E8, the freshness-encoding break E11, the
state requirements E6/E7, the step-5 coherence probe; the two-answers
argument for trust-model keying; the envelope-split completion; the
shipped `/quality` state change closing the snapshot gate.
**invinoveritas** — the interop experiment and transport incidents (#4);
`content_sha256`; the precedence/freshness frame and two flavors; the
authority fixture-flip; court-vs-protocol; the `/ledger` worked split.
**giskard09** — AnchorRegistry; A1–A3 in writing with the July-12
mainnet anchor; the canonical_envelope / anchoring_existence split
(`anchoring-precedence-ref-v1`). **vaaraio** — verify/settle evidence
classes (v0.2 §8.4); the QTSP correction; trust-model keying of the
required set; `qualified_time_v0`. **0xbrainkid** — the original binding
schema. **pipavlo82** — no-rewriting ≠ no-omission; the recomputability
rule. **KKallias** — the prevented-payments evidence class; the payer
re-derivation rule and swap vector, from a shipped bug. **clai-mach** —
the receipt/reputation boundary.

Meta-rule: wherever two adjacent states can be collapsed by a lazy
consumer (stale→fresh, well-formed→authorized, verified→settled,
issued→still-holds), the format makes the middle state impossible to
skip — carry the distinctions in the bound bytes, declare the axis, keep
every judgment consumer-side as a pure function.

---

## 6. Gate status and open items

- **Freeze gate**: snapshot side CLOSED (live `/quality` bytes, 17/17,
  post-deploy). Verdict side OPEN: `/ledger` dry-run lands against this
  draft.
- **Vectors owed against this text**: Tom's 1/2/5 set including the
  conflicting-pair and valid-anchor negatives; the payTo/payer swap;
  chain_anchored carrying an `authorization_sha256` it has no right to.
- **Fixtures owed**: one per authority surface (§2.6) — only
  `issuer_signed` has one today.
- **Requested**: the five-invariant `anchoring-precedence-ref-v1` spec +
  fixture (giskard09); the `evidenceRef` mapping statement (vaaraio).
- **Open for §4.1**: the alg registry and contract-signer design.

---

*Draft-2 changelog: trust-model-keyed conditional sets replacing the
uniform table; `trust_model` + `authority_ref` in the common core
(rename of `verifier_key_ref`); empty-array and deduplication rules;
freshness encoding with per-axis inputs; three-keys-present MUST;
lowercase digests; snapshot `state` with closed vocabulary and the
step-5 coherence table; steps 1–5 offline as a theorem with step 6 named
as the consumer-judgment step and the §8 insertion point fixed; the
chain_anchored envelope model with encoding profile, two-layer
granularity, existence invariant and circularity rule; the July-12
mainnet anchor as §2.8(3)/§3's worked example; §4.3 payer re-derivation
and payTo epistemics. Nothing here is frozen; everything here is
testable.*
