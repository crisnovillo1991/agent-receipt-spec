# Agent Interaction Receipt (AIR) — Specification v0.3 — DRAFT 1

**Status: DRAFT.** This document is not frozen. Entries produced against it
MUST use `spec_version: "0.3-draft-1"`; the value `"0.3"` is reserved for
the frozen release. Per this project's working method, no section freezes
until it has been tested against live systems: two dry-runs are committed
(SmartFlow's `/quality` endpoint on the snapshot side; invinoveritas'
`/ledger` on the verdict side) and their results gate the freeze.

v0.3 entries inherit **§1–§9 of v0.2 unchanged** except as amended here.
The design record for §2 of this draft is issue #14 of this repository —
four questions, each resolved by shipped evidence, credited inline and in
§5. Change process: disagreements become issues; findings become vectors.

---

## 1. Scope of v0.3

| Area | Status in draft 1 |
|---|---|
| First-class `authorizations` field | **Specified** (§2) — design record complete |
| Anchoring profile | **Skeleton** (§3) — open questions pending a scheduled walkthrough |
| Provider/payer co-signatures | Scoped, design pending (§4.1) |
| No-omission interface | Scoped, design pending (§4.2) |
| x402 v2 profile | Scoped, design pending (§4.3) |

---

## 2. The `authorizations` field

### 2.1 Placement and envelope

A v0.3 entry MAY carry a top-level field `authorizations`: an **array** of
binding objects, included in the signed core (canonicalized and signed per
v0.2 §5–§6). Entries without it remain valid. Array rather than a single
object because one interaction may bind artifacts of different classes —
a pre-action verdict and a trust-score snapshot, for instance — under one
transport discipline (composition question raised in the design record).
*Array-vs-single is Open Question Q1 (§6) for draft review.*

Migration: the v0.2 extension-point pattern `meta.authorization` (proven
in the issue-4 interop experiment) maps field-for-field into one element
of `authorizations`. Issuers SHOULD migrate; verifiers targeting 0.3 MUST
accept both during the draft period.

### 2.2 Binding object

| Field | Type | Req | Meaning |
|---|---|---|---|
| `scheme` | string | yes | Verifier/schema name of the bound artifact (e.g. `invinoveritas.verdict_proof.v1`). Deliberately open: the field admits any artifact class under one discipline. |
| `decision_ref` | string | yes | Content-addressed identifier of the decision/verdict/snapshot, as defined by `scheme`. |
| `authorization_uri` | string \| null | yes | Checksum-stable retrieval pointer for the exact artifact bytes (raw URL, relay pointer, on-chain locator). `null` only when `transport_hint` is `"bundle"` (bytes travel alongside the entry). |
| `authorization_sha256` | string (64 hex) | **yes — MUST** | SHA-256 of the **exact bytes the binding party verified at binding time**. See §2.3. |
| `transport_hint` | string | yes | `raw_url` \| `relay_event` \| `bundle` \| `onchain` \| `other`. |
| `verifier_key_ref` | string | yes | Identification/discovery of the artifact's signing key (e.g. `nostr:<pubkey>`, `ed25519:<b64[:12]>`, a `.well-known` URL). **Never an authority claim** — see §2.6. |
| `axes` | object | yes | Axis declaration — see §2.4. |

Schema shape credited to 0xbrainkid (design record, question schema).

### 2.3 Transport discipline: why `authorization_sha256` is MUST

Content-addressing **at issuance** and byte-integrity **at point of use**
are different failure modes. All three transport failures documented in
the issue-4 experiment (two truncated transcriptions, one markdown
whitespace-collapse) happened to artifacts that were *already correctly
content-addressed at the source* — so "the URI is already
content-addressed" is precisely the plausible-sounding reason that would
have let every one of them through silently. A SHOULD that invites that
reasoning is a MUST that lost an argument with convenience.

Semantics: `authorization_sha256` attests **"these are the bytes I
verified before binding"** — not "this is what the issuer published."
Prior art, live: invinoveritas' `content_sha256` envelope field
(`services/proof_signing.py`, commit `dc12cb2`), shipped on the verdict
side before this section existed. (Resolution and evidence: invinoveritas,
design record question 1 and 3.)

Prose remains not a transport (v0.2 §9): inline copies of the artifact are
illustrative only.

### 2.4 Axis declaration

Every documented failure in this project's design record is a
**cross-axis substitution** wearing a plausible field name: issuance time
answering a freshness question; processing status answering a settlement
question; structural validity answering an authority question; "verdict
issued" answering "verdict still holds." An undeclared axis is an
invitation to substitute; a declared one turns the substitution into a
visible type error. (Rule: SmartFlow, design record.)

Three axes, and a bound artifact MUST declare its coverage of each:

- **precedence** — *did this exist no later than T?* Frozen on landing,
  answered once, never re-checked (e.g. an observation timestamp, an
  OpenTimestamps/Bitcoin-block anchor).
- **freshness** — *is this still good now?* Consumer-side, in one of two
  declared flavors:
  - `computable`: a pure function of the observation time, the declared
    cadence, and the consumer's clock — no round trip;
  - `re_verifiable`: a live re-query of a public authoritative source —
    re-checkable by anyone, indefinitely.
- **correctness** — *was the claim right?* (e.g. outcome evidence graded
  against a realized result). Neither precedence nor freshness answers it.

Encoding (Open Question Q2, §6): each axis maps to `null` (declared not
covered — visible non-coverage, never silent) or an object
`{"field": "<name in the artifact carrying this axis>"}`, where
`freshness` additionally carries `"flavor": "computable" | "re_verifiable"`.

(Frame: invinoveritas — precedence/freshness distinction, with
`hanjoonchoe/liveness-bench` as the reference comparison of freshness
proofs vs precedence anchors: neither substitutes, they compose. Third
axis and declaration rule: SmartFlow.)

### 2.5 Artifact-class requirements

**Point-in-time artifacts** (verdicts, one-shot judgments): MUST cover
`precedence`. Freshness and correctness MAY be `null` — a verdict that
cannot say "still holds" must say so visibly.

**Rolling-snapshot artifacts** (trust scores, quality metrics, any
refresh-cadence value): the bound bytes MUST carry, as distinct fields of
the artifact itself:

- (a) an **observation timestamp** distinct from issuance and serving
  time (a single timestamp silently re-stamps cached observations as
  fresh — the freshness-side twin of "processing that never landed");
- (b) the **declared cadence** (maximum age);
- (c) a representable **degraded/stale state** for when the source is
  stale or missing — never a silent fallback to a fresh-looking value.

Under (a)+(b)+(c), update cadence stops mattering to the binding: the
receipt attests "this exact snapshot, observed at T, declared fresh for
N seconds," and staleness is the consumer's pure function. (Requirements
and incident evidence: SmartFlow's `/quality` production split —
`served_at` / `fetched_at` / `max_age_seconds`. Worked verdict-side
example of the same separation: invinoveritas' `/ledger` —
`commitment_proof` for precedence, `outcome_evidence` for correctness,
distinct fields, never merged.)

### 2.6 Authority is consumer-side

`verifier_key_ref` carries enough to compute **structural validity**
(signature verifies, format conforms) and never an authority claim.
Authority is strictly a downstream consumer-policy lookup keyed by the
same identifier. Consumers MUST distinguish three states and MUST NOT
collapse them:

`structurally_invalid` · `structurally_valid_zero_authority` ·
`valid_and_authorized`

The middle state is REQUIRED to be representable: collapsing it is
precisely how a consumer with the wrong key set reads *well-formed* as
*authorized*. Evidence: a conformance fixture in which the identical
bundle, unchanged, flips from `structurally_valid_zero_authority` to
`valid_and_authorized` solely by adding the key to the consumer's trust
policy — authority is a property of the reader, not of the bytes.
(Resolution and fixture: invinoveritas, design record question 4.)

**Recomputability companion rule** (after pipavlo82's inclusion-set
principle): any *published* authority classification MUST carry the
trust-policy identifier (or anchor set) it was computed against.
Consumer-relative truth stays verifiable only if the consumer's frame
travels with the verdict.

### 2.7 Verification procedure (per binding object)

1. Retrieve the artifact bytes via `authorization_uri` (or take them from
   the bundle). 2. `SHA-256(bytes)` MUST equal `authorization_sha256`;
   mismatch is a **transport failure, not a signing failure** — report it
   as such. 3. Verify the artifact per `scheme` (its own signature/id
   rules). 4. Check the `axes` declaration against the artifact: every
   declared field MUST exist in the artifact. 5. For snapshot-class
   schemes, check §2.5 (a)(b)(c) are present and distinct. 6. Compute
   freshness (if declared) as a pure function; classify authority per the
   consumer's own policy (§2.6). Steps 1–5 require no trust in the
   issuer; step 6 requires no trust in anyone but the consumer's own
   policy source.

### 2.8 Worked examples

**(1) Point-in-time verdict — the issue-4 interop binding, upgraded from
`meta.authorization` to first-class.** All values are the experiment's
real artifacts:

```json
"authorizations": [{
  "scheme": "invinoveritas.verdict_proof.v1",
  "decision_ref": "sha256:58edaf5325483774affa674f294675b796ff30a332acca10f889125564d371ef",
  "authorization_uri": "https://raw.githubusercontent.com/babyblueviper1/preaction-governance-conformance/main/events/279fbf14007edf171d58a1876f036ef6564bd6316a00d1c10d6495c9cdc60ef6.json",
  "authorization_sha256": "8e6030b4e9f7e6a9cdb4e3f7896f6a37cdf8eed39af4a93e54cec3213f544654",
  "transport_hint": "raw_url",
  "verifier_key_ref": "nostr:6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7",
  "axes": {
    "precedence": {"field": "created_at"},
    "freshness": null,
    "correctness": null
  }
}]
```

The two `null`s are load-bearing: this verdict proves judgment-before-
action and visibly does not claim "still holds" or "turned out right."

**(2) Rolling snapshot — `/quality`-shaped trust score:**

```json
{
  "scheme": "smartflow.quality_score.v1",
  "decision_ref": "sha256:<snapshot-preimage-hash>",
  "authorization_uri": "https://<host>/quality/snapshots/<id>.json",
  "authorization_sha256": "<sha256 of the exact snapshot bytes>",
  "transport_hint": "raw_url",
  "verifier_key_ref": "ed25519:<key-id>",
  "axes": {
    "precedence": {"field": "fetched_at"},
    "freshness": {"field": "max_age_seconds", "flavor": "computable"},
    "correctness": null
  }
}
```

The artifact itself carries `served_at` / `fetched_at` /
`max_age_seconds` / a degraded state per §2.5.

---

## 3. Anchoring profile — SKELETON

Purpose (from v0.2 §7): anchoring turns equivocation from "detectable
when surfaced" into "concealable never." An anchor is a **precedence-only
artifact** (§2.4): it answers *existed no later than block N* and MUST
NOT be read as freshness or correctness — the composition point, not a
limitation.

Candidate prior art, under evaluation: **AnchorRegistry**
(giskard09/argentum-core) — permissionless `anchor(bytes32)`, no owner,
no roles, no funds; CREATE2-deployed at the same address on Base,
Arbitrum and Ink mainnet
(`0x49fEcA52bC634a9Ab773226D16619deC547794aa`). Answers "who controls the
anchor" with *nobody, verifiably* — no Transparency Service or operator
attestation in the loop.

Open questions gating this section (scheduled walkthrough):

- **A1** — anchor granularity: per-entry `entry_hash` vs per-epoch
  Merkle root of a session's entries (cost vs dispute granularity on
  Base-class fees).
- **A2** — the third-party recomputability path: exactly what a verifier
  holding only a receipt and the registry address recomputes, end to end.
- **A3** — reference shape: does an anchor reference live inside
  `authorizations` (as an `onchain` transport precedence artifact) or as
  a sibling top-level field?

---

## 4. Scoped, design pending

**4.1 Co-signatures.** Provider/payer signatures over the same signing
payload (v0.2 §6 already admits appended co-signatures); open design:
smart-account signers via an ERC-1271-style contract-signature path
alongside raw Ed25519. First reviewer committed: SmartFlow Observatory.

**4.2 No-omission interface.** Per v0.2 §7, closing no-omission needs a
declared cadence or an enumerable obligation set. v0.3 will interface
with, not reinvent, the obligation-record prior art
(`issuance_record.v0` + skip records, pipavlo82) including the
**answered / provably-overdue / undeterminable** trichotomy, where
`undeterminable` costs nothing. For the x402 profile the obligation set
is free: settled payments are enumerable on-chain and each obligates
exactly one receipt. Pricing of silence stays in the reputation layer
(clai-mach's boundary), reached through these interfaces.

**4.3 x402 v2 profile.** Header mapping (`PAYMENT-*`) and mainnet
settlement evidence; the §8.4 evidence-class rules carry forward
unchanged. Standing re-validation committed: the 610-response archive
replay (SmartFlow) upon landing.

---

## 5. Design record and credits

This draft's §2 was designed in issue #14 in five days, every question
resolved by shipped evidence rather than argument: **(Q1)**
byte-integrity MUST — incident data from three real transport failures
(invinoveritas). **(Q2)** snapshot semantics — a production timestamp
split (SmartFlow `/quality`), framed by the precedence/freshness
distinction (invinoveritas) and completed by the correctness axis and
axis-declaration rule (SmartFlow). **(Q3)** working precedent —
`content_sha256` live (invinoveritas). **(Q4)** consumer-side authority —
a conformance fixture flip (invinoveritas). Schema shape: 0xbrainkid.
Recomputability companion: pipavlo82. Anchoring candidate: giskard09.

The meta-rule none of us started with: *wherever two adjacent states can
be collapsed by a lazy consumer (stale→fresh, well-formed→authorized,
verified→settled), the format's job is to make the middle state
impossible to skip — carry the distinctions in the bound bytes, declare
the axis, keep every judgment consumer-side as a pure function.*

---

## 6. Open questions for draft review

- **Q1** `authorizations` as array vs single object (§2.1).
- **Q2** the `axes` encoding — per-axis `null | {field, flavor?}` as
  drafted, vs a flat list of declared-axis objects (§2.4).
- **Q3** whether `state` (degraded/stale) is REQUIRED as a named artifact
  field or only as a representable value per `scheme` (§2.5c).
- **A1–A3** anchoring (§3).

Dry-run gate before freeze: live `/quality` responses (snapshot side) and
live `/ledger` entries (verdict side) bound and verified end-to-end per
§2.7 by both parties.

---

*Draft 1 changelog: initial draft against the issue-14 design record.
Nothing here is frozen; everything here is testable.*
