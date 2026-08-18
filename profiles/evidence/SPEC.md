# AIR Evidence Profile

**Profile:** `air-evidence/0.1` — Draft 1
**Extends:** AIR (Agent Interaction Receipt) SPEC v0.3
**Status:** DRAFT — for implementor review
**Audience:** AI-agent insurers, claims adjusters, arbitrators, payment gateways, agent operators

---

## 1. Abstract

AIR core defines cryptographic receipts for agent-to-agent transactions. This profile defines the **minimum evidence set a receipt chain must carry to support liability claims**: insurance claims, disputes, and arbitration arising from autonomous agent transactions.

The design goal is **deterministic adjudication**: given a valid evidence chain, a machine can decide whether an agent acted within its mandate without human interpretation. Human judgment is reserved for cases the algorithm explicitly marks `INDETERMINATE`.

The profile answers five forensic questions:

1. **Mandate** — what exactly did the principal authorize?
2. **Identity** — which agent acted, running what software, operated by which legal entity?
3. **Decision context** — what information did the agent commit to at decision time?
4. **Terms** — what was transacted, with whom, under what conditions?
5. **Outcome & chain** — what happened, and how does subsequent activity (settlement, delivery, disputes) link back?

A receipt chain conforming to this profile is designed to be **admissible evidence**: signed by all parties at the time of the event, tamper-evident since capture, and verifiable by a third party without trusting any single participant.

> Logs are testimony from an interested party. Evidence is signed by all parties at the moment of the event and immutable since. This profile specifies evidence.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **Principal** | The human or legal entity that delegates authority to an agent. |
| **Agent** | The autonomous software system acting under a mandate. |
| **Operator** | The legal entity responsible for running the agent. May equal the principal. |
| **Counterparty** | The other side of the transaction (merchant, another agent, a service). |
| **Witness** | Neutral infrastructure that observes and co-signs a receipt (e.g. a payment gateway). |
| **Anchor** | A periodic commitment of the receipt log to an external timestamping authority or public ledger. |
| **Adjudicator** | The machine (or human, on escalation) that evaluates a claim against the evidence chain. |
| **Claim** | A formal assertion that a transaction caused a covered loss. |

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as in RFC 2119.

---

## 3. Conventions

These conventions exist so that hashes and signatures are reproducible across independent implementations.

- **Serialization.** All signed objects MUST be canonicalized with JCS (RFC 8785, JSON Canonicalization Scheme) before hashing or signing.
- **Hashes.** SHA-256, encoded as `sha256:<hex>`. The hash of an object means the hash of its JCS canonical form **excluding the `signatures` array**.
- **Signatures.** Detached JWS (RFC 7515) with `EdDSA` (Ed25519). Each signature entry carries the signer role, key reference, and timestamp. Other algorithms MAY be negotiated but Ed25519 is the mandatory baseline.
- **Identifiers.** Parties are identified by DIDs. `did:key` for ephemeral agents, `did:web` for operators and merchants. UUIDv7 for object ids (time-ordered).
- **Timestamps.** RFC 3339, UTC, millisecond precision.
- **Amounts.** Integers in the currency's minor unit (`amount_minor`) plus ISO 4217 `currency`. Floats are prohibited anywhere in the profile.
- **Versioning.** Every object carries `"profile": "air-evidence/0.1"` alongside the AIR core version.

---

## 4. Evidence Block 1 — Mandate

The mandate is the root of the liability chain. It separates *"the agent exceeded its authority"* from *"the principal authorized a bad decision"* — the single distinction every insurer needs.

### 4.1 Design rule: constraints are typed, not prose

The principal's free-text instruction is preserved **only as a hash** (`instruction_hash`) for context. Adjudication runs **exclusively** against the typed `constraints` object. This is the design decision that makes automatic claims resolution possible: a prose mandate requires a human interpreter forever; a typed mandate is machine-decidable.

Implementations SHOULD have the agent (or onboarding UI) translate the principal's natural-language instruction into typed constraints and present them back for explicit confirmation and signature. The signed constraints — not the prose — are the mandate.

### 4.2 Schema

```json
{
  "profile": "air-evidence/0.1",
  "air_version": "0.3",
  "type": "mandate",
  "mandate_id": "018f3c2e-7b1a-7c3d-9e4f-2a6b8c0d1e2f",
  "principal": {
    "id": "did:web:principal-buyer.example",
    "legal_entity": {
      "jurisdiction": "AR",
      "registration_hash": "sha256:9f2b…"
    }
  },
  "agent_id": "did:key:z6MkhaXgBZD…",
  "operator_id": "did:web:agentops.example",
  "authorization": {
    "instruction_hash": "sha256:71aa…",
    "constraints": {
      "max_total_amount_minor": 50000000,
      "max_per_tx_amount_minor": 20000000,
      "currency": "ARS",
      "max_transactions": 10,
      "categories": ["industrial_supplies"],
      "counterparties": { "mode": "any" },
      "valid_from": "2026-08-01T00:00:00.000Z",
      "valid_until": "2026-09-30T23:59:59.999Z",
      "human_approval_above_minor": 15000000
    }
  },
  "issued_at": "2026-08-01T10:12:03.412Z",
  "signatures": [
    { "role": "principal", "kid": "did:web:principal-buyer.example#key-1", "sig": "eyJ…", "signed_at": "2026-08-01T10:12:04.001Z" }
  ]
}
```

### 4.3 Constraint semantics

| Field | Required | Adjudication rule |
|---|---|---|
| `max_total_amount_minor` | MUST | Sum of all settled receipts under this mandate ≤ value. |
| `max_per_tx_amount_minor` | SHOULD | Each receipt's `terms.amount_minor` ≤ value. |
| `currency` | MUST | Receipt currency MUST match. Cross-currency requires an FX attestation extension (out of scope for 0.1). |
| `max_transactions` | MAY | Count of settled receipts ≤ value. |
| `categories` | MUST | Receipt `terms.category` ∈ list. Taxonomy: see §4.4. |
| `counterparties` | MUST | `mode: "any"` or `mode: "allowlist"` + `ids: [did…]`. |
| `valid_from` / `valid_until` | MUST | Receipt `timestamps.decision_at` inside window. |
| `human_approval_above_minor` | MAY | Above this threshold the receipt MUST carry a `human_approval` block (a fresh principal signature over the specific terms hash). Absence = mandate violation. |

Unknown constraint fields MUST cause `INDETERMINATE` (fail-safe: an adjudicator never silently ignores a constraint it does not understand).

### 4.4 Category taxonomy (open issue)

v0.1 ships with a flat, registry-managed string list (UN CPC-inspired). A hierarchical taxonomy with wildcard matching is deferred to 0.2. Implementations MUST treat category comparison as exact string match in 0.1.

---

## 5. Evidence Block 2 — Identity

Binds the action to accountable parties. This is what a court or insurer subrogates against.

```json
"identity": {
  "agent_id": "did:key:z6MkhaXgBZD…",
  "software": {
    "name": "procurement-agent",
    "version": "2.4.1",
    "build_hash": "sha256:cc01…"
  },
  "model": {
    "provider": "anthropic",
    "model_id": "claude-sonnet-4-6",
    "config_hash": "sha256:5e77…"
  },
  "operator": {
    "id": "did:web:agentops.example",
    "legal_entity": { "jurisdiction": "AR", "registration_hash": "sha256:3b90…" }
  }
}
```

Notes:

- `config_hash` commits to the system prompt / policy configuration **without revealing it** (see §9 on selective disclosure). This lets an insurer verify, during a claim, that the agent ran the audited configuration — the link between pre-deployment certification (what AIUC-style audits cover) and production behavior (what they currently cannot see).
- Agent keys SHOULD be rotated per mandate or per epoch; key continuity is established through the operator's DID document.

---

## 6. Evidence Block 3 — Decision context

A cryptographic commitment to what the agent knew when it decided. Full reasoning traces are explicitly **not** required: they are impractical to standardize, leak proprietary and personal data, and are not needed for mandate adjudication.

```json
"decision_context": {
  "inputs_commitment": "sha256:a1f4…",
  "inputs_manifest_hash": "sha256:0d2c…",
  "policy_version": "procurement-policy/1.3",
  "captured_at": "2026-08-14T13:02:11.238Z"
}
```

- `inputs_commitment` — Merkle root over the input set (messages, retrieved documents, tool outputs) the agent used for this decision. The operator retains the preimages.
- `inputs_manifest_hash` — hash of a manifest listing input *types and counts* (not contents), so an adjudicator can see the shape of the context without disclosure.
- During a claim, the adjudicator MAY require disclosure of specific preimages; they verify against the commitment. Refusal to disclose on a covered claim SHOULD be treated contractually as adverse inference.

---

## 7. Evidence Block 4 — Terms

The transaction itself, cross-signed. Both sides sign the **same** canonical object; "I never agreed to that" dies here.

```json
"terms": {
  "amount_minor": 78000000,
  "currency": "ARS",
  "category": "industrial_supplies",
  "counterparty": {
    "id": "did:web:supplier.example",
    "role": "merchant"
  },
  "description_hash": "sha256:88ab…",
  "line_items_hash": "sha256:41c9…",
  "payment": {
    "rail": "mercadopago",
    "rail_tx_ref": "mp:pay:123456789",
    "gateway_id": "did:web:gateway.example"
  }
}
```

- `description_hash` / `line_items_hash` — commitments to the human-readable order; preimages retained by both parties, disclosed on claim.
- `payment.rail_tx_ref` — the join key to the payment rail's own records, so evidence cross-verifies against Mercado Pago / bank records during a claim.

---

## 8. Evidence Block 5 — Outcome & chain

```json
"outcome": {
  "status": "settled",
  "settled_at": "2026-08-14T13:02:19.804Z",
  "delivery": {
    "expected_by": "2026-08-21T23:59:59.999Z",
    "confirmation_hash": null
  }
}
```

`status` ∈ `authorized | settled | failed | reversed | disputed`.

Subsequent events (delivery confirmation, dispute filing, refund, claim, adjudication result, subrogation) are **their own receipt objects** whose `refs` field points to the originating receipt hash. Nothing about a transaction's afterlife floats free of the chain.

---

## 9. Receipt envelope

The five blocks travel inside one signed envelope:

```json
{
  "profile": "air-evidence/0.1",
  "air_version": "0.3",
  "type": "transaction_receipt",
  "receipt_id": "018f4a91-2c0e-7f6b-8a3d-6e1f0b9c4d21",
  "mandate_ref": {
    "mandate_id": "018f3c2e-7b1a-7c3d-9e4f-2a6b8c0d1e2f",
    "mandate_hash": "sha256:d47b…"
  },
  "prev_receipt_hash": "sha256:19ce…",
  "seq": 4,
  "identity": { … },
  "decision_context": { … },
  "terms": { … },
  "outcome": { … },
  "timestamps": {
    "decision_at": "2026-08-14T13:02:11.238Z",
    "authorized_at": "2026-08-14T13:02:14.900Z",
    "settled_at": "2026-08-14T13:02:19.804Z"
  },
  "human_approval": null,
  "refs": [],
  "signatures": [
    { "role": "agent", "kid": "did:key:z6Mkh…#0", "sig": "…", "signed_at": "…" },
    { "role": "counterparty", "kid": "did:web:supplier.example#key-2", "sig": "…", "signed_at": "…" },
    { "role": "witness", "kid": "did:web:gateway.example#key-1", "sig": "…", "signed_at": "…" }
  ]
}
```

Signature requirements:

- `agent` — MUST.
- `counterparty` — MUST for settled transactions. A counterparty that cannot sign (legacy merchant) MAY be represented by the witness gateway co-signing on its behalf under a declared trust arrangement; adjudicators MUST treat gateway-attested counterparty consent as weaker evidence (`INDETERMINATE` on counterparty-consent disputes).
- `witness` — SHOULD when a gateway or neutral infrastructure is in the path. Witness signatures are what make single-party fraud (agent + fake counterparty colluding) expensive.
- `mandate_hash` binds the receipt to the exact mandate version; a mandate amendment produces a new mandate object and hash.

---

## 10. Chain of custody: hash chain + anchoring

A signed receipt proves *who agreed*; the chain proves *nothing was deleted or reordered afterward*. The model is Certificate Transparency, not per-transaction blockchain — near-zero marginal cost, externally verifiable.

### 10.1 Per-agent stream

- Every receipt carries `prev_receipt_hash` (hash of the previous receipt in that agent's stream) and a monotonic `seq`.
- Gap or fork in the stream = `BROKEN_CHAIN` at adjudication.

### 10.2 Log operator and anchoring

- Receipts are appended to a log (the notarization service). Every anchoring interval — **every N=1000 receipts or T=10 minutes, whichever first** — the operator computes a Merkle root over the interval.
- The root MUST be anchored externally by at least one of:
  - RFC 3161 timestamping authority (baseline, cheap), and/or
  - a public ledger transaction (stronger, censorship-resistant).
- Each receipt is thereafter associated with a **Merkle inclusion proof** to an anchored root. `verify(receipt) = signatures valid ∧ chain intact ∧ inclusion proof to anchored root`.
- Anyone can verify a receipt existed at anchor time and is unmodified, **without trusting the log operator**. Consistency proofs between successive roots (RFC 6962-style) prevent the operator from rewriting history.

### 10.3 Retention

Log operators SHOULD offer a compliance-retention tier (receipts + proofs held ≥ 5 years, jurisdiction-configurable). Preimage retention (for commitments) is the obligation of the committing party.

---

## 11. Deterministic adjudication

Given a claim referencing receipt(s), the adjudicator runs, in order:

| Step | Check | Failure code |
|---|---|---|
| D1 | All required signatures verify against DID documents valid at `signed_at` | `INVALID_EVIDENCE` |
| D2 | Chain integrity: `prev_receipt_hash` links, `seq` monotonic, inclusion proof to anchored root | `BROKEN_CHAIN` |
| D3 | `mandate_hash` resolves to a signed mandate; principal signature verifies | `MANDATE_MISMATCH` |
| D4 | `decision_at` within `valid_from … valid_until` | `EXPIRED_MANDATE` |
| D5 | Every typed constraint evaluates true (amount caps, category, counterparty, tx count, human-approval threshold) | `EXCEEDED_MANDATE` + machine-readable `violations[]` |
| D6 | No unknown constraint fields, no weak-evidence conditions triggered | `INDETERMINATE` |

**Verdicts:**

- `WITHIN_MANDATE` — agent acted inside authority. Loss, if covered, prices as product/model risk.
- `EXCEEDED_MANDATE` — agent breached typed constraints. Liability path points at operator; principal payout is mechanical. `violations[]` lists each failed constraint with expected vs. actual.
- `INVALID_EVIDENCE | BROKEN_CHAIN | MANDATE_MISMATCH | EXPIRED_MANDATE` — evidence defects; contractual consequences (typically: no automatic cover).
- `INDETERMINATE` — escalate to human (or arbiter-agent) review, with the full verified chain attached.

The adjudicator itself SHOULD emit its verdict as a signed receipt (`type: "adjudication"`, `refs: [claim, receipts…]`) — decisions about the chain live on the chain.

**Design consequence:** D1–D5 are pure functions over signed data. The share of claims resolving automatically is governed by one variable — how much of the mandate is typed. That is why §4.1 is the load-bearing rule of the profile.

---

## 12. Claim flow (end to end)

```
claim_filed(refs: receipt_ids, asserted_loss)
   → evidence_verification (D1–D2)
   → mandate_adjudication (D3–D5)
   → verdict:
        WITHIN_MANDATE / EXCEEDED_MANDATE → auto-resolution per policy terms
        INDETERMINATE → human/arbiter queue
   → settlement receipt (payout or denial, signed)
   → optional subrogation receipt (insurer → operator), chained
```

Every stage emits a signed, chained object. An insurer's loss database and the evidence log are the same data structure.

---

## 13. Worked example: simulated claim

**Setup.** Principal (a distribution business, `did:web:principal-buyer.example`) mandates a procurement agent: total ≤ ARS 500,000.00 (`50000000` minor), per-tx ≤ ARS 200,000.00, category `industrial_supplies`, any counterparty, valid Aug 1 – Sep 30 2026, human approval required above ARS 150,000.00. Mandate signed as in §4.2.

**Event.** On Aug 14 the agent settles a purchase of ARS 780,000.00 (`78000000` minor) with a supplier, receipt as in §9. No `human_approval` block present.

**Claim.** Principal files a claim asserting unauthorized spend.

**Adjudication run:**

```json
{
  "type": "adjudication",
  "profile": "air-evidence/0.1",
  "refs": ["sha256:receipt-018f4a91…", "sha256:claim-018f4b02…"],
  "checks": {
    "D1_signatures": "PASS",
    "D2_chain": "PASS (anchored: tsa:freetsa 2026-08-14T13:10:00Z)",
    "D3_mandate": "PASS (mandate_hash match)",
    "D4_temporal": "PASS"
  },
  "verdict": "EXCEEDED_MANDATE",
  "violations": [
    {
      "constraint": "max_per_tx_amount_minor",
      "expected": 20000000,
      "actual": 78000000
    },
    {
      "constraint": "max_total_amount_minor",
      "expected": 50000000,
      "actual": 78000000
    },
    {
      "constraint": "human_approval_above_minor",
      "expected": "principal signature over terms_hash for amounts > 15000000",
      "actual": "human_approval: null"
    }
  ],
  "resolution_path": "auto",
  "signatures": [ { "role": "adjudicator", "kid": "did:web:bureau.example#adj-1", "sig": "…" } ]
}
```

**Outcome.** Three independent typed violations (per-tx cap, cumulative cap, missing human approval), all provable from signed data alone. Payout to principal is mechanical; insurer records a subrogation receipt against the operator. Zero human minutes spent. The same claim with a prose mandate ("buy parts when we're low, don't spend too much") is unadjudicatable by machine — which is the entire argument for §4.1.

---

## 14. Security considerations

- **Collusion (agent + counterparty).** Mitigated by witness signatures and by the payment-rail join key (`rail_tx_ref`): fabricated receipts must also fabricate rail records.
- **Key compromise.** DID documents carry key validity windows; signatures verify against the key state *at signing time*. Operators MUST publish revocations to the log; post-revocation signatures fail D1.
- **Log operator misbehavior.** Anchoring + consistency proofs make suppression and rewriting detectable. Multiple independent log operators MAY mirror streams (gossip), as in CT.
- **Privacy.** Receipts carry commitments, not contents. Amounts and category are the deliberate exception — they are what adjudication needs. Deployments requiring amount privacy can move amounts behind commitments with range proofs; deferred to 0.2.
- **Replay.** `receipt_id` uniqueness + `seq` monotonicity + mandate binding prevent receipt reuse across mandates.
- **Clock manipulation.** Party-asserted timestamps are bounded by anchor times: a receipt cannot claim a `decision_at` later than an anchor that already includes it.

---

## 15. Open issues for 0.2

1. Hierarchical category taxonomy + wildcard matching (§4.4).
2. Cross-currency mandates: FX-rate attestation format.
3. Amount-private receipts (Pedersen commitments + range proofs).
4. Multi-agent chains: sub-mandates (agent delegating to agent) and how authority attenuates — likely the single most important 0.2 feature for real agent economies.
5. Standard disclosure protocol for claim-time preimage exchange (today: bilateral, contractual).
6. Witness diversity requirements per receipt-value tier.

---

## 16. Conformance

An implementation conforms to `air-evidence/0.1` if it:

1. Emits mandates and receipts with all MUST fields, JCS-canonicalized, Ed25519-signed.
2. Maintains per-agent hash chains with monotonic `seq`.
3. Anchors Merkle roots at the declared interval and serves inclusion + consistency proofs.
4. Implements adjudication checks D1–D6 with the exact failure codes of §11.
5. Fails safe: unknown constraints → `INDETERMINATE`, never silently ignored.

---

*Changelog — Draft 1: initial profile. Five evidence blocks, CT-style custody chain, deterministic adjudication D1–D6, worked claim example.*
