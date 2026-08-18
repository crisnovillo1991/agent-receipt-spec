# AIR Evidence Profile

![profile](https://img.shields.io/badge/profile-air--evidence%2F0.1-b9975b)
![status](https://img.shields.io/badge/status-draft%201-orange)
![extends](https://img.shields.io/badge/extends-AIR%20v0.3-blue)
![tests](https://img.shields.io/badge/conformance-10%2F10%20passing-5e9c76)

**The forensic evidence layer for agent transactions.** A profile over AIR
receipts defining the minimum evidence a transaction must carry to support a
liability claim — and a deterministic adjudicator that resolves those claims
as a pure function over signed data.

> Logs are testimony from an interested party. Evidence is signed by all
> parties at the moment of the event and immutable since. This profile
> specifies evidence.

**▶ [Try the live console](https://YOUR-USER.github.io/YOUR-REPO/)** — issue
receipts, anchor, tamper, file claims. All cryptography (Ed25519, SHA-256,
Merkle) runs locally in your browser; nothing leaves the page.

---

## How it works

```mermaid
flowchart LR
    P["Principal<br/><i>signs typed mandate</i>"] -->|authorizes| A["Agent<br/><i>decides & transacts</i>"]
    A -->|cross-signed receipt| L["Receipt log<br/><i>hash chain per agent</i>"]
    C["Counterparty"] -.->|co-signs| L
    G["Gateway / witness"] -.->|co-signs| L
    L -->|Merkle root| AN["Anchor<br/><i>RFC 3161 / ledger</i>"]
    L --> J["Adjudicator<br/><i>D1–D6, deterministic</i>"]
    AN --> J
    J --> V["Signed verdict<br/><i>+ machine-readable violations</i>"]
```

Five evidence blocks per receipt (spec §4–§8):

| # | Block | Answers | Key mechanism |
|---|-------|---------|---------------|
| 1 | **Mandate** | What did the principal authorize? | Typed, machine-decidable constraints — prose kept only as hash |
| 2 | **Identity** | Which agent, software, operator? | DIDs + `config_hash` linking audited config to conduct |
| 3 | **Decision context** | What did the agent know? | Cryptographic commitment, no data disclosure |
| 4 | **Terms** | What was transacted? | Cross-signed by agent, counterparty, witness |
| 5 | **Outcome & chain** | What happened after? | Disputes, refunds, claims chain to the origin receipt |

## Claim adjudication

```mermaid
sequenceDiagram
    participant CL as Claimant
    participant AD as Adjudicator
    participant LG as Receipt log
    CL->>AD: claim (refs receipt)
    AD->>LG: fetch receipt + inclusion proof
    AD->>AD: D1 signatures · D2 chain+anchor · D3 mandate · D4 temporal · D5 constraints · D6 fail-safe
    AD-->>CL: signed verdict + violations[expected vs actual]
```

| Verdict | Meaning | Resolution |
|---|---|---|
| `WITHIN_MANDATE` | Agent acted inside authority | auto |
| `EXCEEDED_MANDATE` | Typed constraint(s) breached — listed with expected vs. actual | auto |
| `INVALID_EVIDENCE` | Signatures or content fail verification (tampering) | auto |
| `BROKEN_CHAIN` | Stream gap, fork, or missing anchor | auto |
| `MANDATE_MISMATCH` / `EXPIRED_MANDATE` | Wrong or out-of-window mandate | auto |
| `INDETERMINATE` | Unknown constraint → fail-safe | human review |

The share of claims that resolve automatically is governed by one variable:
**how much of the mandate is typed**. That is the load-bearing rule of the
profile (spec §4.1).

## Quickstart

```bash
cd reference
pip install cryptography fastapi uvicorn pytest httpx

python -m demo.simulate_claim   # the §13 incident, end to end
python -m pytest tests/ -q      # conformance suite (one test per verdict)
uvicorn air_evidence.api:app    # HTTP API + local console at /
```

Cross-language guarantee: the Python reference and the browser console
(`docs/core.js`) canonicalize and hash identically — same object, same
`sha256:…` in both. JCS (RFC 8785) restricted to a no-float subset: amounts
are integers in minor units, and the canonicalizer *rejects* anything else.

## Documents

- **[SPEC.md](./SPEC.md)** — the profile: conventions, evidence blocks,
  custody chain, adjudication algorithm, worked example, security
  considerations.
- **[ADOPTION.md](./ADOPTION.md)** — conformance levels and the shortest path
  to emitting evidence-grade receipts.
- **[reference/](./reference/)** — Python reference implementation, tests,
  demo, HTTP API.
- **[../../docs/](../../docs/)** — browser console (GitHub Pages).

## Status

Draft 1, open for implementor review. Open issues for 0.2 tracked in
[SPEC.md §15](./SPEC.md#15-open-issues-for-02) — sub-mandates (agent-to-agent
delegation) is the headline item. Feedback via issues and PRs welcome.
