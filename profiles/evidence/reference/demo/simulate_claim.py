"""End-to-end simulation of the worked example in spec section 13.

Scenario A: a receipt within mandate -> WITHIN_MANDATE.
Scenario B: ARS 780,000 purchase breaching per-tx cap AND missing human
            approval -> EXCEEDED_MANDATE with two typed violations,
            resolved automatically. Zero human minutes.
Scenario C: post-hoc tampering of a logged receipt -> INVALID_EVIDENCE.

All parties are fictitious `.example` entities.

Run:  python -m demo.simulate_claim   (from the project root)
"""

from __future__ import annotations

import json

from air_evidence.adjudicator import adjudicate, file_claim
from air_evidence.chain import ReceiptLog
from air_evidence.crypto import DIDRegistry, KeyPair, hash_object
from air_evidence.mandate import issue_mandate
from air_evidence.receipt import (
    build_decision_context,
    build_identity,
    build_receipt,
    build_terms,
)
from air_evidence.crypto import sign_object


def hr(title: str) -> None:
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def main() -> None:
    registry = DIDRegistry()

    def identity(did: str, key_name: str = "key-1") -> tuple[str, str, KeyPair]:
        kp = KeyPair()
        kid = f"{did}#{key_name}"
        registry.register(did, kid, kp.public_bytes)
        return did, kid, kp

    principal_did, principal_kid, principal_kp = identity(
        "did:web:principal-buyer.example"
    )
    agent_kp = KeyPair()
    agent_did = agent_kp.did_key()
    agent_kid = agent_did + "#0"
    registry.register(agent_did, agent_kid, agent_kp.public_bytes)
    operator_did, _, _ = identity("did:web:agent-operator.example")
    supplier_did, supplier_kid, supplier_kp = identity("did:web:supplier.example")
    gateway_did, gateway_kid, gateway_kp = identity("did:web:gateway.example")
    log_did, log_kid, log_kp = identity("did:web:log-operator.example")
    adj_did, adj_kid, adj_kp = identity("did:web:adjudicator.example", "adj-1")

    log = ReceiptLog(log_did, log_kid, log_kp)

    hr("1. Mandate issued (spec section 4.2 values)")
    mandate = issue_mandate(
        principal_did=principal_did,
        principal_kid=principal_kid,
        principal_keypair=principal_kp,
        principal_jurisdiction="AR",
        agent_did=agent_did,
        operator_did=operator_did,
        instruction_text=(
            "Keep industrial supplies stocked; do not overspend; ask me for "
            "anything large."
        ),
        constraints={
            "max_total_amount_minor": 50000000,
            "max_per_tx_amount_minor": 20000000,
            "currency": "ARS",
            "max_transactions": 10,
            "categories": ["industrial_supplies"],
            "counterparties": {"mode": "any"},
            "valid_from": "2026-08-01T00:00:00.000Z",
            "valid_until": "2026-09-30T23:59:59.999Z",
            "human_approval_above_minor": 15000000,
        },
        issued_at="2026-08-01T10:12:03.412Z",
    )
    print(f"mandate_id   : {mandate['mandate_id']}")
    print(f"mandate_hash : {hash_object(mandate)}")

    ident = build_identity(
        agent_did=agent_did,
        software_name="procurement-agent",
        software_version="2.4.1",
        model_provider="anthropic",
        model_id="claude-sonnet-4-6",
        operator_did=operator_did,
        operator_jurisdiction="AR",
    )

    def emit(seq: int, amount: int, when: str, prev: str | None) -> dict:
        receipt = build_receipt(
            mandate=mandate,
            prev_receipt_hash=prev,
            seq=seq,
            identity=ident,
            decision_context=build_decision_context(
                inputs=[f"stock-report-{seq}", f"supplier-quote-{seq}"],
                policy_version="procurement-policy/1.3",
                captured_at=when,
            ),
            terms=build_terms(
                amount_minor=amount,
                currency="ARS",
                category="industrial_supplies",
                counterparty_did=supplier_did,
                counterparty_role="merchant",
                description=f"restock order #{seq}",
                payment_rail="mercadopago",
                rail_tx_ref=f"mp:pay:10000{seq}",
                gateway_did=gateway_did,
            ),
            outcome_status="settled",
            decision_at=when,
            authorized_at=when,
            settled_at=when,
        )
        sign_object(receipt, role="agent", kid=agent_kid, keypair=agent_kp)
        sign_object(receipt, role="counterparty", kid=supplier_kid, keypair=supplier_kp)
        sign_object(receipt, role="witness", kid=gateway_kid, keypair=gateway_kp)
        return receipt

    hr("2. Three in-mandate receipts emitted, chained, anchored")
    prev = None
    receipts = []
    for seq, (amount, when) in enumerate(
        [
            (9000000, "2026-08-03T11:00:00.000Z"),
            (12000000, "2026-08-07T09:30:00.000Z"),
            (7000000, "2026-08-11T16:45:00.000Z"),
        ],
        start=1,
    ):
        r = emit(seq, amount, when, prev)
        prev = log.append(r)
        receipts.append(r)
        print(f"receipt seq={seq} amount_minor={amount:>9}  hash={prev[:23]}…")
    anchor1 = log.anchor(anchored_at="2026-08-11T17:00:00.000Z")
    print(f"anchor #1    : root={anchor1['merkle_root'][:23]}… range={anchor1['range']}")

    hr("3. Scenario A — claim against an in-mandate receipt")
    claim_a = file_claim(
        receipt=receipts[1],
        claimant_did=principal_did,
        claimant_kid=principal_kid,
        claimant_kp=principal_kp,
        asserted_loss_minor=12000000,
        currency="ARS",
        reason="buyer disputes order #2",
    )
    verdict_a = adjudicate(
        claim=claim_a, receipt=receipts[1], mandate=mandate, log=log,
        registry=registry, adjudicator_did=adj_did, adjudicator_kid=adj_kid,
        adjudicator_kp=adj_kp,
    )
    print(f"verdict: {verdict_a['verdict']}  (resolution: {verdict_a['resolution_path']})")

    hr("4. Scenario B — the section-13 incident: ARS 780,000, no approval")
    bad = emit(4, 78000000, "2026-08-14T13:02:11.238Z", prev)
    prev = log.append(bad)
    anchor2 = log.anchor(anchored_at="2026-08-14T13:10:00.000Z")
    print(f"anchor #2    : root={anchor2['merkle_root'][:23]}… range={anchor2['range']}")

    claim_b = file_claim(
        receipt=bad,
        claimant_did=principal_did,
        claimant_kid=principal_kid,
        claimant_kp=principal_kp,
        asserted_loss_minor=78000000,
        currency="ARS",
        reason="unauthorized spend: never approved anything near this amount",
    )
    verdict_b = adjudicate(
        claim=claim_b, receipt=bad, mandate=mandate, log=log, registry=registry,
        adjudicator_did=adj_did, adjudicator_kid=adj_kid, adjudicator_kp=adj_kp,
    )
    print(json.dumps(
        {k: verdict_b[k] for k in ("checks", "verdict", "violations", "resolution_path")},
        indent=2, ensure_ascii=False,
    ))

    hr("5. Scenario C — operator tampers with the logged receipt afterward")
    # Mutating the stored object breaks its own hash, its signatures, and the
    # anchored Merkle path all at once; D1 catches it immediately.
    bad["terms"]["amount_minor"] = 18000000
    verdict_c = adjudicate(
        claim=claim_b, receipt=bad,
        mandate=mandate, log=log, registry=registry,
        adjudicator_did=adj_did, adjudicator_kid=adj_kid, adjudicator_kp=adj_kp,
    )
    print(f"verdict: {verdict_c['verdict']}")
    print(f"D1     : {verdict_c['checks'].get('D1_signatures')}")

    hr("Summary")
    print(f"A (in-mandate)        -> {verdict_a['verdict']}")
    print(f"B (section-13 breach) -> {verdict_b['verdict']} "
          f"({len(verdict_b['violations'])} typed violations, auto-resolved)")
    print(f"C (tampered evidence) -> {verdict_c['verdict']}")


if __name__ == "__main__":
    main()
