"""Demo world for the visual console (served at /).

Holds a self-contained cast of fictitious `.example` identities server-side
so the browser can drive the full flow — issue receipts, anchor, tamper,
claim — without doing Ed25519 in JavaScript. Reference/demo only.
"""

from __future__ import annotations

import random
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .adjudicator import adjudicate, file_claim
from .chain import ReceiptLog
from .crypto import DIDRegistry, KeyPair, hash_object, sign_object
from .mandate import issue_mandate
from .receipt import (
    build_decision_context,
    build_identity,
    build_receipt,
    build_terms,
    human_approval,
)

router = APIRouter(prefix="/demo", tags=["demo"])


class DemoWorld:
    def __init__(self) -> None:
        self.registry = DIDRegistry()
        self.parties: dict[str, tuple[str, KeyPair]] = {}

        def make(did: str, key_name: str = "key-1") -> None:
            kp = KeyPair()
            kid = f"{did}#{key_name}"
            self.registry.register(did, kid, kp.public_bytes)
            self.parties[did] = (kid, kp)

        make("did:web:principal-buyer.example")
        make("did:web:supplier.example")
        make("did:web:gateway.example")
        make("did:web:log-operator.example")
        make("did:web:adjudicator.example", "adj-1")

        agent_kp = KeyPair()
        self.agent_did = agent_kp.did_key()
        agent_kid = self.agent_did + "#0"
        self.registry.register(self.agent_did, agent_kid, agent_kp.public_bytes)
        self.parties[self.agent_did] = (agent_kid, agent_kp)

        log_kid, log_kp = self.parties["did:web:log-operator.example"]
        self.log = ReceiptLog("did:web:log-operator.example", log_kid, log_kp)

        p_kid, p_kp = self.parties["did:web:principal-buyer.example"]
        self.mandate = issue_mandate(
            principal_did="did:web:principal-buyer.example",
            principal_kid=p_kid,
            principal_keypair=p_kp,
            principal_jurisdiction="AR",
            agent_did=self.agent_did,
            operator_did="did:web:agent-operator.example",
            instruction_text=(
                "Keep industrial supplies stocked; do not overspend; ask me "
                "for anything large."
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
        self.identity = build_identity(
            agent_did=self.agent_did,
            software_name="procurement-agent",
            software_version="2.4.1",
            model_provider="anthropic",
            model_id="claude-sonnet-4-6",
            operator_did="did:web:agent-operator.example",
            operator_jurisdiction="AR",
        )
        self.original_hashes: list[str] = []  # log-order, as appended
        self.tampered: set[str] = set()
        self.seq = 0
        self.prev: str | None = None

    # ------------------------------------------------------------------ #
    def issue(self, amount_minor: int, with_approval: bool) -> dict[str, Any]:
        from .crypto import now_iso

        self.seq += 1
        when = now_iso()
        terms = build_terms(
            amount_minor=amount_minor,
            currency="ARS",
            category="industrial_supplies",
            counterparty_did="did:web:supplier.example",
            counterparty_role="merchant",
            description=f"restock order #{self.seq}",
            payment_rail="mercadopago",
            rail_tx_ref=f"mp:pay:10000{self.seq}",
            gateway_did="did:web:gateway.example",
        )
        approval = None
        if with_approval:
            p_kid, p_kp = self.parties["did:web:principal-buyer.example"]
            approval = human_approval(
                terms=terms, principal_kid=p_kid, principal_keypair=p_kp
            )
        receipt = build_receipt(
            mandate=self.mandate,
            prev_receipt_hash=self.prev,
            seq=self.seq,
            identity=self.identity,
            decision_context=build_decision_context(
                inputs=[f"stock-report-{self.seq}", f"supplier-quote-{self.seq}"],
                policy_version="procurement-policy/1.3",
                captured_at=when,
            ),
            terms=terms,
            outcome_status="settled",
            decision_at=when,
            authorized_at=when,
            settled_at=when,
            human_approval_block=approval,
        )
        for did, role in (
            (self.agent_did, "agent"),
            ("did:web:supplier.example", "counterparty"),
            ("did:web:gateway.example", "witness"),
        ):
            kid, kp = self.parties[did]
            sign_object(receipt, role=role, kid=kid, keypair=kp)
        rh = self.log.append(receipt)
        self.original_hashes.append(rh)
        self.prev = rh
        return {"receipt_hash": rh, "seq": self.seq}

    def state(self) -> dict[str, Any]:
        anchored: set[str] = set()
        for a in self.log.anchors:
            anchored.update(a["receipt_hashes"])
        receipts = []
        for rh in self.original_hashes:
            r = self.log.by_hash[rh]
            receipts.append(
                {
                    "hash": rh,
                    "seq": r["seq"],
                    "amount_minor": r["terms"]["amount_minor"],
                    "prev": r["prev_receipt_hash"],
                    "anchored": rh in anchored,
                    "tampered": rh in self.tampered,
                    "human_approval": r.get("human_approval") is not None,
                    "settled_at": r["timestamps"]["settled_at"],
                }
            )
        c = self.mandate["authorization"]["constraints"]
        spent = sum(
            r["terms"]["amount_minor"]
            for h, r in ((h, self.log.by_hash[h]) for h in self.original_hashes)
            if h not in self.tampered
        )
        return {
            "mandate": {
                "mandate_id": self.mandate["mandate_id"],
                "mandate_hash": hash_object(self.mandate),
                "constraints": c,
                "principal": self.mandate["principal"]["id"],
                "agent": self.agent_did,
            },
            "receipts": receipts,
            "anchors": [
                {"merkle_root": a["merkle_root"], "range": a["range"],
                 "anchored_at": a["anchored_at"]}
                for a in self.log.anchors
            ],
            "spent_minor": spent,
            "unanchored_count": len(self.original_hashes) - len(anchored),
        }


world = DemoWorld()


class IssueRequest(BaseModel):
    amount_minor: int | None = None
    with_approval: bool = False


class TamperRequest(BaseModel):
    new_amount_minor: int = 18000000


class ClaimRequest(BaseModel):
    receipt_hash: str


@router.post("/reset")
def reset() -> dict[str, str]:
    global world
    world = DemoWorld()
    return {"status": "world reset"}


@router.get("/state")
def state() -> dict[str, Any]:
    return world.state()


@router.post("/receipts")
def issue(body: IssueRequest) -> dict[str, Any]:
    amount = body.amount_minor or random.randrange(5000000, 14000000, 500000)
    if amount <= 0:
        raise HTTPException(422, "amount_minor must be positive")
    return world.issue(amount, body.with_approval)


@router.post("/anchor")
def anchor() -> dict[str, Any]:
    try:
        a = world.log.anchor()
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    return {"merkle_root": a["merkle_root"], "range": a["range"]}


@router.post("/tamper")
def tamper(body: TamperRequest) -> dict[str, Any]:
    if not world.original_hashes:
        raise HTTPException(409, "no receipts to tamper with")
    rh = world.original_hashes[-1]
    receipt = world.log.by_hash[rh]
    before = receipt["terms"]["amount_minor"]
    receipt["terms"]["amount_minor"] = body.new_amount_minor
    world.tampered.add(rh)
    return {
        "receipt_hash": rh,
        "amount_before": before,
        "amount_after": body.new_amount_minor,
        "note": "stored receipt mutated post-hoc; its hash, signatures and "
        "Merkle path are now all inconsistent",
    }


@router.post("/claim")
def claim(body: ClaimRequest) -> dict[str, Any]:
    receipt = world.log.by_hash.get(body.receipt_hash)
    if receipt is None:
        raise HTTPException(404, "unknown receipt")
    p_kid, p_kp = world.parties["did:web:principal-buyer.example"]
    claim_obj = file_claim(
        receipt=receipt,
        claimant_did="did:web:principal-buyer.example",
        claimant_kid=p_kid,
        claimant_kp=p_kp,
        asserted_loss_minor=receipt["terms"]["amount_minor"],
        currency="ARS",
        reason="principal disputes this transaction",
    )
    adj_kid, adj_kp = world.parties["did:web:adjudicator.example"]
    return adjudicate(
        claim=claim_obj,
        receipt=receipt,
        mandate=world.mandate,
        log=world.log,
        registry=world.registry,
        adjudicator_did="did:web:adjudicator.example",
        adjudicator_kid=adj_kid,
        adjudicator_kp=adj_kp,
    )
