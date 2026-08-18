"""Adjudicator conformance tests: one test per verdict class (spec section 11),
plus canonicalization guarantees."""

from __future__ import annotations

import pytest

from air_evidence.adjudicator import (
    BROKEN_CHAIN,
    EXCEEDED_MANDATE,
    EXPIRED_MANDATE,
    INDETERMINATE,
    INVALID_EVIDENCE,
    WITHIN_MANDATE,
    adjudicate,
    file_claim,
)
from air_evidence.canonical import canonicalize
from air_evidence.chain import ReceiptLog
from air_evidence.crypto import DIDRegistry, KeyPair, hash_object, sign_object
from air_evidence.mandate import issue_mandate
from air_evidence.receipt import (
    build_decision_context,
    build_identity,
    build_receipt,
    build_terms,
    human_approval,
)

WHEN = "2026-08-14T13:02:11.238Z"


@pytest.fixture()
def world():
    registry = DIDRegistry()
    parties = {}

    def make(did, key_name="key-1"):
        kp = KeyPair()
        kid = f"{did}#{key_name}"
        registry.register(did, kid, kp.public_bytes)
        parties[did] = (kid, kp)
        return did, kid, kp

    principal = make("did:web:principal-buyer.example")
    agent_kp = KeyPair()
    agent_did = agent_kp.did_key()
    agent_kid = agent_did + "#0"
    registry.register(agent_did, agent_kid, agent_kp.public_bytes)
    supplier = make("did:web:supplier.example")
    gateway = make("did:web:gateway.example")
    logop = make("did:web:log-operator.example")
    adj = make("did:web:adjudicator.example", "adj-1")
    make("did:web:agent-operator.example")

    log = ReceiptLog(*logop)
    return {
        "registry": registry,
        "log": log,
        "principal": principal,
        "agent": (agent_did, agent_kid, agent_kp),
        "supplier": supplier,
        "gateway": gateway,
        "adj": adj,
    }


def make_mandate(w, extra_constraints=None, **overrides):
    constraints = {
        "max_total_amount_minor": 50000000,
        "max_per_tx_amount_minor": 20000000,
        "currency": "ARS",
        "max_transactions": 10,
        "categories": ["industrial_supplies"],
        "counterparties": {"mode": "any"},
        "valid_from": "2026-08-01T00:00:00.000Z",
        "valid_until": "2026-09-30T23:59:59.999Z",
        "human_approval_above_minor": 15000000,
    }
    constraints.update(extra_constraints or {})
    p_did, p_kid, p_kp = w["principal"]
    return issue_mandate(
        principal_did=p_did,
        principal_kid=p_kid,
        principal_keypair=p_kp,
        principal_jurisdiction="AR",
        agent_did=w["agent"][0],
        operator_did="did:web:agent-operator.example",
        instruction_text="keep supplies stocked",
        constraints=constraints,
        **overrides,
    )


def make_receipt(w, mandate, *, amount, seq=1, prev=None, when=WHEN, approval=None,
                 category="industrial_supplies"):
    a_did, a_kid, a_kp = w["agent"]
    s_did, s_kid, s_kp = w["supplier"]
    g_did, g_kid, g_kp = w["gateway"]
    receipt = build_receipt(
        mandate=mandate,
        prev_receipt_hash=prev,
        seq=seq,
        identity=build_identity(
            agent_did=a_did, software_name="procurement-agent",
            software_version="2.4.1", model_provider="anthropic",
            model_id="claude-sonnet-4-6",
            operator_did="did:web:agent-operator.example",
            operator_jurisdiction="AR",
        ),
        decision_context=build_decision_context(
            inputs=["q"], policy_version="p/1", captured_at=when
        ),
        terms=build_terms(
            amount_minor=amount, currency="ARS", category=category,
            counterparty_did=s_did, counterparty_role="merchant",
            description=f"order-{seq}", payment_rail="mercadopago",
            rail_tx_ref=f"mp:pay:{seq}", gateway_did=g_did,
        ),
        outcome_status="settled",
        decision_at=when, authorized_at=when, settled_at=when,
        human_approval_block=approval,
    )
    sign_object(receipt, role="agent", kid=a_kid, keypair=a_kp)
    sign_object(receipt, role="counterparty", kid=s_kid, keypair=s_kp)
    sign_object(receipt, role="witness", kid=g_kid, keypair=g_kp)
    return receipt


def run(w, mandate, receipt):
    p_did, p_kid, p_kp = w["principal"]
    claim = file_claim(
        receipt=receipt, claimant_did=p_did, claimant_kid=p_kid, claimant_kp=p_kp,
        asserted_loss_minor=receipt["terms"]["amount_minor"], currency="ARS",
        reason="test claim",
    )
    a_did, a_kid, a_kp = w["adj"]
    return adjudicate(
        claim=claim, receipt=receipt, mandate=mandate, log=w["log"],
        registry=w["registry"], adjudicator_did=a_did, adjudicator_kid=a_kid,
        adjudicator_kp=a_kp,
    )


def test_within_mandate(world):
    m = make_mandate(world)
    r = make_receipt(world, m, amount=12000000)
    world["log"].append(r)
    world["log"].anchor()
    v = run(world, m, r)
    assert v["verdict"] == WITHIN_MANDATE
    assert v["violations"] == []
    assert v["resolution_path"] == "auto"


def test_exceeded_mandate_two_violations(world):
    m = make_mandate(world)
    r = make_receipt(world, m, amount=78000000)  # > per-tx cap, no approval
    world["log"].append(r)
    world["log"].anchor()
    v = run(world, m, r)
    assert v["verdict"] == EXCEEDED_MANDATE
    names = {viol["constraint"] for viol in v["violations"]}
    assert names == {"max_per_tx_amount_minor", "human_approval_above_minor",
                     "max_total_amount_minor"}


def test_human_approval_satisfies_threshold(world):
    m = make_mandate(world, extra_constraints={"max_per_tx_amount_minor": 20000000})
    p_did, p_kid, p_kp = world["principal"]
    # amount above approval threshold but below per-tx cap, WITH approval
    from air_evidence.receipt import build_terms as _bt  # terms must match block
    r_terms_amount = 18000000
    receipt = make_receipt(world, m, amount=r_terms_amount, approval=None)
    approval = human_approval(
        terms=receipt["terms"], principal_kid=p_kid, principal_keypair=p_kp
    )
    receipt = make_receipt(world, m, amount=r_terms_amount, approval=approval)
    world["log"].append(receipt)
    world["log"].anchor()
    v = run(world, m, receipt)
    assert v["verdict"] == WITHIN_MANDATE


def test_expired_mandate(world):
    m = make_mandate(world)
    r = make_receipt(world, m, amount=1000000, when="2026-10-05T00:00:00.000Z")
    world["log"].append(r)
    world["log"].anchor()
    v = run(world, m, r)
    assert v["verdict"] == EXPIRED_MANDATE


def test_unknown_constraint_is_indeterminate(world):
    m = make_mandate(world, extra_constraints={"max_velocity_per_hour": 3})
    r = make_receipt(world, m, amount=1000000)
    world["log"].append(r)
    world["log"].anchor()
    v = run(world, m, r)
    assert v["verdict"] == INDETERMINATE
    assert v["resolution_path"] == "human_review"


def test_tampered_receipt_is_invalid_evidence(world):
    m = make_mandate(world)
    r = make_receipt(world, m, amount=1000000)
    world["log"].append(r)
    world["log"].anchor()
    r["terms"]["amount_minor"] = 999
    v = run(world, m, r)
    assert v["verdict"] == INVALID_EVIDENCE


def test_unanchored_receipt_is_broken_chain(world):
    m = make_mandate(world)
    r = make_receipt(world, m, amount=1000000)
    world["log"].append(r)  # appended but never anchored
    v = run(world, m, r)
    assert v["verdict"] == BROKEN_CHAIN


def test_category_violation(world):
    m = make_mandate(world)
    r = make_receipt(world, m, amount=1000000, category="office_snacks")
    world["log"].append(r)
    world["log"].anchor()
    v = run(world, m, r)
    assert v["verdict"] == EXCEEDED_MANDATE
    assert v["violations"][0]["constraint"] == "categories"


def test_canonicalization_rejects_floats():
    with pytest.raises(TypeError):
        canonicalize({"amount": 1.5})


def test_canonicalization_is_deterministic():
    a = canonicalize({"b": 1, "a": [True, None, "ñ"]})
    b = canonicalize({"a": [True, None, "ñ"], "b": 1})
    assert a == b == '{"a":[true,null,"ñ"],"b":1}'.encode("utf-8")
