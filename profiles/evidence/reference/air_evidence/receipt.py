"""Receipt construction (spec sections 5-9)."""

from __future__ import annotations

import uuid
from typing import Any

from .canonical import canonicalize
from .crypto import KeyPair, hash_object, hash_text, now_iso, sign_object


def build_identity(
    *,
    agent_did: str,
    software_name: str,
    software_version: str,
    model_provider: str,
    model_id: str,
    operator_did: str,
    operator_jurisdiction: str,
) -> dict[str, Any]:
    return {
        "agent_id": agent_did,
        "software": {
            "name": software_name,
            "version": software_version,
            "build_hash": hash_text(f"{software_name}@{software_version}"),
        },
        "model": {
            "provider": model_provider,
            "model_id": model_id,
            "config_hash": hash_text(f"config:{software_name}@{software_version}"),
        },
        "operator": {
            "id": operator_did,
            "legal_entity": {
                "jurisdiction": operator_jurisdiction,
                "registration_hash": hash_text(f"registration:{operator_did}"),
            },
        },
    }


def build_decision_context(
    *, inputs: list[str], policy_version: str, captured_at: str | None = None
) -> dict[str, Any]:
    """Commit to the agent's inputs without revealing them (spec section 6)."""
    leaf_hashes = [hash_text(i) for i in inputs]
    manifest = {"input_count": len(inputs), "input_types": ["text"] * len(inputs)}
    return {
        "inputs_commitment": hash_text("|".join(leaf_hashes)),
        "inputs_manifest_hash": "sha256:"
        + __import__("hashlib").sha256(canonicalize(manifest)).hexdigest(),
        "policy_version": policy_version,
        "captured_at": captured_at or now_iso(),
    }


def build_terms(
    *,
    amount_minor: int,
    currency: str,
    category: str,
    counterparty_did: str,
    counterparty_role: str,
    description: str,
    payment_rail: str,
    rail_tx_ref: str,
    gateway_did: str,
) -> dict[str, Any]:
    return {
        "amount_minor": amount_minor,
        "currency": currency,
        "category": category,
        "counterparty": {"id": counterparty_did, "role": counterparty_role},
        "description_hash": hash_text(description),
        "line_items_hash": hash_text("items:" + description),
        "payment": {
            "rail": payment_rail,
            "rail_tx_ref": rail_tx_ref,
            "gateway_id": gateway_did,
        },
    }


def terms_hash(terms: dict[str, Any]) -> str:
    return "sha256:" + __import__("hashlib").sha256(canonicalize(terms)).hexdigest()


def human_approval(
    *,
    terms: dict[str, Any],
    principal_kid: str,
    principal_keypair: KeyPair,
    approved_at: str | None = None,
) -> dict[str, Any]:
    """Fresh principal signature over the specific terms hash (spec 4.3)."""
    block: dict[str, Any] = {
        "terms_hash": terms_hash(terms),
        "approved_at": approved_at or now_iso(),
    }
    sign_object(block, role="principal", kid=principal_kid, keypair=principal_keypair)
    return block


def build_receipt(
    *,
    mandate: dict[str, Any],
    prev_receipt_hash: str | None,
    seq: int,
    identity: dict[str, Any],
    decision_context: dict[str, Any],
    terms: dict[str, Any],
    outcome_status: str,
    decision_at: str,
    authorized_at: str,
    settled_at: str | None,
    human_approval_block: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the unsigned envelope (spec section 9). Callers then attach
    agent / counterparty / witness signatures with crypto.sign_object."""
    return {
        "profile": "air-evidence/0.1",
        "air_version": "0.3",
        "type": "transaction_receipt",
        "receipt_id": str(uuid.uuid4()),
        "mandate_ref": {
            "mandate_id": mandate["mandate_id"],
            "mandate_hash": hash_object(mandate),
        },
        "prev_receipt_hash": prev_receipt_hash,
        "seq": seq,
        "identity": identity,
        "decision_context": decision_context,
        "terms": terms,
        "outcome": {
            "status": outcome_status,
            "settled_at": settled_at,
            "delivery": {"expected_by": None, "confirmation_hash": None},
        },
        "timestamps": {
            "decision_at": decision_at,
            "authorized_at": authorized_at,
            "settled_at": settled_at,
        },
        "human_approval": human_approval_block,
        "refs": [],
    }
