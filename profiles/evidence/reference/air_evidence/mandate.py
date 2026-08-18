"""Mandate issuance (spec section 4).

The free-text instruction is preserved only as a hash; adjudication runs
exclusively against the typed `constraints` object (spec 4.1).
"""

from __future__ import annotations

import uuid
from typing import Any

from .crypto import KeyPair, hash_text, now_iso, sign_object

#: Constraint fields the 0.1 adjudicator understands. Anything else in a
#: mandate's constraints triggers INDETERMINATE (fail-safe, spec 4.3 / D6).
KNOWN_CONSTRAINTS = {
    "max_total_amount_minor",
    "max_per_tx_amount_minor",
    "currency",
    "max_transactions",
    "categories",
    "counterparties",
    "valid_from",
    "valid_until",
    "human_approval_above_minor",
}

REQUIRED_CONSTRAINTS = {
    "max_total_amount_minor",
    "currency",
    "categories",
    "counterparties",
    "valid_from",
    "valid_until",
}


def issue_mandate(
    *,
    principal_did: str,
    principal_kid: str,
    principal_keypair: KeyPair,
    principal_jurisdiction: str,
    agent_did: str,
    operator_did: str,
    instruction_text: str,
    constraints: dict[str, Any],
    issued_at: str | None = None,
) -> dict[str, Any]:
    missing = REQUIRED_CONSTRAINTS - constraints.keys()
    if missing:
        raise ValueError(f"mandate missing required constraints: {sorted(missing)}")

    mandate: dict[str, Any] = {
        "profile": "air-evidence/0.1",
        "air_version": "0.3",
        "type": "mandate",
        "mandate_id": str(uuid.uuid4()),
        "principal": {
            "id": principal_did,
            "legal_entity": {
                "jurisdiction": principal_jurisdiction,
                "registration_hash": hash_text(f"registration:{principal_did}"),
            },
        },
        "agent_id": agent_did,
        "operator_id": operator_did,
        "authorization": {
            "instruction_hash": hash_text(instruction_text),
            "constraints": constraints,
        },
        "issued_at": issued_at or now_iso(),
    }
    sign_object(
        mandate, role="principal", kid=principal_kid, keypair=principal_keypair
    )
    return mandate
