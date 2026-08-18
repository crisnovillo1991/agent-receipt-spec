"""Deterministic adjudication D1-D6 (spec section 11).

Pure functions over signed data. The only exit to human review is the
explicit INDETERMINATE verdict.
"""

from __future__ import annotations

import uuid
from typing import Any

from .canonical import canonicalize
from .chain import MerkleTree, ReceiptLog, _leaf_bytes
from .crypto import DIDRegistry, KeyPair, hash_object, now_iso, sign_object, verify_signature
from .mandate import KNOWN_CONSTRAINTS
from .receipt import terms_hash

WITHIN_MANDATE = "WITHIN_MANDATE"
EXCEEDED_MANDATE = "EXCEEDED_MANDATE"
INVALID_EVIDENCE = "INVALID_EVIDENCE"
BROKEN_CHAIN = "BROKEN_CHAIN"
MANDATE_MISMATCH = "MANDATE_MISMATCH"
EXPIRED_MANDATE = "EXPIRED_MANDATE"
INDETERMINATE = "INDETERMINATE"


def _sig_by_role(obj: dict[str, Any], role: str) -> dict[str, Any] | None:
    for s in obj.get("signatures", []):
        if s.get("role") == role:
            return s
    return None


def _verify_role(
    obj: dict[str, Any], role: str, registry: DIDRegistry
) -> tuple[bool, str]:
    sig = _sig_by_role(obj, role)
    if sig is None:
        return False, f"missing {role} signature"
    pub = registry.resolve(sig.get("kid", ""))
    if pub is None:
        return False, f"unresolvable kid for {role}: {sig.get('kid')}"
    if not verify_signature(obj, sig, pub):
        return False, f"{role} signature does not verify"
    return True, "ok"


def adjudicate(
    *,
    claim: dict[str, Any],
    receipt: dict[str, Any],
    mandate: dict[str, Any],
    log: ReceiptLog,
    registry: DIDRegistry,
    adjudicator_did: str,
    adjudicator_kid: str,
    adjudicator_kp: KeyPair,
) -> dict[str, Any]:
    checks: dict[str, str] = {}
    violations: list[dict[str, Any]] = []
    verdict: str | None = None

    # ---- D1: signatures --------------------------------------------------
    d1_msgs = []
    for role in ("agent", "counterparty"):
        ok, msg = _verify_role(receipt, role, registry)
        if not ok:
            d1_msgs.append(msg)
    if _sig_by_role(receipt, "witness") is not None:
        ok, msg = _verify_role(receipt, "witness", registry)
        if not ok:
            d1_msgs.append(msg)
    rh = hash_object(receipt)
    if log.by_hash.get(rh) is None:
        d1_msgs.append("receipt hash not present in log (content altered?)")
    if d1_msgs:
        checks["D1_signatures"] = "FAIL: " + "; ".join(d1_msgs)
        verdict = INVALID_EVIDENCE
    else:
        checks["D1_signatures"] = "PASS"

    # ---- D2: chain integrity + anchoring ---------------------------------
    if verdict is None:
        agent = receipt["identity"]["agent_id"]
        proof = log.inclusion_proof(rh)
        if not log.verify_stream(agent):
            checks["D2_chain"] = "FAIL: agent stream broken (prev/seq/hash mismatch)"
            verdict = BROKEN_CHAIN
        elif proof is None:
            checks["D2_chain"] = "FAIL: receipt not covered by any anchor"
            verdict = BROKEN_CHAIN
        else:
            anchor = proof["anchor"]
            ok_anchor, msg = _verify_role(anchor, "log_operator", registry)
            ok_path = MerkleTree.verify(
                _leaf_bytes(rh), proof["path"], anchor["merkle_root"]
            )
            if not (ok_anchor and ok_path):
                checks["D2_chain"] = f"FAIL: anchor/{msg} path_ok={ok_path}"
                verdict = BROKEN_CHAIN
            else:
                checks["D2_chain"] = (
                    f"PASS (anchored: {anchor['anchor_method']} "
                    f"{anchor['anchored_at']})"
                )

    # ---- D3: mandate resolution ------------------------------------------
    if verdict is None:
        if receipt["mandate_ref"]["mandate_hash"] != hash_object(mandate):
            checks["D3_mandate"] = "FAIL: mandate_hash mismatch"
            verdict = MANDATE_MISMATCH
        else:
            ok, msg = _verify_role(mandate, "principal", registry)
            if not ok:
                checks["D3_mandate"] = f"FAIL: {msg}"
                verdict = MANDATE_MISMATCH
            else:
                checks["D3_mandate"] = "PASS (mandate_hash match)"

    constraints = mandate["authorization"]["constraints"]

    # ---- D4: temporal validity --------------------------------------------
    if verdict is None:
        decision_at = receipt["timestamps"]["decision_at"]
        if not (constraints["valid_from"] <= decision_at <= constraints["valid_until"]):
            checks["D4_temporal"] = (
                f"FAIL: decision_at {decision_at} outside mandate window"
            )
            verdict = EXPIRED_MANDATE
        else:
            checks["D4_temporal"] = "PASS"

    # ---- D6 (evaluated before D5 verdicts are final): unknown constraints -
    unknown = set(constraints.keys()) - KNOWN_CONSTRAINTS
    if verdict is None and unknown:
        checks["D6_unknown_constraints"] = (
            f"FAIL: adjudicator does not understand {sorted(unknown)}; fail-safe"
        )
        verdict = INDETERMINATE

    # ---- D5: typed constraint evaluation -----------------------------------
    if verdict is None:
        t = receipt["terms"]

        if t["currency"] != constraints["currency"]:
            violations.append(
                {
                    "constraint": "currency",
                    "expected": constraints["currency"],
                    "actual": t["currency"],
                }
            )

        per_tx = constraints.get("max_per_tx_amount_minor")
        if per_tx is not None and t["amount_minor"] > per_tx:
            violations.append(
                {
                    "constraint": "max_per_tx_amount_minor",
                    "expected": per_tx,
                    "actual": t["amount_minor"],
                }
            )

        # cumulative totals: settled receipts under this mandate up to and
        # including the disputed one, in log order
        settled = [
            r
            for r in log.entries
            if r["mandate_ref"]["mandate_id"] == mandate["mandate_id"]
            and r["outcome"]["status"] == "settled"
            and r["seq"] <= receipt["seq"]
            and r["identity"]["agent_id"] == receipt["identity"]["agent_id"]
        ]
        total = sum(r["terms"]["amount_minor"] for r in settled)
        if total > constraints["max_total_amount_minor"]:
            violations.append(
                {
                    "constraint": "max_total_amount_minor",
                    "expected": constraints["max_total_amount_minor"],
                    "actual": total,
                }
            )

        max_tx = constraints.get("max_transactions")
        if max_tx is not None and len(settled) > max_tx:
            violations.append(
                {
                    "constraint": "max_transactions",
                    "expected": max_tx,
                    "actual": len(settled),
                }
            )

        if t["category"] not in constraints["categories"]:
            violations.append(
                {
                    "constraint": "categories",
                    "expected": constraints["categories"],
                    "actual": t["category"],
                }
            )

        cp = constraints["counterparties"]
        if cp.get("mode") == "allowlist" and t["counterparty"]["id"] not in cp.get(
            "ids", []
        ):
            violations.append(
                {
                    "constraint": "counterparties",
                    "expected": cp.get("ids", []),
                    "actual": t["counterparty"]["id"],
                }
            )

        threshold = constraints.get("human_approval_above_minor")
        if threshold is not None and t["amount_minor"] > threshold:
            ha = receipt.get("human_approval")
            ha_ok = False
            if ha is not None and ha.get("terms_hash") == terms_hash(t):
                ok, _ = _verify_role(ha, "principal", registry)
                ha_ok = ok
            if not ha_ok:
                violations.append(
                    {
                        "constraint": "human_approval_above_minor",
                        "expected": (
                            "principal signature over terms_hash for amounts "
                            f"> {threshold}"
                        ),
                        "actual": "human_approval: "
                        + ("invalid" if ha else "null"),
                    }
                )

        checks["D5_constraints"] = (
            "PASS" if not violations else f"FAIL: {len(violations)} violation(s)"
        )
        verdict = EXCEEDED_MANDATE if violations else WITHIN_MANDATE

    adjudication: dict[str, Any] = {
        "profile": "air-evidence/0.1",
        "type": "adjudication",
        "adjudication_id": str(uuid.uuid4()),
        "adjudicator": adjudicator_did,
        "refs": [hash_object(claim), rh],
        "checks": checks,
        "verdict": verdict,
        "violations": violations,
        "resolution_path": "auto" if verdict != INDETERMINATE else "human_review",
        "adjudicated_at": now_iso(),
    }
    sign_object(
        adjudication, role="adjudicator", kid=adjudicator_kid, keypair=adjudicator_kp
    )
    return adjudication


def file_claim(
    *,
    receipt: dict[str, Any],
    claimant_did: str,
    claimant_kid: str,
    claimant_kp: KeyPair,
    asserted_loss_minor: int,
    currency: str,
    reason: str,
) -> dict[str, Any]:
    claim: dict[str, Any] = {
        "profile": "air-evidence/0.1",
        "type": "claim",
        "claim_id": str(uuid.uuid4()),
        "claimant": claimant_did,
        "refs": [hash_object(receipt)],
        "asserted_loss_minor": asserted_loss_minor,
        "currency": currency,
        "reason_hash": __import__("air_evidence.crypto", fromlist=["hash_text"]).hash_text(reason),
        "filed_at": now_iso(),
    }
    sign_object(claim, role="claimant", kid=claimant_kid, keypair=claimant_kp)
    return claim
