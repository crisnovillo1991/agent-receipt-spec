"""Reference HTTP facade (FastAPI) over the core library.

In-memory, single-process, no auth — a demonstrator of the interface shape,
not a deployable service. Run with:

    uvicorn air_evidence.api:app --reload
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .adjudicator import adjudicate, file_claim
from .chain import ReceiptLog
from .crypto import DIDRegistry, KeyPair, hash_object
from .demo_api import router as demo_router

app = FastAPI(title="AIR Evidence Profile — reference API", version="0.1")
app.include_router(demo_router)

_STATIC = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
def console() -> FileResponse:
    """The visual evidence console (demo UI)."""
    return FileResponse(_STATIC / "index.html")

# --- service-owned identities (regenerated on boot; reference only) --------
registry = DIDRegistry()

_log_kp = KeyPair()
LOG_DID = "did:web:log-operator.example"
LOG_KID = LOG_DID + "#key-1"
registry.register(LOG_DID, LOG_KID, _log_kp.public_bytes)

_adj_kp = KeyPair()
ADJ_DID = "did:web:adjudicator.example"
ADJ_KID = ADJ_DID + "#adj-1"
registry.register(ADJ_DID, ADJ_KID, _adj_kp.public_bytes)

log = ReceiptLog(LOG_DID, LOG_KID, _log_kp)
mandates: dict[str, dict[str, Any]] = {}
claims: dict[str, dict[str, Any]] = {}


class KeyRegistration(BaseModel):
    did: str
    kid: str
    public_key_b64url: str


@app.post("/registry/keys")
def register_key(body: KeyRegistration) -> dict[str, str]:
    from .crypto import b64url_decode

    registry.register(body.did, body.kid, b64url_decode(body.public_key_b64url))
    return {"registered": body.kid}


@app.post("/mandates")
def post_mandate(mandate: dict[str, Any]) -> dict[str, str]:
    if mandate.get("type") != "mandate":
        raise HTTPException(422, "not a mandate object")
    mandates[mandate["mandate_id"]] = mandate
    return {"mandate_id": mandate["mandate_id"], "mandate_hash": hash_object(mandate)}


@app.post("/receipts")
def post_receipt(receipt: dict[str, Any]) -> dict[str, str]:
    try:
        rh = log.append(receipt)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    return {"receipt_hash": rh, "seq": str(receipt["seq"])}


@app.post("/anchors")
def post_anchor() -> dict[str, Any]:
    try:
        anchor = log.anchor()
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    return {"merkle_root": anchor["merkle_root"], "range": anchor["range"]}


@app.get("/receipts/{receipt_hash}/proof")
def get_proof(receipt_hash: str) -> dict[str, Any]:
    proof = log.inclusion_proof(receipt_hash)
    if proof is None:
        raise HTTPException(404, "receipt not anchored (or unknown)")
    return {
        "leaf_index": proof["leaf_index"],
        "path": proof["path"],
        "merkle_root": proof["anchor"]["merkle_root"],
        "anchored_at": proof["anchor"]["anchored_at"],
    }


class ClaimRequest(BaseModel):
    receipt_hash: str
    mandate_id: str
    claimant_did: str
    asserted_loss_minor: int
    currency: str
    reason: str


@app.post("/claims")
def post_claim(body: ClaimRequest) -> dict[str, Any]:
    receipt = log.by_hash.get(body.receipt_hash)
    if receipt is None:
        raise HTTPException(404, "unknown receipt")
    mandate = mandates.get(body.mandate_id)
    if mandate is None:
        raise HTTPException(404, "unknown mandate")

    # The service signs the claim intake on the claimant's behalf here only
    # because the reference API holds no client keys; a real deployment
    # requires the claimant's own signature on the claim object.
    intake_kp = KeyPair()
    intake_kid = body.claimant_did + "#intake-1"
    registry.register(body.claimant_did, intake_kid, intake_kp.public_bytes)

    claim = file_claim(
        receipt=receipt,
        claimant_did=body.claimant_did,
        claimant_kid=intake_kid,
        claimant_kp=intake_kp,
        asserted_loss_minor=body.asserted_loss_minor,
        currency=body.currency,
        reason=body.reason,
    )
    claims[claim["claim_id"]] = claim

    adjudication = adjudicate(
        claim=claim,
        receipt=receipt,
        mandate=mandate,
        log=log,
        registry=registry,
        adjudicator_did=ADJ_DID,
        adjudicator_kid=ADJ_KID,
        adjudicator_kp=_adj_kp,
    )
    return adjudication
