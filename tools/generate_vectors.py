#!/usr/bin/env python3
"""Generate the normative test vectors for AIR v0.1 + v0.2.

Deterministic: fixed key, fixed timestamps, fixed content — running twice
yields byte-identical vectors; `expected.json` records every hash/outcome.
v0.1 vectors (01–03, 10–12) are byte-identical to the v0.1 release.

The private key below is PUBLIC BY DESIGN (test vectors only). Never reuse.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1] / "test-vectors"
DISC = ROOT / "disclosures"
SEED = bytes(range(1, 33))  # 0x01..0x20 — TEST KEY, intentionally public
SK = Ed25519PrivateKey.from_private_bytes(SEED)
PUB_B64 = base64.b64encode(SK.public_key().public_bytes_raw()).decode()
KEY_ID = "ed25519:" + PUB_B64[:12]


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entry_hash(entry: dict) -> str:
    return sha(canonical(entry))


def sign(core: dict) -> dict:
    return {**core, "signatures": [{
        "signer": "bridge", "alg": "ed25519", "key_id": KEY_ID,
        "public_key": PUB_B64,
        "sig": base64.b64encode(SK.sign(canonical(core))).decode(),
    }]}


def derive_x402(raw: bytes) -> tuple[str, str | None]:
    """Normative §8.4 mapping: verbatim settle response -> (final_status, tx_hash)."""
    try:
        obj = json.loads(raw.decode("utf-8"))
        tx = obj.get("transaction")
        if obj.get("success") is True and isinstance(tx, str) and tx:
            return "settled", tx
        return "failed", tx if isinstance(tx, str) and tx else None
    except Exception:
        return "failed", None


# ---------------------------------------------------------------- v0.1 cores
def v01_core(session: str, seq: int, prev: str | None, paid: bool) -> dict:
    body_req = b'{"q":"iphone 13 screen"}'
    body_res = b'{"prices":[{"model":"iPhone 13","part":"screen","usd":"38.50"}]}'
    return {
        "spec": "agent-interaction-receipt", "spec_version": "0.1",
        "session_id": session, "seq": seq, "prev_receipt_hash": prev,
        "issued_at": f"2026-07-21T12:00:0{seq}.000Z",
        "capability_id": "vector-cap",
        "parties": [
            {"role": "bridge", "id": "https://bridge.example", "key_id": KEY_ID},
            {"role": "provider", "id": "0xPROVIDER", "key_id": None},
            {"role": "payer", "id": "0xPAYER" if paid else None, "key_id": None},
        ],
        "request": {"kind": "http-request", "method": "POST", "target": "/mcp/vector-cap",
                    "status": None, "media_type": "application/json",
                    "body_sha256": sha(body_req), "body_len": len(body_req)},
        "response": {"kind": "http-response", "method": None, "target": None,
                     "status": 200, "media_type": "application/json",
                     "body_sha256": sha(body_res), "body_len": len(body_res)},
        "payment": {
            "protocol": "x402", "scheme": "exact", "network": "base-sepolia",
            "asset": "USDC", "amount": "1000", "pay_to": "0xPROVIDER",
            "payer": "0xPAYER", "payment_payload_sha256": sha(b"vector-payment"),
            "settlement_ref": "0xvectortx",
        } if paid else None,
        "meta": {},
    }


# ---------------------------------------------------------------- v0.2 cores
def v02_receipt_core(session: str, seq: int, prev: str | None,
                     settlement_status: str, settle_raw: bytes | None,
                     settlement_ref: str | None) -> dict:
    body_req = b'{"q":"iphone 14 battery"}'
    body_res = b'{"prices":[{"model":"iPhone 14","part":"battery","usd":"22.10"}]}'
    return {
        "spec": "agent-interaction-receipt", "spec_version": "0.2",
        "entry_type": "receipt",
        "session_id": session, "seq": seq, "prev_entry_hash": prev,
        "issued_at": f"2026-07-23T10:00:0{seq}.000Z",
        "capability_id": "vector-cap",
        "parties": [
            {"role": "bridge", "id": "https://bridge.example", "key_id": KEY_ID},
            {"role": "provider", "id": "0xPROVIDER", "key_id": None},
            {"role": "payer", "id": "0xPAYER", "key_id": None},
        ],
        "request": {"kind": "http-request", "method": "POST", "target": "/mcp/vector-cap",
                    "status": None, "media_type": "application/json",
                    "body_sha256": sha(body_req), "body_len": len(body_req)},
        "response": {"kind": "http-response", "method": None, "target": None,
                     "status": 200, "media_type": "application/json",
                     "body_sha256": sha(body_res), "body_len": len(body_res)},
        "payment": {
            "protocol": "x402", "scheme": "exact", "network": "base-sepolia",
            "asset": "USDC", "amount": "1000", "pay_to": "0xPROVIDER",
            "payer": "0xPAYER", "payment_payload_sha256": sha(b"vector-payment-v2"),
            "settlement_status": settlement_status,
            "settlement_ref": settlement_ref,
            "settle_response_sha256": sha(settle_raw) if settle_raw else None,
            "settle_response_len": len(settle_raw) if settle_raw else None,
        },
        "meta": {},
    }


def v02_attachment_core(session: str, seq: int, prev: str, attaches_to: str,
                        settle_raw: bytes, ts: str,
                        override_status: str | None = None,
                        override_tx: str | None | object = "DERIVE") -> dict:
    status, tx = derive_x402(settle_raw)
    if override_status is not None:
        status = override_status
    if override_tx != "DERIVE":
        tx = override_tx  # type: ignore[assignment]
    return {
        "spec": "agent-interaction-receipt", "spec_version": "0.2",
        "entry_type": "settlement-attachment",
        "session_id": session, "seq": seq, "prev_entry_hash": prev,
        "issued_at": ts,
        "attaches_to": attaches_to,
        "settlement": {
            "final_status": status,
            "tx_hash": tx,
            "network": "base-sepolia",
            "facilitator_id": "https://facilitator.example",
            "response_timestamp": ts,
            "settle_response_sha256": sha(settle_raw),
            "settle_response_len": len(settle_raw),
        },
        "meta": {},
    }


def write(path: Path, obj: dict) -> None:
    path.write_bytes(canonical(obj))


def main() -> None:
    DISC.mkdir(parents=True, exist_ok=True)
    expected: dict = {}

    # ---------------------------------------------------- v0.1 (byte-stable)
    v01 = sign(v01_core("s-free", 0, None, paid=False))
    write(ROOT / "valid/01-free-call-seq0.json", v01)
    expected["valid/01-free-call-seq0.json"] = {
        "spec_version": "0.1", "entry_hash": entry_hash(v01), "standalone_verify": "pass"}

    v02_ = sign(v01_core("s-paid", 0, None, paid=True))
    write(ROOT / "valid/02-paid-call-seq0.json", v02_)
    expected["valid/02-paid-call-seq0.json"] = {
        "spec_version": "0.1", "entry_hash": entry_hash(v02_), "standalone_verify": "pass"}

    v03 = sign(v01_core("s-paid", 1, entry_hash(v02_), paid=True))
    write(ROOT / "valid/03-paid-call-seq1-chained.json", v03)
    expected["valid/03-paid-call-seq1-chained.json"] = {
        "spec_version": "0.1", "entry_hash": entry_hash(v03), "standalone_verify": "pass",
        "chain_verify_against": "valid/02-paid-call-seq0.json", "chain_verify": "pass"}

    i10 = json.loads(canonical(v02_)); i10["payment"]["amount"] = "999999"
    write(ROOT / "invalid/10-tampered-amount.json", i10)
    expected["invalid/10-tampered-amount.json"] = {
        "spec_version": "0.1", "standalone_verify": "fail",
        "why": "signature no longer covers the mutated amount"}

    i11 = sign(v01_core("s-paid", 1, "ab" * 32, paid=True))
    write(ROOT / "invalid/11-valid-sig-wrong-prev.json", i11)
    expected["invalid/11-valid-sig-wrong-prev.json"] = {
        "spec_version": "0.1", "entry_hash": entry_hash(i11), "standalone_verify": "pass",
        "chain_verify_against": "valid/02-paid-call-seq0.json", "chain_verify": "fail",
        "why": "signature honest, chain link wrong — signature checks are necessary, not sufficient"}

    i12 = json.loads(canonical(v02_)); i12["payment"]["amount"] = 0.001
    (ROOT / "invalid/12-float-amount.json").write_text(json.dumps(i12, sort_keys=True))
    expected["invalid/12-float-amount.json"] = {
        "spec_version": "0.1", "standalone_verify": "fail",
        "why": "floats are forbidden (§4 number rule)"}

    # ------------------------------------------------------------- v0.2
    raw_sync = b'{"success":true,"transaction":"0xabc123settledsync","network":"base-sepolia","payer":"0xPAYER"}'
    (DISC / "04-settle-response.json").write_bytes(raw_sync)
    r04 = sign(v02_receipt_core("s-sync", 0, None, "settled", raw_sync, "0xabc123settledsync"))
    write(ROOT / "valid/04-v02-receipt-settled-sync.json", r04)
    expected["valid/04-v02-receipt-settled-sync.json"] = {
        "spec_version": "0.2", "entry_hash": entry_hash(r04), "standalone_verify": "pass",
        "disclosure": "disclosures/04-settle-response.json", "rederivation": "pass"}

    r05 = sign(v02_receipt_core("s-late", 0, None, "pending", None, None))
    write(ROOT / "valid/05-v02-receipt-pending.json", r05)
    expected["valid/05-v02-receipt-pending.json"] = {
        "spec_version": "0.2", "entry_hash": entry_hash(r05), "standalone_verify": "pass",
        "note": "pending + no attachment = dispute-grade for content, NOT payment finality (§8.3)"}

    raw_late = b'{"success":true,"transaction":"0xdef456landedlate","network":"base-sepolia"}'
    (DISC / "06-settle-response.json").write_bytes(raw_late)
    a06 = sign(v02_attachment_core("s-late", 1, entry_hash(r05), entry_hash(r05),
                                   raw_late, "2026-07-23T10:05:00.000Z"))
    write(ROOT / "valid/06-v02-attachment-settled.json", a06)
    expected["valid/06-v02-attachment-settled.json"] = {
        "spec_version": "0.2", "entry_hash": entry_hash(a06), "standalone_verify": "pass",
        "chain_verify_against": "valid/05-v02-receipt-pending.json", "chain_verify": "pass",
        "pair_verify_against": "valid/05-v02-receipt-pending.json", "pair_verify": "pass",
        "disclosure": "disclosures/06-settle-response.json", "rederivation": "pass"}

    r07 = sign(v02_receipt_core("s-2814", 0, None, "pending", None, None))
    write(ROOT / "valid/07-v02-receipt-pending-2814.json", r07)
    expected["valid/07-v02-receipt-pending-2814.json"] = {
        "spec_version": "0.2", "entry_hash": entry_hash(r07), "standalone_verify": "pass"}

    raw_2814 = b'{"success":true,"transaction":null,"status":"processing","network":"base-sepolia"}'
    (DISC / "08-settle-response.json").write_bytes(raw_2814)
    a08 = sign(v02_attachment_core("s-2814", 1, entry_hash(r07), entry_hash(r07),
                                   raw_2814, "2026-07-23T10:09:39.612Z"))
    write(ROOT / "valid/08-v02-attachment-failed-2814.json", a08)
    expected["valid/08-v02-attachment-failed-2814.json"] = {
        "spec_version": "0.2", "entry_hash": entry_hash(a08), "standalone_verify": "pass",
        "pair_verify_against": "valid/07-v02-receipt-pending-2814.json", "pair_verify": "pass",
        "disclosure": "disclosures/08-settle-response.json", "rederivation": "pass",
        "why": "the false-assurance case (x402#2814): settle claimed processing/success, "
               "no tx landed — derives failed + null; the verbatim digest carries the claim"}

    raw_real = b'{"success":true,"transaction":"0xrealhash777","network":"base-sepolia"}'
    (DISC / "13-settle-response.json").write_bytes(raw_real)
    i13 = sign(v02_attachment_core("s-2814", 1, entry_hash(r07), entry_hash(r07),
                                   raw_real, "2026-07-23T10:09:39.612Z",
                                   override_tx="0xtamperedhash"))
    write(ROOT / "invalid/13-v02-rederivation-mismatch.json", i13)
    expected["invalid/13-v02-rederivation-mismatch.json"] = {
        "spec_version": "0.2", "entry_hash": entry_hash(i13), "standalone_verify": "pass",
        "disclosure": "disclosures/13-settle-response.json", "rederivation": "fail",
        "why": "embedded tx_hash does not re-derive from the disclosed bytes (§8.4) — "
               "signature honest, disclosure inconsistent"}

    i14 = sign(v02_attachment_core("s-2814", 1, entry_hash(r07), "cd" * 32,
                                   raw_2814, "2026-07-23T10:09:39.612Z"))
    write(ROOT / "invalid/14-v02-attachment-dangling.json", i14)
    expected["invalid/14-v02-attachment-dangling.json"] = {
        "spec_version": "0.2", "standalone_verify": "pass",
        "pair_verify_against": "valid/07-v02-receipt-pending-2814.json", "pair_verify": "fail",
        "why": "attaches_to does not match the receipt's entry hash (§8.2)"}

    i15_core = v02_receipt_core("s-sync", 0, None, "settled", raw_sync, "0xabc123settledsync")
    del i15_core["payment"]["settlement_status"]
    i15 = sign(i15_core)
    write(ROOT / "invalid/15-v02-missing-settlement-status.json", i15)
    expected["invalid/15-v02-missing-settlement-status.json"] = {
        "spec_version": "0.2", "standalone_verify": "fail",
        "why": "payment present without required settlement_status (§4.3)"}

    (ROOT / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True))
    (ROOT / "KEY.txt").write_text(
        "TEST KEY — public by design, never use outside test vectors\n"
        f"ed25519 seed (b64): {base64.b64encode(SEED).decode()}\n"
        f"ed25519 public (b64): {PUB_B64}\n"
        f"key_id: {KEY_ID}\n")
    print(f"wrote {len(expected)} vectors")


if __name__ == "__main__":
    main()
