#!/usr/bin/env python3
"""Generate the normative test vectors for AIR v0.1.

Self-contained (stdlib + `cryptography`). Deterministic: fixed key, fixed
timestamps, fixed content digests — running it twice yields byte-identical
vectors, and `expected.json` records every hash so implementers can diff.

The private key below is PUBLIC BY DESIGN (test vectors only). Never reuse.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1] / "test-vectors"
SEED = bytes(range(1, 33))  # 0x01..0x20 — TEST KEY, intentionally public
SK = Ed25519PrivateKey.from_private_bytes(SEED)
PUB_B64 = base64.b64encode(SK.public_key().public_bytes_raw()).decode()
KEY_ID = "ed25519:" + PUB_B64[:12]


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def rhash(receipt: dict) -> str:
    return hashlib.sha256(canonical(receipt)).hexdigest()


def sign(core: dict) -> dict:
    return {
        **core,
        "signatures": [{
            "signer": "bridge", "alg": "ed25519", "key_id": KEY_ID,
            "public_key": PUB_B64,
            "sig": base64.b64encode(SK.sign(canonical(core))).decode(),
        }],
    }


def base_core(session: str, seq: int, prev: str | None, paid: bool) -> dict:
    body_req = b'{"q":"iphone 13 screen"}'
    body_res = b'{"prices":[{"model":"iPhone 13","part":"screen","usd":"38.50"}]}'
    return {
        "spec": "agent-interaction-receipt",
        "spec_version": "0.1",
        "session_id": session,
        "seq": seq,
        "prev_receipt_hash": prev,
        "issued_at": f"2026-07-21T12:00:0{seq}.000Z",
        "capability_id": "vector-cap",
        "parties": [
            {"role": "bridge", "id": "https://bridge.example", "key_id": KEY_ID},
            {"role": "provider", "id": "0xPROVIDER", "key_id": None},
            {"role": "payer", "id": "0xPAYER" if paid else None, "key_id": None},
        ],
        "request": {"kind": "http-request", "method": "POST", "target": "/mcp/vector-cap",
                    "status": None, "media_type": "application/json",
                    "body_sha256": hashlib.sha256(body_req).hexdigest(), "body_len": len(body_req)},
        "response": {"kind": "http-response", "method": None, "target": None,
                     "status": 200, "media_type": "application/json",
                     "body_sha256": hashlib.sha256(body_res).hexdigest(), "body_len": len(body_res)},
        "payment": {
            "protocol": "x402", "scheme": "exact", "network": "base-sepolia",
            "asset": "USDC", "amount": "1000", "pay_to": "0xPROVIDER",
            "payer": "0xPAYER",
            "payment_payload_sha256": hashlib.sha256(b"vector-payment").hexdigest(),
            "settlement_ref": "0xvectortx",
        } if paid else None,
        "meta": {},
    }


def write(path: Path, obj: dict) -> None:
    path.write_bytes(canonical(obj))


def main() -> None:
    expected = {}

    v01 = sign(base_core("s-free", 0, None, paid=False))
    write(ROOT / "valid/01-free-call-seq0.json", v01)
    expected["valid/01-free-call-seq0.json"] = {
        "receipt_hash": rhash(v01), "standalone_verify": "pass"}

    v02 = sign(base_core("s-paid", 0, None, paid=True))
    write(ROOT / "valid/02-paid-call-seq0.json", v02)
    expected["valid/02-paid-call-seq0.json"] = {
        "receipt_hash": rhash(v02), "standalone_verify": "pass"}

    v03 = sign(base_core("s-paid", 1, rhash(v02), paid=True))
    write(ROOT / "valid/03-paid-call-seq1-chained.json", v03)
    expected["valid/03-paid-call-seq1-chained.json"] = {
        "receipt_hash": rhash(v03), "standalone_verify": "pass",
        "chain_verify_against": "valid/02-paid-call-seq0.json", "chain_verify": "pass"}

    i10 = json.loads(canonical(v02))
    i10["payment"]["amount"] = "999999"
    write(ROOT / "invalid/10-tampered-amount.json", i10)
    expected["invalid/10-tampered-amount.json"] = {
        "standalone_verify": "fail", "why": "signature no longer covers the mutated amount"}

    i11 = sign(base_core("s-paid", 1, "ab" * 32, paid=True))
    write(ROOT / "invalid/11-valid-sig-wrong-prev.json", i11)
    expected["invalid/11-valid-sig-wrong-prev.json"] = {
        "receipt_hash": rhash(i11),
        "standalone_verify": "pass",
        "chain_verify_against": "valid/02-paid-call-seq0.json", "chain_verify": "fail",
        "why": "signature is honest but the chain link does not match receipt 02 — "
               "standalone signature checks are necessary, not sufficient"}

    i12 = json.loads(canonical(v02))
    i12["payment"]["amount"] = 0.001
    (ROOT / "invalid/12-float-amount.json").write_text(json.dumps(i12, sort_keys=True))
    expected["invalid/12-float-amount.json"] = {
        "standalone_verify": "fail", "why": "floats are forbidden (spec §4 number rule)"}

    (ROOT / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True))
    (ROOT / "KEY.txt").write_text(
        "TEST KEY — public by design, never use outside test vectors\n"
        f"ed25519 seed (b64): {base64.b64encode(SEED).decode()}\n"
        f"ed25519 public (b64): {PUB_B64}\n"
        f"key_id: {KEY_ID}\n"
    )
    print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
