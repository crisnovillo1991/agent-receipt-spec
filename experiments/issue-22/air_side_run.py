#!/usr/bin/env python3
"""AIR-side run of the SAR primitive corpus (sar-primitive-vectors/v1).

Reads vectors.json as DATA. Executes none of the capsule's code. Every outcome
below is produced by the AIR reference verifier's own primitives
(loads_strict / canonical / SHA-256 / Ed25519 + small-order check).

Two columns are kept apart on purpose:
  primitive : what the AIR primitives do with the input
  profile   : whether the input would be admissible inside an AIR entry
Claim ceiling: PRIMITIVE_COMPATIBILITY_ONLY.

Inputs are not vendored here. They are fetched from the SAR-side pin
  nutstrut/default-settlement-verifier@8efd6528be234e66ff976c0a01dddabbf05671e7
  evidence/sar-primitive-vectors-20261006/{vectors.json, fixtures/...json}
and this runner refuses to run on any other bytes (SHA-256 pins below).

usage: air_side_run.py <verify.py> <vectors.json> <fixture.json> <out.json>
"""
import base64
import hashlib
import importlib.util
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization

verify_py, vectors_path, fixture_path, out_path = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("air_verify", verify_py)
air = importlib.util.module_from_spec(spec)
spec.loader.exec_module(air)

SAR_PIN = "nutstrut/default-settlement-verifier@8efd6528be234e66ff976c0a01dddabbf05671e7"
VECTORS_SHA256 = "9692dfc5bd59cbbf6b8cad8f6a309786b3a07194a718c2952dd7506344db155f"
FIXTURE_SHA256 = "538b6d7bfd3ff215c3156c3085c47b636ac2c4a473617799f4f96cab682f3236"

vec_bytes = open(vectors_path, "rb").read()
fix_bytes = open(fixture_path, "rb").read()
for label, data, want in (("vectors.json", vec_bytes, VECTORS_SHA256),
                          ("fixture", fix_bytes, FIXTURE_SHA256)):
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        sys.exit(f"{label}: sha256 {got} is not the pinned {want} -- refusing to run")
vectors = json.loads(vec_bytes)
fixture = json.loads(fix_bytes)
cases = {c["case_id"]: c for c in vectors["cases"]}


def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def has_float(o) -> bool:
    if isinstance(o, float):
        return True
    if isinstance(o, dict):
        return any(has_float(v) for v in o.values())
    if isinstance(o, list):
        return any(has_float(v) for v in o)
    return False


def air_input(case):
    """-> (stage, value_or_error). stage: 'parsed' | 'parse_rejected'."""
    inp = case["input"]
    if inp["kind"] == "json_text":
        text = inp["text"]
    else:  # reused artifact: six-field core, re-serialized so AIR parses text
        r = fixture["receipt"]
        core = {k: r[k] for k in ("task_id_hash", "verdict", "confidence",
                                  "reason_code", "ts", "verifier_kid")}
        text = json.dumps(core)
    try:
        return "parsed", air.loads_strict(text)
    except air.DuplicateKeyError as e:
        return "parse_rejected", f"DuplicateKeyError: {e}"
    except Exception as e:  # noqa: BLE001
        return "parse_rejected", f"{type(e).__name__}: {e}"


results = []
for case in vectors["cases"]:
    cid = case["case_id"]
    row = {"case_id": cid, "category": case["category"]}

    if "input" in case:
        exp = case["expect"]
        stage, val = air_input(case)
        row["air_parse"] = "ESTABLISHED" if stage == "parsed" else "REJECTED"
        if stage != "parsed":
            row["air_parse_error"] = val
            row["air_canonicalization"] = "NOT_APPLICABLE"
            row["relation_to_sar_jcs"] = (
                "DIFFERENT_OUTCOME" if exp["canonicalization"]["status"] == "ESTABLISHED"
                else "BOTH_REJECTED")
        else:
            try:
                cb = air.canonical(val)
                row["air_canonicalization"] = "ESTABLISHED"
                row["air_canonical_bytes_hex"] = cb.hex()
                row["air_sha256"] = hashlib.sha256(cb).hexdigest()
                if exp["canonicalization"]["status"] == "ESTABLISHED":
                    same = cb.hex() == exp["canonicalization"]["canonical_bytes_hex"]
                    row["relation_to_sar_jcs"] = "IDENTICAL_BYTES" if same else "DIFFERENT_BYTES"
                    row["sha256_matches_sar"] = (
                        row["air_sha256"] == exp["sha256"].get("digest_hex"))
                else:
                    row["relation_to_sar_jcs"] = "DIFFERENT_OUTCOME"
            except ValueError as e:
                row["air_canonicalization"] = "REJECTED"
                row["air_canonicalization_error"] = str(e)
                row["relation_to_sar_jcs"] = (
                    "BOTH_REJECTED" if exp["canonicalization"]["status"] == "REJECTED"
                    else "DIFFERENT_OUTCOME")
                # is this rejection a float (profile) or an input-domain one?
                row["air_rejection_kind"] = (
                    "PROFILE_NO_FLOATS" if has_float(val) else "INPUT_DOMAIN")
        # SHA-256 as a primitive, independent of who canonicalized:
        if exp["canonicalization"]["status"] == "ESTABLISHED":
            pinned = bytes.fromhex(exp["canonicalization"]["canonical_bytes_hex"])
            row["sha256_over_pinned_sar_bytes_matches"] = (
                hashlib.sha256(pinned).hexdigest() == exp["sha256"]["digest_hex"])
        row["air_profile_admissible_as_entry_content"] = (
            row["air_parse"] == "ESTABLISHED"
            and row["air_canonicalization"] == "ESTABLISHED")

    else:
        sc = case["signature_check"]
        expected = sc["expected_verify"]
        if "preimage_hex" not in sc:
            # REUSE-2-MUT-FIELD: defined only through the SAR portable reader.
            # AIR cannot canonicalize the mutated core (it carries a float), so
            # the only AIR-side observation available is at byte level: patch
            # the pinned canonical bytes 0.99 -> 0.98, hash, verify.
            base = bytes.fromhex(
                cases["REUSE-1"]["expect"]["canonicalization"]["canonical_bytes_hex"])
            assert base.count(b"0.99") == 1
            msg = hashlib.sha256(base.replace(b"0.99", b"0.98")).digest()
            pk = b64u(fixture["public_key_base64url"])
            sig = b64u(fixture["receipt"]["sig"].split(":", 1)[1])
            row["air_note"] = ("byte-level substitution on the pinned SAR canonical "
                               "bytes; not an AIR canonicalization, not the SAR reader")
        else:
            msg = bytes.fromhex(sc["preimage_hex"])
            pk = b64u(sc["pubkey_b64url"])
            sig = b64u(sc["signature_b64url"])
        row["air_small_order_key"] = air.is_small_order(pk)
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            got = "ESTABLISHED"
        except InvalidSignature:
            got = "REJECTED"
        row["air_ed25519_verify"] = got
        row["sar_expected_verify"] = expected
        row["verify_agrees"] = got == expected

        # where AIR can derive the preimage itself, do it
        der = sc.get("preimage_derivation")
        if der:
            src = cases[der["from_case"]]
            stage, val = air_input(src)
            try:
                cb = air.canonical(val)
                own = hashlib.sha256(cb).digest() if der["transform"].startswith("sha256") else cb
                row["air_derived_preimage_matches"] = own == msg
            except ValueError as e:
                row["air_derived_preimage_matches"] = None
                row["air_derived_preimage_note"] = (
                    f"AIR cannot canonicalize {der['from_case']}: {e}")
        if sc.get("deterministic_resign_check"):
            label = vectors["test_key_labels"]["test_key_1"]
            sk = Ed25519PrivateKey.from_private_bytes(
                hashlib.sha256(label.encode()).digest())
            pub = sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            row["air_test_key_rederived"] = pub == pk
            row["air_resign_identical"] = sk.sign(msg) == sig
    results.append(row)

out = {
    "schema": "air-side-run-of-sar-primitive-vectors/v1",
    "claim_ceiling": "PRIMITIVE_COMPATIBILITY_ONLY",
    "sar_pin": SAR_PIN,
    "vectors_file_sha256": VECTORS_SHA256,
    "fixture_file_sha256": FIXTURE_SHA256,
    "air_verifier_sha256": hashlib.sha256(open(verify_py, "rb").read()).hexdigest(),
    "air_stack": {"parser": "verify.loads_strict (json.loads + duplicate-key hook)",
                  "canonicalizer": "verify.canonical (own RFC 8785 profile: no floats, |int| <= 2^53-1)",
                  "ed25519": "cryptography Ed25519PublicKey + verify.is_small_order"},
    "capsule_code_executed": False,
    "cases_run": len(results),
    "results": results,
}
open(out_path, "w").write(json.dumps(out, indent=2, ensure_ascii=True) + "\n")

for r in results:
    if "air_parse" in r:
        print(f"{r['case_id']:22} parse={r['air_parse']:11} canon={r['air_canonicalization']:14} "
              f"rel={r['relation_to_sar_jcs']:18} sha_pinned={r.get('sha256_over_pinned_sar_bytes_matches')} "
              f"kind={r.get('air_rejection_kind','-')}")
    else:
        print(f"{r['case_id']:22} verify={r['air_ed25519_verify']:11} expected={r['sar_expected_verify']:11} "
              f"agree={r['verify_agrees']} derived={r.get('air_derived_preimage_matches','-')} "
              f"rekey={r.get('air_test_key_rederived','-')} resign={r.get('air_resign_identical','-')}")
