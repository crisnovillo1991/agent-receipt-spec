#!/usr/bin/env python3
"""Independent verification of babyblueviper's signed verdict event.

Zero dependencies on their code or infra: NIP-01 id recompute (stdlib),
BIP340 schnorr verification (pure Python, reference construction), and
decision_ref recompute per their declared preimage rule. Same bar we hold
everyone to: don't trust the summary, recompute the evidence.
"""
import hashlib
import json
import sys

# ---------- BIP340 schnorr verify (pure Python, secp256k1) ----------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        lam = (3 * a[0] * a[0] * pow(2 * a[1], P - 2, P)) % P
    else:
        lam = ((b[1] - a[1]) * pow(b[0] - a[0], P - 2, P)) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(pt, k):
    r = None
    while k:
        if k & 1: r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r


def lift_x(x):
    if x >= P: return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq: return None
    return (x, y if y % 2 == 0 else P - y)


def tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def schnorr_verify(msg32: bytes, pubkey32: bytes, sig64: bytes) -> bool:
    Ppt = lift_x(int.from_bytes(pubkey32, "big"))
    if Ppt is None: return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if r >= P or s >= N: return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig64[:32] + pubkey32 + msg32), "big") % N
    R = point_add(point_mul(G, s), point_mul((Ppt[0], P - Ppt[1]), e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


# ---------- checks ----------
def main():
    ev = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "event.json", encoding="utf-8"))
    results = {}

    # 1) NIP-01 id: sha256 of [0, pubkey, created_at, kind, tags, content]
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
                     separators=(",", ":"), ensure_ascii=False).encode()
    computed_id = hashlib.sha256(ser).hexdigest()
    results["nip01_id"] = (computed_id == ev["id"], computed_id)

    # 2) BIP340 schnorr over the id, against the embedded x-only pubkey
    ok = schnorr_verify(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"]))
    results["schnorr_sig"] = (ok, "verified against embedded pubkey" if ok else "INVALID")

    # 3) decision_ref recompute per their declared preimage rule
    content = json.loads(ev["content"])
    fields = content["decision_ref_preimage_fields"]
    preimage = {f: content.get(f, None) for f in fields}  # absent -> null, per their rule
    jcs = json.dumps(preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    computed_ref = "sha256:" + hashlib.sha256(jcs).hexdigest()
    results["decision_ref"] = (computed_ref == content["decision_ref"], computed_ref)

    # 4) coherence: content pubkey fields match the event pubkey
    results["key_coherence"] = (
        content.get("verifier_pubkey") == ev["pubkey"] == content.get("key_id"),
        ev["pubkey"][:16] + "...")

    all_ok = all(v[0] for v in results.values())
    for k, (ok, detail) in results.items():
        print(f"{'PASS' if ok else 'FAIL'}  {k:14} {detail}")
    print("\nVEREDICTO:", "su lado VERIFICA independientemente ✓" if all_ok else "NO verifica — frenar y reportar")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
