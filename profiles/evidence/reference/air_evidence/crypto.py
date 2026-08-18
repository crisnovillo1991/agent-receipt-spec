"""Cryptographic primitives for air-evidence/0.1.

- Ed25519 keypairs (mandatory baseline of the profile).
- Object hashing: sha256 over JCS canonical form, excluding `signatures`.
- Detached signatures over the same canonical bytes.
- Minimal did:key encoding (multicodec ed25519-pub + base58btc).
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def signing_body(obj: dict[str, Any]) -> dict[str, Any]:
    """The portion of an object that is hashed and signed: everything
    except the `signatures` array (spec section 3)."""
    return {k: v for k, v in obj.items() if k != "signatures"}


def hash_object(obj: dict[str, Any]) -> str:
    """`sha256:<hex>` over the JCS canonical form, excluding signatures."""
    return "sha256:" + hashlib.sha256(canonicalize(signing_body(obj))).hexdigest()


def hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class KeyPair:
    """An Ed25519 identity. Reference implementation only: keys live in memory."""

    def __init__(self) -> None:
        self._sk = Ed25519PrivateKey.generate()

    @property
    def public_bytes(self) -> bytes:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def did_key(self) -> str:
        """did:key with the ed25519-pub multicodec prefix (0xed 0x01)."""
        return "did:key:z" + b58encode(b"\xed\x01" + self.public_bytes)

    def sign(self, data: bytes) -> str:
        return b64url(self._sk.sign(data))


def sign_object(
    obj: dict[str, Any],
    *,
    role: str,
    kid: str,
    keypair: KeyPair,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Append a detached signature entry over the object's canonical body.

    The signature covers the canonical bytes of the object *without* its
    `signatures` array, so co-signers all sign the identical message.
    """
    entry = {
        "role": role,
        "kid": kid,
        "alg": "EdDSA",
        "sig": keypair.sign(canonicalize(signing_body(obj))),
        "signed_at": signed_at or now_iso(),
    }
    obj.setdefault("signatures", []).append(entry)
    return entry


def verify_signature(
    obj: dict[str, Any], sig_entry: dict[str, Any], public_key_bytes: bytes
) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(
            b64url_decode(sig_entry["sig"]), canonicalize(signing_body(obj))
        )
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


class DIDRegistry:
    """Minimal in-memory DID resolver: did -> {kid -> public key bytes}.

    Stands in for did:web resolution / DID document fetching. A production
    verifier resolves DID documents and honors key validity windows and
    revocations (spec section 14); the reference keeps the interface only.
    """

    def __init__(self) -> None:
        self._keys: dict[str, dict[str, bytes]] = {}

    def register(self, did: str, kid: str, public_key_bytes: bytes) -> None:
        self._keys.setdefault(did, {})[kid] = public_key_bytes

    def resolve(self, kid: str) -> bytes | None:
        did = kid.split("#", 1)[0]
        return self._keys.get(did, {}).get(kid)
