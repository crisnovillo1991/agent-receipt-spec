"""RFC 8785 (JCS) canonicalization, restricted to the air-evidence/0.1 subset.

The profile prohibits floats everywhere (amounts are integers in minor units),
which removes the hardest part of full JCS (ECMAScript number serialization).
This module implements JCS exactly for the remaining types and *rejects*
anything outside the subset, so a non-conforming object can never produce
a hash at all.

Guarantees:
- Object keys sorted by UTF-16 code units (JCS section 3.2.3).
- Minimal string escaping identical to JCS (via json.dumps semantics).
- Integers only within the IEEE-754 safe range (|n| <= 2^53 - 1).
- floats, NaN, Infinity, non-string keys -> TypeError/ValueError.
"""

from __future__ import annotations

import json
from typing import Any


def canonicalize(value: Any) -> bytes:
    """Return the JCS canonical UTF-8 encoding of *value*."""
    return _serialize(value).encode("utf-8")


def _serialize(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):  # must precede int check (bool subclasses int)
        return "true" if v else "false"
    if isinstance(v, int):
        if abs(v) > 2**53 - 1:
            raise ValueError(
                f"integer {v} outside IEEE-754 safe range; not representable in JCS"
            )
        return str(v)
    if isinstance(v, float):
        raise TypeError("floats are prohibited by air-evidence/0.1 (use minor units)")
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_serialize(x) for x in v) + "]"
    if isinstance(v, dict):
        parts = []
        for key in sorted(v.keys(), key=_utf16_units):
            if not isinstance(key, str):
                raise TypeError("object keys must be strings")
            parts.append(_string(key) + ":" + _serialize(v[key]))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"type not allowed in canonical form: {type(v).__name__}")


def _string(s: str) -> str:
    # json.dumps with ensure_ascii=False applies exactly the JCS escape set:
    # \" \\ and control chars < 0x20 (short forms \b \t \n \f \r, else \u00XX).
    return json.dumps(s, ensure_ascii=False)


def _utf16_units(s: str) -> list[int]:
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            units.append(cp)
        else:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
    return units
