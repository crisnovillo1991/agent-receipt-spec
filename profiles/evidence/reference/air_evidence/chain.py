"""Chain of custody (spec section 10): per-agent hash chain, Merkle tree,
signed anchors, inclusion proofs.

The anchor here is signed by the log operator and timestamped locally; a
production deployment replaces that with RFC 3161 TSA responses and/or a
public-ledger transaction. The verification interface is identical.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .crypto import KeyPair, hash_object, now_iso, sign_object


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf_bytes(receipt_hash: str) -> bytes:
    return bytes.fromhex(receipt_hash.split(":", 1)[1])


class MerkleTree:
    """Odd nodes are promoted (never duplicated)."""

    def __init__(self, leaves: list[bytes]) -> None:
        if not leaves:
            raise ValueError("empty tree")
        self.levels: list[list[bytes]] = [list(leaves)]
        while len(self.levels[-1]) > 1:
            prev = self.levels[-1]
            nxt: list[bytes] = []
            for i in range(0, len(prev), 2):
                if i + 1 < len(prev):
                    nxt.append(_h(prev[i] + prev[i + 1]))
                else:
                    nxt.append(prev[i])
            self.levels.append(nxt)

    @property
    def root(self) -> str:
        return "sha256:" + self.levels[-1][0].hex()

    def proof(self, index: int) -> list[dict[str, str]]:
        path: list[dict[str, str]] = []
        for level in self.levels[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                side = "right" if sibling > index else "left"
                path.append({"hash": "sha256:" + level[sibling].hex(), "side": side})
            index //= 2
        return path

    @staticmethod
    def verify(leaf: bytes, proof: list[dict[str, str]], root: str) -> bool:
        node = leaf
        for step in proof:
            sib = bytes.fromhex(step["hash"].split(":", 1)[1])
            node = _h(node + sib) if step["side"] == "right" else _h(sib + node)
        return "sha256:" + node.hex() == root


class ReceiptLog:
    """Append-only log with per-agent streams and periodic anchoring."""

    def __init__(self, operator_did: str, operator_kid: str, operator_kp: KeyPair):
        self.operator_did = operator_did
        self.operator_kid = operator_kid
        self.operator_kp = operator_kp
        self.entries: list[dict[str, Any]] = []
        self.by_hash: dict[str, dict[str, Any]] = {}
        self.streams: dict[str, list[str]] = {}
        self.anchors: list[dict[str, Any]] = []
        self._anchored_upto = 0

    def append(self, receipt: dict[str, Any]) -> str:
        agent = receipt["identity"]["agent_id"]
        stream = self.streams.setdefault(agent, [])
        expected_prev = stream[-1] if stream else None
        if receipt.get("prev_receipt_hash") != expected_prev:
            raise ValueError("prev_receipt_hash does not match agent stream head")
        if receipt.get("seq") != len(stream) + 1:
            raise ValueError("seq is not monotonic for agent stream")
        rh = hash_object(receipt)
        self.entries.append(receipt)
        self.by_hash[rh] = receipt
        stream.append(rh)
        return rh

    def anchor(self, anchored_at: str | None = None) -> dict[str, Any]:
        """Anchor everything not yet anchored (spec 10.2: every N receipts or
        T minutes; the reference anchors on demand)."""
        start, end = self._anchored_upto, len(self.entries)
        if start == end:
            raise ValueError("nothing to anchor")
        hashes = [hash_object(r) for r in self.entries[start:end]]
        tree = MerkleTree([_leaf_bytes(h) for h in hashes])
        anchor: dict[str, Any] = {
            "profile": "air-evidence/0.1",
            "type": "anchor",
            "log_operator": self.operator_did,
            "range": [start, end],
            "receipt_hashes": hashes,
            "merkle_root": tree.root,
            "anchor_method": "local-signed-timestamp (stand-in for RFC 3161 TSA)",
            "anchored_at": anchored_at or now_iso(),
        }
        sign_object(
            anchor, role="log_operator", kid=self.operator_kid, keypair=self.operator_kp
        )
        self.anchors.append(anchor)
        self._anchored_upto = end
        return anchor

    def inclusion_proof(self, receipt_hash: str) -> dict[str, Any] | None:
        """Find the anchor covering the receipt and build its Merkle path."""
        for anchor in self.anchors:
            if receipt_hash in anchor["receipt_hashes"]:
                idx = anchor["receipt_hashes"].index(receipt_hash)
                tree = MerkleTree(
                    [_leaf_bytes(h) for h in anchor["receipt_hashes"]]
                )
                return {
                    "anchor": anchor,
                    "leaf_index": idx,
                    "path": tree.proof(idx),
                }
        return None

    def verify_stream(self, agent_did: str) -> bool:
        """Recompute the chain from stored receipts; detects tampering."""
        prev = None
        for i, rh in enumerate(self.streams.get(agent_did, []), start=1):
            receipt = self.by_hash[rh]
            if hash_object(receipt) != rh:
                return False
            if receipt.get("prev_receipt_hash") != prev or receipt.get("seq") != i:
                return False
            prev = rh
        return True
