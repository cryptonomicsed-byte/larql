"""Python port of the GlyphIndex sovereign-memory contract.

Spec: OSOVM/GLYPHINDEX_SPEC.md. The canonical reference implementation
(Vantage/backend/glyph_index.py) owns sealing/KDF/storage; this
dependency-free port covers the portable, keyless surface shared by every
language leg: GIX-FOLD-v1 folding, Odù linkage, the content-addressed
GlyphGraph with LQL-style verbs (DESCRIBE / SELECT / WALK / INFER) plus
A2A merge, the cross-language JSON wire format, GIX1 structural audit,
and the Sui-anchorable Merkle root.

Run the conformance suite:  python3 glyphindex.py
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path
from typing import Iterable

FOLD_RANGES = ((0x0020, 0xD7FF - 0x0020 + 1),
               (0xE000, 0xFDCF - 0xE000 + 1),
               (0xFDF0, 0xFFFD - 0xFDF0 + 1))
FOLD_TOTAL = sum(count for _, count in FOLD_RANGES)
EMPTY_ROOT = "58cc47f0d238cea8bb764f7a927a54b398c8baf5de0a2332c03008038c3fd9a8"
_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def content_hash(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


def canonical_id(digest: bytes) -> str:
    return digest.hex()


def glyph_fold(digest: bytes) -> str:
    idx = int.from_bytes(digest, "big") % FOLD_TOTAL
    for start, count in FOLD_RANGES:
        if idx < count:
            return chr(start + idx)
        idx -= count
    raise AssertionError("unreachable")


def odu_link(digest: bytes) -> tuple[int, int]:
    return digest[0], (digest[0] << 8) | digest[1]


def node_from_chunk(chunk: str, ts: float) -> dict:
    digest = content_hash(chunk)
    base, composed = odu_link(digest)
    return {"canonical_id": canonical_id(digest), "glyph": glyph_fold(digest),
            "odu_base": base, "odu_composed": composed, "ts": ts,
            "tags": [], "walrus_blob_id": None}


class GlyphGraph:
    """Content-addressed glyph memory graph with LQL-style verbs."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: set[tuple[str, str, str]] = set()

    def insert(self, node: dict) -> None:
        if not _ID_PATTERN.match(node.get("canonical_id", "")):
            raise ValueError("canonical id must be 64 lowercase hex chars")
        stored = dict(node)
        stored["tags"] = sorted(set(node["tags"]))
        self.nodes[stored["canonical_id"]] = stored

    def link(self, from_id: str, to_id: str, relation: str) -> None:
        for node_id in (from_id, to_id):
            if node_id not in self.nodes:
                raise KeyError(f"unknown node {node_id}")
        self.edges.add((from_id, to_id, relation))

    def _sorted_edges(self) -> list[tuple[str, str, str]]:
        return sorted(self.edges)

    def describe(self, node_id: str) -> dict:
        if node_id not in self.nodes:
            raise KeyError(f"unknown node {node_id}")
        edges = self._sorted_edges()
        return {"node": self.nodes[node_id],
                "outgoing": [e for e in edges if e[0] == node_id],
                "incoming": [e for e in edges if e[1] == node_id]}

    def select_by_tag(self, tag: str) -> list[dict]:
        return [self.nodes[i] for i in sorted(self.nodes) if tag in self.nodes[i]["tags"]]

    def walk(self, start: str, depth: int) -> list[dict]:
        if start not in self.nodes:
            raise KeyError(f"unknown node {start}")
        edges = self._sorted_edges()
        seen = {start}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        out: list[dict] = []
        while queue:
            node_id, d = queue.popleft()
            if d == depth:
                continue
            for from_id, to_id, _ in edges:
                nxt = to_id if from_id == node_id else from_id if to_id == node_id else None
                if nxt is None or nxt in seen:
                    continue
                seen.add(nxt)
                out.append(self.nodes[nxt])
                queue.append((nxt, d + 1))
        return out

    def infer_shared_odu(self) -> int:
        ids = sorted(self.nodes)
        added = 0
        for i, id_a in enumerate(ids):
            for id_b in ids[i + 1:]:
                if self.nodes[id_a]["odu_base"] != self.nodes[id_b]["odu_base"]:
                    continue
                edge = (id_a, id_b, "shared-odu")
                if edge not in self.edges:
                    self.edges.add(edge)
                    added += 1
        return added

    def merge(self, other: "GlyphGraph") -> tuple[int, int]:
        nodes_added = 0
        for node_id in sorted(other.nodes):
            theirs = other.nodes[node_id]
            existing = self.nodes.get(node_id)
            if existing is None:
                self.insert(theirs)
                nodes_added += 1
                continue
            existing["tags"] = sorted(set(existing["tags"]) | set(theirs["tags"]))
            existing["ts"] = min(existing["ts"], theirs["ts"])
            if existing["walrus_blob_id"] is None:
                existing["walrus_blob_id"] = theirs["walrus_blob_id"]
        edges_added = len(other.edges - self.edges)
        self.edges |= other.edges
        return nodes_added, edges_added

    def to_wire(self) -> dict:
        return {"nodes": {i: self.nodes[i] for i in sorted(self.nodes)},
                "edges": [{"from": f, "to": t, "relation": r} for f, t, r in self._sorted_edges()]}

    @classmethod
    def from_wire(cls, wire: dict) -> "GlyphGraph":
        graph = cls()
        for node in wire["nodes"].values():
            graph.insert(node)
        for edge in wire["edges"]:
            graph.link(edge["from"], edge["to"], edge["relation"])
        return graph


def gix1_audit(blob: bytes) -> bool:
    return len(blob) >= 34 and blob[:4] == b"GIX1" and blob[4] == 1 and blob[5] <= 1


def merkle_root(entries: Iterable[tuple[str, bytes]]) -> str:
    entries = sorted(entries)
    if not entries:
        return EMPTY_ROOT
    level = [hashlib.sha256(bytes.fromhex(i) + h).digest() for i, h in entries]
    while len(level) > 1:
        nxt = [hashlib.sha256(level[i] + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def _conformance() -> None:
    here = Path(__file__).parent
    vectors = json.loads((here / ".." / "vectors.json").read_text())
    fixture = json.loads((here / ".." / "glyph-graph-snapshot.json").read_text())

    for vec in vectors["fold"]:
        digest = content_hash(vec["text"])
        assert canonical_id(digest) == vec["canonical_id"], vec["text"]
        assert ord(glyph_fold(digest)) == vec["codepoint"], vec["text"]
        assert odu_link(digest) == (vec["odu_base"], vec["odu_composed"]), vec["text"]

    graph = GlyphGraph.from_wire(fixture)
    assert len(graph.nodes) == 5
    assert json.loads(json.dumps(graph.to_wire(), ensure_ascii=False)) == fixture

    start = canonical_id(content_hash(vectors["walk"]["start_text"]))
    assert len(graph.walk(start, 1)) == vectors["walk"]["depth_1_count"]
    assert len(graph.walk(start, 2)) == vectors["walk"]["depth_2_count"]

    hello = canonical_id(content_hash("hello"))
    described = graph.describe(hello)
    assert described["node"]["walrus_blob_id"] == "walrus://vault/hello-chunk"
    assert len(graph.select_by_tag("topic:greeting")) == 1

    mine = GlyphGraph()
    mine.insert(node_from_chunk("shared chunk", 0))
    mine.insert(node_from_chunk("only mine", 1))
    peer = node_from_chunk("shared chunk", 99)
    peer["tags"] = ["from:peer"]
    peer["walrus_blob_id"] = "walrus://peer/blob"
    theirs = GlyphGraph()
    theirs.insert(peer)
    theirs.insert(node_from_chunk("only theirs", 3))
    assert mine.merge(theirs) == (1, 0)
    shared_id = canonical_id(content_hash("shared chunk"))
    assert mine.nodes[shared_id]["ts"] == 0
    assert mine.nodes[shared_id]["walrus_blob_id"] == "walrus://peer/blob"
    assert mine.merge(theirs) == (0, 0)

    assert gix1_audit(b"GIX1" + bytes([1, 0]) + bytes(28))
    assert not gix1_audit(b"GIX1" + bytes([9, 0]) + bytes(28))
    assert not gix1_audit(b"GIX1")

    assert merkle_root([]) == vectors["merkle"]["empty_root"]
    entries = [(i, hashlib.sha256(i.encode()).digest()) for i in fixture["nodes"]]
    assert merkle_root(entries) == vectors["merkle"]["vector_root"]

    print("glyphindex python conformance ok")


if __name__ == "__main__":
    _conformance()
