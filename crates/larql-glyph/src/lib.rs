//! larql-glyph — LQL-style graph queries over GlyphIndex sovereign memory.
//!
//! LARQL treats model weights as a queryable graph; this crate applies the
//! same verbs (`DESCRIBE`, `SELECT`, `WALK`, `INFER`) to an agent's
//! GlyphIndex memory vault. Every memory chunk is a content-addressed node
//! (GIX-FOLD-v1 glyph + SHA-256 canonical id + Odù linkage), and edges are
//! either explicit (added by the agent) or inferred from shared Odù structure.
//!
//! Only *metadata* lives here — chunk plaintext stays sealed in GIX1 blobs
//! (Walrus / Vantage / OSOVM). This is deliberately the queryable projection
//! of the vault, safe to hold in memory or ship to a zerolang graph.
//!
//! Wire formats match the canonical reference implementation
//! (`Vantage/backend/glyph_index.py`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlyphGraphError {
    #[error("unknown node {0}")]
    UnknownNode(String),
    #[error("canonical id must be 64 hex chars")]
    BadCanonicalId,
}

// ---- GIX-FOLD-v1 -----------------------------------------------------------

const FOLD_RANGES: [(u32, u32); 3] = [
    (0x0020, 0xD7FF - 0x0020 + 1),
    (0xE000, 0xFDCF - 0xE000 + 1),
    (0xFDF0, 0xFFFD - 0xFDF0 + 1),
];

pub fn content_hash(text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    h.finalize().into()
}

pub fn glyph_fold(digest: &[u8; 32]) -> char {
    let total: u64 = FOLD_RANGES.iter().map(|(_, c)| *c as u64).sum();
    let mut rem: u64 = 0;
    for byte in digest {
        rem = (rem << 8 | *byte as u64) % total;
    }
    let mut idx = rem as u32;
    for (start, count) in FOLD_RANGES {
        if idx < count {
            return char::from_u32(start + idx).expect("fold ranges exclude invalid points");
        }
        idx -= count;
    }
    unreachable!()
}

pub fn odu_link(digest: &[u8; 32]) -> (u8, u16) {
    (digest[0], (digest[0] as u16) << 8 | digest[1] as u16)
}

// ---- graph model ------------------------------------------------------------

/// Metadata projection of one sealed memory chunk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlyphNode {
    pub canonical_id: String,
    pub glyph: char,
    pub odu_base: u8,
    pub odu_composed: u16,
    pub ts: f64,
    /// Free-form labels the agent chose to reveal (topic, vessel, project…).
    pub tags: BTreeSet<String>,
    /// Optional Walrus blob id so a WALK result can be expanded elsewhere.
    pub walrus_blob_id: Option<String>,
}

impl GlyphNode {
    /// Build the node for a plaintext chunk (plaintext is *not* retained).
    pub fn from_chunk(chunk: &str, ts: f64) -> Self {
        let digest = content_hash(chunk);
        let (odu_base, odu_composed) = odu_link(&digest);
        Self {
            canonical_id: hex::encode(digest),
            glyph: glyph_fold(&digest),
            odu_base,
            odu_composed,
            ts,
            tags: BTreeSet::new(),
            walrus_blob_id: None,
        }
    }
}

/// Typed edge between two memory nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlyphEdge {
    pub from: String,
    pub to: String,
    /// e.g. "follows", "same-conversation", "shared-odu", "rem-cluster"
    pub relation: String,
}

/// In-memory glyph knowledge graph with LQL-flavored query verbs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlyphGraph {
    nodes: BTreeMap<String, GlyphNode>,
    edges: BTreeSet<GlyphEdge>,
}

/// `DESCRIBE` output for a node: the node plus its incident edges.
#[derive(Debug, Serialize)]
pub struct Description<'a> {
    pub node: &'a GlyphNode,
    pub outgoing: Vec<&'a GlyphEdge>,
    pub incoming: Vec<&'a GlyphEdge>,
}

impl GlyphGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, node: GlyphNode) -> Result<(), GlyphGraphError> {
        if node.canonical_id.len() != 64 || hex::decode(&node.canonical_id).is_err() {
            return Err(GlyphGraphError::BadCanonicalId);
        }
        self.nodes.insert(node.canonical_id.clone(), node);
        Ok(())
    }

    pub fn link(&mut self, from: &str, to: &str, relation: &str) -> Result<(), GlyphGraphError> {
        for id in [from, to] {
            if !self.nodes.contains_key(id) {
                return Err(GlyphGraphError::UnknownNode(id.to_string()));
            }
        }
        self.edges.insert(GlyphEdge {
            from: from.to_string(),
            to: to.to_string(),
            relation: relation.to_string(),
        });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// `DESCRIBE <id>` — node metadata plus incident edges.
    pub fn describe(&self, id: &str) -> Result<Description<'_>, GlyphGraphError> {
        let node = self
            .nodes
            .get(id)
            .ok_or_else(|| GlyphGraphError::UnknownNode(id.to_string()))?;
        Ok(Description {
            node,
            outgoing: self.edges.iter().filter(|e| e.from == id).collect(),
            incoming: self.edges.iter().filter(|e| e.to == id).collect(),
        })
    }

    /// `SELECT` — filter nodes with an arbitrary predicate.
    pub fn select<'a>(&'a self, pred: impl Fn(&GlyphNode) -> bool + 'a) -> Vec<&'a GlyphNode> {
        self.nodes.values().filter(|n| pred(n)).collect()
    }

    /// `SELECT ... WHERE tag` convenience.
    pub fn select_by_tag(&self, tag: &str) -> Vec<&GlyphNode> {
        self.nodes
            .values()
            .filter(|n| n.tags.contains(tag))
            .collect()
    }

    /// `WALK <id> DEPTH <n>` — BFS over edges (both directions), returning
    /// nodes in discovery order, start excluded.
    pub fn walk(&self, start: &str, depth: usize) -> Result<Vec<&GlyphNode>, GlyphGraphError> {
        if !self.nodes.contains_key(start) {
            return Err(GlyphGraphError::UnknownNode(start.to_string()));
        }
        let mut seen: BTreeSet<&str> = BTreeSet::from([start]);
        let mut queue: VecDeque<(&str, usize)> = VecDeque::from([(start, 0)]);
        let mut out = Vec::new();
        while let Some((id, d)) = queue.pop_front() {
            if d == depth {
                continue;
            }
            for edge in &self.edges {
                let next = if edge.from == id {
                    edge.to.as_str()
                } else if edge.to == id {
                    edge.from.as_str()
                } else {
                    continue;
                };
                if seen.insert(next) {
                    out.push(&self.nodes[next]);
                    queue.push_back((next, d + 1));
                }
            }
        }
        Ok(out)
    }

    /// `INFER` — materialize "shared-odu" edges between nodes whose composed
    /// Odù share a top byte (same base-Odù lineage in the Digital Calabash).
    /// Returns how many new edges were added.
    pub fn infer_shared_odu(&mut self) -> usize {
        let ids: Vec<(String, u8)> = self
            .nodes
            .values()
            .map(|n| (n.canonical_id.clone(), n.odu_base))
            .collect();
        let mut added = 0;
        for (i, (id_a, base_a)) in ids.iter().enumerate() {
            for (id_b, base_b) in &ids[i + 1..] {
                if base_a == base_b
                    && self.edges.insert(GlyphEdge {
                        from: id_a.clone(),
                        to: id_b.clone(),
                        relation: "shared-odu".into(),
                    })
                {
                    added += 1;
                }
            }
        }
        added
    }

    /// A2A memory exchange: union another agent's projection into this one.
    /// Nodes are content-addressed, so a colliding id is the same sealed
    /// chunk — tags union, earliest ts wins, and an existing locator is
    /// never dropped. Returns `(nodes_added, edges_added)`.
    pub fn merge(&mut self, other: GlyphGraph) -> (usize, usize) {
        let mut nodes_added = 0;
        for (id, node) in other.nodes {
            match self.nodes.entry(id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(node);
                    nodes_added += 1;
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    let existing = slot.get_mut();
                    existing.tags.extend(node.tags);
                    if node.ts < existing.ts {
                        existing.ts = node.ts;
                    }
                    if existing.walrus_blob_id.is_none() {
                        existing.walrus_blob_id = node.walrus_blob_id;
                    }
                }
            }
        }
        let mut edges_added = 0;
        for edge in other.edges {
            if self.edges.insert(edge) {
                edges_added += 1;
            }
        }
        (nodes_added, edges_added)
    }

    /// Serialize the whole graph projection (for zerolang / Axiom / snapshots).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("graph is always serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frozen cross-language vectors (canonical Python reference, Vantage).
    #[test]
    fn fold_matches_canonical_vectors() {
        for (text, codepoint, base, composed) in [
            ("Àṣẹ", 21841u32, 227u8, 58152u16),
            ("hello", 23636, 44, 11506),
            ("GlyphIndex", 13726, 68, 17595),
            ("😊🚀 Unicode test", 64591, 189, 48626),
            ("Ọ̀rúnmìlà", 17963, 204, 52390),
        ] {
            let digest = content_hash(text);
            assert_eq!(glyph_fold(&digest) as u32, codepoint);
            assert_eq!(odu_link(&digest), (base, composed));
        }
    }

    fn graph_with(chunks: &[&str]) -> (GlyphGraph, Vec<String>) {
        let mut g = GlyphGraph::new();
        let ids: Vec<String> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let n = GlyphNode::from_chunk(c, i as f64);
                let id = n.canonical_id.clone();
                g.insert(n).unwrap();
                id
            })
            .collect();
        (g, ids)
    }

    #[test]
    fn describe_select_walk() {
        let (mut g, ids) = graph_with(&["chunk one", "chunk two", "chunk three"]);
        g.link(&ids[0], &ids[1], "follows").unwrap();
        g.link(&ids[1], &ids[2], "follows").unwrap();

        let d = g.describe(&ids[1]).unwrap();
        assert_eq!(d.outgoing.len(), 1);
        assert_eq!(d.incoming.len(), 1);

        // depth 1 from node 0 reaches only node 1; depth 2 reaches node 2 too.
        assert_eq!(g.walk(&ids[0], 1).unwrap().len(), 1);
        assert_eq!(g.walk(&ids[0], 2).unwrap().len(), 2);

        let mut node = GlyphNode::from_chunk("tagged", 9.0);
        node.tags.insert("weather".into());
        g.insert(node).unwrap();
        assert_eq!(g.select_by_tag("weather").len(), 1);
    }

    #[test]
    fn infer_links_shared_odu_lineage() {
        // Find two chunks whose digests share a first byte, plus one that doesn't.
        let mut g = GlyphGraph::new();
        let a = GlyphNode::from_chunk("seed-a", 0.0);
        let mut b_chunk = None;
        for i in 0..4096 {
            let candidate = format!("probe-{i}");
            let n = GlyphNode::from_chunk(&candidate, 1.0);
            if n.odu_base == a.odu_base && n.canonical_id != a.canonical_id {
                b_chunk = Some(n);
                break;
            }
        }
        let b = b_chunk.expect("a shared-base probe exists within 4096 tries");
        g.insert(a.clone()).unwrap();
        g.insert(b.clone()).unwrap();
        assert_eq!(g.infer_shared_odu(), 1);
        assert_eq!(g.infer_shared_odu(), 0, "idempotent");
        assert_eq!(g.walk(&a.canonical_id, 1).unwrap().len(), 1);
    }

    #[test]
    fn rejects_bad_ids_and_unknown_nodes() {
        let mut g = GlyphGraph::new();
        let mut n = GlyphNode::from_chunk("x", 0.0);
        n.canonical_id = "nothex".into();
        assert!(matches!(g.insert(n), Err(GlyphGraphError::BadCanonicalId)));
        assert!(matches!(
            g.walk("00", 1),
            Err(GlyphGraphError::UnknownNode(_))
        ));
    }

    #[test]
    fn merge_unions_projections_for_a2a_exchange() {
        let (mut mine, ids) = graph_with(&["shared chunk", "only mine"]);
        mine.link(&ids[0], &ids[1], "follows").unwrap();

        let mut theirs = GlyphGraph::new();
        let mut shared = GlyphNode::from_chunk("shared chunk", 99.0);
        shared.tags.insert("from:peer".into());
        shared.walrus_blob_id = Some("walrus://peer/blob".into());
        let fresh = GlyphNode::from_chunk("only theirs", 3.0);
        let (shared_id, fresh_id) = (shared.canonical_id.clone(), fresh.canonical_id.clone());
        theirs.insert(shared).unwrap();
        theirs.insert(fresh).unwrap();
        theirs.link(&shared_id, &fresh_id, "rem-cluster").unwrap();

        assert_eq!(mine.merge(theirs.clone()), (1, 1));
        assert_eq!(mine.len(), 3);
        let merged = mine.describe(&ids[0]).unwrap();
        assert!(merged.node.tags.contains("from:peer"));
        assert_eq!(merged.node.ts, 0.0, "earliest ts wins");
        assert_eq!(
            merged.node.walrus_blob_id.as_deref(),
            Some("walrus://peer/blob")
        );
        assert_eq!(mine.merge(theirs), (0, 0), "idempotent");
    }

    // The golden snapshot is generated by the TypeScript implementation
    // (oh-my-pi packages/mnemopi test/fixtures/glyph-graph-snapshot.json);
    // both suites assert against the identical committed bytes.
    const GOLDEN_SNAPSHOT: &str = include_str!("../tests/fixtures/glyph-graph-snapshot.json");

    #[test]
    fn golden_snapshot_is_wire_compatible_across_languages() {
        let value: serde_json::Value = serde_json::from_str(GOLDEN_SNAPSHOT).unwrap();
        let graph: GlyphGraph = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(graph.len(), 5);

        // Re-serialization must be structurally identical to what TS emitted.
        assert_eq!(graph.to_json(), value);

        // Frozen-vector node for "Àṣẹ": WALK depth 1 crosses its follows +
        // rem-cluster edges; depth 2 reaches the rest of the chain.
        let ase = hex::encode(content_hash("Àṣẹ"));
        assert_eq!(graph.walk(&ase, 1).unwrap().len(), 2);
        assert_eq!(graph.walk(&ase, 2).unwrap().len(), 4);

        let hello = hex::encode(content_hash("hello"));
        let described = graph.describe(&hello).unwrap();
        assert_eq!(
            described.node.walrus_blob_id.as_deref(),
            Some("walrus://vault/hello-chunk")
        );
        assert!(described.node.tags.contains("topic:greeting"));
    }

    #[test]
    fn json_projection_roundtrips() {
        let (mut g, ids) = graph_with(&["alpha", "beta"]);
        g.link(&ids[0], &ids[1], "follows").unwrap();
        let json = g.to_json();
        let back: GlyphGraph = serde_json::from_value(json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.describe(&ids[0]).unwrap().outgoing.len(), 1);
    }
}
