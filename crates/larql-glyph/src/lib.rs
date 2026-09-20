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

pub mod merkle_bridge;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

// Re-export canonical GIX-FOLD-v1 primitives from gix-types (single source of truth).
pub use gix_types::{content_hash, glyph_fold, odu_link, GlyphEdge, GlyphNode};

#[derive(Debug, Error)]
pub enum GlyphGraphError {
    #[error("unknown node {0}")]
    UnknownNode(String),
    #[error("canonical id must be 64 hex chars")]
    BadCanonicalId,
}

/// In-memory glyph knowledge graph with LQL-flavored query verbs.
#[derive(Debug, Default, Serialize, Deserialize)]
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
            weight: 0,
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
        self.nodes.values().filter(|n| n.tags.contains(tag)).collect()
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

    /// `WALK FOLDS <id>` — directed BFS through the fold hierarchy.
    ///
    /// Follows `fold_child` edges in the `from → to` direction only, so
    /// traversal descends into nested child folds rather than ascending to the
    /// root.  Returns all descendant fold nodes in BFS discovery order
    /// (start node excluded).
    ///
    /// Use after wiring fold topology with `fold_child` edges:
    ///   `graph.link(fold_id, child_id, "fold_child")?`
    pub fn walk_folds(&self, start: &str) -> Result<Vec<&GlyphNode>, GlyphGraphError> {
        self.walk_by_relation(start, "fold_child", true)
    }

    /// Directed or bidirectional BFS following only edges with `relation`.
    ///
    /// `directed = true`  → follows only `from == start` edges (downward).
    /// `directed = false` → follows both `from` and `to` ends (undirected).
    pub fn walk_by_relation(
        &self,
        start:    &str,
        relation: &str,
        directed: bool,
    ) -> Result<Vec<&GlyphNode>, GlyphGraphError> {
        if !self.nodes.contains_key(start) {
            return Err(GlyphGraphError::UnknownNode(start.to_string()));
        }
        let mut seen: BTreeSet<&str>    = BTreeSet::from([start]);
        let mut queue: VecDeque<&str>   = VecDeque::from([start]);
        let mut out: Vec<&GlyphNode>    = Vec::new();

        while let Some(id) = queue.pop_front() {
            for edge in &self.edges {
                if edge.relation != relation { continue; }
                let next = if edge.from == id {
                    edge.to.as_str()
                } else if !directed && edge.to == id {
                    edge.from.as_str()
                } else {
                    continue
                };
                if seen.insert(next) {
                    if let Some(node) = self.nodes.get(next) {
                        out.push(node);
                        queue.push_back(next);
                    }
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
                        weight: 0,
                    })
                {
                    added += 1;
                }
            }
        }
        added
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

    // ── Phase 8D — walk_folds / walk_by_relation ─────────────────────────────

    #[test]
    fn walk_folds_traverses_fold_child_edges() {
        let (mut g, ids) = graph_with(&["root-fold", "child-fold-a", "child-fold-b", "grandchild"]);
        // Wire: root → child-a → grandchild; root → child-b (unrelated to grandchild).
        g.link(&ids[0], &ids[1], "fold_child").unwrap();
        g.link(&ids[0], &ids[2], "fold_child").unwrap();
        g.link(&ids[1], &ids[3], "fold_child").unwrap();
        // Also add a non-fold edge that must NOT appear in walk_folds.
        g.link(&ids[2], &ids[3], "follows").unwrap();

        let folds = g.walk_folds(&ids[0]).unwrap();
        let fold_ids: Vec<&str> = folds.iter().map(|n| n.canonical_id.as_str()).collect();

        assert!(fold_ids.contains(&ids[1].as_str()), "child-a reachable");
        assert!(fold_ids.contains(&ids[2].as_str()), "child-b reachable");
        assert!(fold_ids.contains(&ids[3].as_str()), "grandchild reachable via child-a fold_child");
        assert_eq!(folds.len(), 3, "root excluded; all 3 descendants");
    }

    #[test]
    fn walk_folds_does_not_follow_non_fold_edges() {
        let (mut g, ids) = graph_with(&["fold-a", "fold-b", "isolated"]);
        g.link(&ids[0], &ids[2], "follows").unwrap();
        g.link(&ids[0], &ids[1], "fold_child").unwrap();

        let folds = g.walk_folds(&ids[0]).unwrap();
        // Only fold_child edges → only ids[1].
        assert_eq!(folds.len(), 1);
        assert_eq!(folds[0].canonical_id, ids[1]);
    }

    #[test]
    fn walk_by_relation_directed_follows_only_from_direction() {
        let (mut g, ids) = graph_with(&["a", "b", "c"]);
        // a→b→c as fold_child; c→a as reverse (would cause cycle in undirected).
        g.link(&ids[0], &ids[1], "fold_child").unwrap();
        g.link(&ids[1], &ids[2], "fold_child").unwrap();

        // Directed from c should find nothing (c has no outgoing fold_child).
        let from_c = g.walk_by_relation(&ids[2], "fold_child", true).unwrap();
        assert!(from_c.is_empty(), "directed walk from leaf must find nothing");

        // Undirected from c should find a and b.
        let from_c_undir = g.walk_by_relation(&ids[2], "fold_child", false).unwrap();
        assert_eq!(from_c_undir.len(), 2, "undirected walk from leaf finds both ancestors");
    }

    #[test]
    fn walk_folds_returns_error_for_unknown_start() {
        let g = GlyphGraph::new();
        assert!(matches!(g.walk_folds("nonexistent"), Err(GlyphGraphError::UnknownNode(_))));
    }

    #[test]
    fn rejects_bad_ids_and_unknown_nodes() {
        let mut g = GlyphGraph::new();
        let mut n = GlyphNode::from_chunk("x", 0.0);
        n.canonical_id = "nothex".into();
        assert!(matches!(g.insert(n), Err(GlyphGraphError::BadCanonicalId)));
        assert!(matches!(g.walk("00", 1), Err(GlyphGraphError::UnknownNode(_))));
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
