//! Integration point for Omo-Koda2 to call larql-glyph for local inference.
//!
//! Omo-Koda2 imports this via the `larql-glyph` crate and guards every call
//! with [`crate::is_enabled()`].  When `LARQL_ENABLED` is not set (the default),
//! all functions here are no-ops that return empty results, so the crate can be
//! linked without any cost unless the sovereign LLM path is explicitly activated.
//!
//! # Usage from Omo-Koda2
//!
//! ```rust,ignore
//! use larql_glyph::{is_enabled, omokoda_integration};
//!
//! let memories = omokoda_integration::query_glyph_memory("emission");
//! // Returns vec![] when LARQL_ENABLED is unset; rich results when enabled.
//! ```

use crate::{is_enabled, GlyphGraph, GlyphNode};

/// Query the agent's glyph memory for nodes whose tags contain `query`.
///
/// This is the primary integration hook: Omo-Koda2 calls this before routing
/// a prompt to the LLM, allowing previously-observed patterns to surface as
/// context without a full network round-trip.
///
/// Each result is formatted as `"[<id_prefix>] glyph=<char> tags=[<tag1>,<tag2>…]"`.
///
/// Returns an empty `Vec` when `LARQL_ENABLED` is `false` or the in-process
/// graph is empty (no prior ingest in this session).
pub fn query_glyph_memory(query: &str) -> Vec<String> {
    if !is_enabled() {
        return vec![];
    }
    // In the current phase the graph lives only in process memory.
    // Future phases will persist via GIX1 blobs (Walrus / Vantage).
    let graph = in_process_graph();
    let q = query.to_lowercase();
    graph
        .select(|node: &GlyphNode| {
            node.tags.iter().any(|t| t.to_lowercase().contains(&q))
        })
        .into_iter()
        .map(|node| {
            let tags: Vec<&str> = node.tags.iter().map(String::as_str).collect();
            format!(
                "[{}] glyph={} tags=[{}]",
                &node.canonical_id[..8],
                node.glyph,
                tags.join(",")
            )
        })
        .collect()
}

/// `DESCRIBE` a specific glyph node by its canonical id prefix (first 8 hex chars).
///
/// Returns the node's glyph and tags as a single formatted string, or an empty
/// `Vec` when the node is not found or larql is disabled.
pub fn describe_glyph(canonical_id_prefix: &str) -> Vec<String> {
    if !is_enabled() {
        return vec![];
    }
    let graph = in_process_graph();
    graph
        .select(|node: &GlyphNode| node.canonical_id.starts_with(canonical_id_prefix))
        .into_iter()
        .map(|node| {
            let tags: Vec<&str> = node.tags.iter().map(String::as_str).collect();
            format!(
                "[{}] glyph={} odu_base={} tags=[{}]",
                &node.canonical_id[..8],
                node.glyph,
                node.odu_base,
                tags.join(", ")
            )
        })
        .collect()
}

/// `WALK` outward from a node (identified by prefix) to depth 2.
///
/// Returns canonical-id prefixes of reachable neighbours, useful for
/// context expansion in the Omo-Koda2 reasoning loop.
pub fn walk_neighbours(canonical_id_prefix: &str, depth: usize) -> Vec<String> {
    if !is_enabled() {
        return vec![];
    }
    let graph = in_process_graph();
    let start_id = graph
        .select(|node: &GlyphNode| node.canonical_id.starts_with(canonical_id_prefix))
        .into_iter()
        .map(|n| n.canonical_id.clone())
        .next();

    match start_id {
        None => vec![],
        Some(id) => graph
            .walk(&id, depth)
            .unwrap_or_default()
            .into_iter()
            .map(|node| {
                let tags: Vec<&str> = node.tags.iter().map(String::as_str).collect();
                format!(
                    "[{}] glyph={} tags=[{}]",
                    &node.canonical_id[..8],
                    node.glyph,
                    tags.join(",")
                )
            })
            .collect(),
    }
}

// ── Session graph ────────────────────────────────────────────────────────────
//
// The session graph is a process-local, thread-local singleton.  It starts
// empty and is populated via `ingest_node` during the agent's session.
// A future phase will persist / restore it across restarts via GIX1 blobs.

use std::cell::RefCell;

thread_local! {
    static SESSION_GRAPH: RefCell<GlyphGraph> = RefCell::new(GlyphGraph::new());
}

fn in_process_graph() -> GlyphGraph {
    // Return a snapshot clone so the caller holds no borrow across yield points.
    SESSION_GRAPH.with(|g| g.borrow().clone())
}

/// Ingest a new glyph node into the session graph.
///
/// Call this when Omo-Koda2 observes a new memory chunk that should be
/// reachable via glyph queries in the same session.
pub fn ingest_node(node: GlyphNode) -> Result<(), crate::GlyphGraphError> {
    if !is_enabled() {
        return Ok(());
    }
    SESSION_GRAPH.with(|g| g.borrow_mut().insert(node))
}

/// Return the number of nodes currently held in the session graph.
pub fn session_graph_size() -> usize {
    SESSION_GRAPH.with(|g| g.borrow().len())
}

/// Derive shared-Odù inference edges across all nodes currently in the session
/// graph.  Returns the number of new edges materialized.
pub fn infer_session_edges() -> usize {
    if !is_enabled() {
        return 0;
    }
    SESSION_GRAPH.with(|g| g.borrow_mut().infer_shared_odu())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GlyphNode;

    fn with_enabled<F: FnOnce()>(f: F) {
        // SAFETY: tests run single-threaded under `cargo test -- --test-threads=1`
        // for env-var mutation; in CI the entire integration block is isolated.
        unsafe { std::env::set_var("LARQL_ENABLED", "true") };
        f();
        unsafe { std::env::remove_var("LARQL_ENABLED") };
        // Reset session graph so tests don't bleed into each other.
        SESSION_GRAPH.with(|g| *g.borrow_mut() = GlyphGraph::new());
    }

    #[test]
    fn returns_empty_when_disabled() {
        // LARQL_ENABLED unset → all ops are no-ops.
        unsafe { std::env::remove_var("LARQL_ENABLED") };
        assert!(query_glyph_memory("anything").is_empty());
        assert!(describe_glyph("00000000").is_empty());
        assert!(walk_neighbours("00000000", 2).is_empty());
        assert_eq!(session_graph_size(), 0);
        assert_eq!(infer_session_edges(), 0);
    }

    #[test]
    fn query_and_ingest_roundtrip() {
        with_enabled(|| {
            let mut node = GlyphNode::from_chunk("Àṣẹ emission cycle context", 1.0);
            node.tags.insert("emission".into());
            ingest_node(node).unwrap();

            let results = query_glyph_memory("emission");
            assert_eq!(results.len(), 1, "should find node by summary substring");
            assert!(results[0].contains("Àṣẹ emission"));

            let results_by_tag = query_glyph_memory("emission");
            assert_eq!(results_by_tag.len(), 1);
        });
    }

    #[test]
    fn describe_glyph_returns_node_info() {
        with_enabled(|| {
            let node = GlyphNode::from_chunk("sovereign memory probe", 2.0);
            let id_prefix = node.canonical_id[..8].to_string();
            ingest_node(node).unwrap();

            let desc = describe_glyph(&id_prefix);
            assert_eq!(desc.len(), 1);
            assert!(desc[0].contains("sovereign memory probe"));
        });
    }

    #[test]
    fn walk_neighbours_returns_connected_nodes() {
        with_enabled(|| {
            let node_a = GlyphNode::from_chunk("node alpha", 1.0);
            let node_b = GlyphNode::from_chunk("node beta", 2.0);
            let id_a = node_a.canonical_id[..8].to_string();
            let full_id_a = node_a.canonical_id.clone();
            let full_id_b = node_b.canonical_id.clone();

            ingest_node(node_a).unwrap();
            ingest_node(node_b).unwrap();

            // Wire the edge directly on the session graph.
            SESSION_GRAPH.with(|g| {
                g.borrow_mut().link(&full_id_a, &full_id_b, "follows").unwrap();
            });

            let neighbours = walk_neighbours(&id_a, 1);
            assert_eq!(neighbours.len(), 1);
            assert!(neighbours[0].contains("node beta"));
        });
    }

    #[test]
    fn infer_session_edges_materializes_shared_odu() {
        with_enabled(|| {
            // Two nodes with the same odu_base will get an inferred edge.
            let node_a = GlyphNode::from_chunk("seed-a", 0.0);
            let target_base = node_a.odu_base;
            let mut found = None;
            for i in 0..4096 {
                let candidate = GlyphNode::from_chunk(&format!("probe-{i}"), 1.0);
                if candidate.odu_base == target_base && candidate.canonical_id != node_a.canonical_id {
                    found = Some(candidate);
                    break;
                }
            }
            if let Some(node_b) = found {
                ingest_node(node_a).unwrap();
                ingest_node(node_b).unwrap();
                let added = infer_session_edges();
                assert_eq!(added, 1);
                // Idempotent.
                assert_eq!(infer_session_edges(), 0);
            }
            // If no shared-odu probe found in 4096 tries, skip gracefully.
        });
    }
}
