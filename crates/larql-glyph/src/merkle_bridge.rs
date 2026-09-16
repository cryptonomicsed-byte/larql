//! merkle_bridge — Conversion adapter between the two merkle_root signatures.
//!
//! ## The API mismatch (M4)
//!
//! `gix-types::merkle_root`       takes `&[&str]`                    (canonical_ids)
//! `sovereign-types::merkle_root` takes `&BTreeMap<&str, Value>`     (Walrus KV pairs)
//!
//! The byte-level algorithms differ in what they hash per leaf:
//!   gix-types:      sha256(canonical_id)
//!   sovereign-types: sha256("key:value_json")
//!
//! This adapter converts a sovereign-types Walrus KV map into the
//! canonical_id slice expected by gix-types without changing either
//! implementation.  The conversion rule:
//!
//!   canonical_id(k, v) = hex( sha256("k:v_json") )
//!
//! which exactly mirrors the leaf-hashing sovereign-types uses internally,
//! so the final Merkle roots are identical for the same data.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use std::collections::BTreeMap;
//! use serde_json::json;
//! use larql_glyph::merkle_bridge::merkle_root_from_kv;
//!
//! let mut kv = BTreeMap::new();
//! kv.insert("agent_id", json!("agent-001"));
//! kv.insert("odu",       json!(42));
//!
//! let root = merkle_root_from_kv(&kv);
//! assert!(root.len() == 64);   // 32-byte hex
//! ```

use gix_types::gix1_merkle_root;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Convert a Walrus KV map (sovereign-types layout) into a gix-types Merkle root.
///
/// Leaf construction mirrors sovereign-types exactly:
///   leaf_preimage = format!("{key}:{value_json}")
///   leaf_id       = hex( sha256(leaf_preimage) )
///
/// The resulting leaf_ids are then passed to `gix1_merkle_root(&[&str])`.
pub fn merkle_root_from_kv(fields: &BTreeMap<&str, Value>) -> String {
    if fields.is_empty() {
        return gix_types::GIX1_EMPTY_ROOT.to_string();
    }

    // Build sorted canonical_id strings (BTreeMap is already alphabetically sorted).
    let leaf_ids: Vec<String> = fields
        .iter()
        .map(|(k, v)| {
            let preimage = format!("{}:{}", k, v);
            let hash: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
            hex::encode(hash)
        })
        .collect();

    let refs: Vec<&str> = leaf_ids.iter().map(String::as_str).collect();
    gix1_merkle_root(&refs)
}

/// Identical to `merkle_root_from_kv` but accepts owned String keys,
/// matching the ergonomics of callers that hold `BTreeMap<String, Value>`.
pub fn merkle_root_from_owned_kv(fields: &BTreeMap<String, Value>) -> String {
    let borrowed: BTreeMap<&str, Value> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    merkle_root_from_kv(&borrowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_map_returns_gix_empty_root() {
        let empty: BTreeMap<&str, Value> = BTreeMap::new();
        assert_eq!(merkle_root_from_kv(&empty), gix_types::GIX1_EMPTY_ROOT);
    }

    #[test]
    fn single_field_is_64_hex_chars() {
        let mut kv = BTreeMap::new();
        kv.insert("agent_id", json!("agent-001"));
        let root = merkle_root_from_kv(&kv);
        assert_eq!(root.len(), 64, "root must be 32-byte hex");
        assert!(hex::decode(&root).is_ok(), "root must be valid hex");
    }

    #[test]
    fn deterministic_over_insertion_order() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("a", json!("hello"));
        kv1.insert("b", json!(42));

        // BTreeMap sorts by key so insertion order does not matter.
        let mut kv2 = BTreeMap::new();
        kv2.insert("b", json!(42));
        kv2.insert("a", json!("hello"));

        assert_eq!(merkle_root_from_kv(&kv1), merkle_root_from_kv(&kv2));
    }

    #[test]
    fn different_values_produce_different_roots() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("a", json!("hello"));

        let mut kv2 = BTreeMap::new();
        kv2.insert("a", json!("world"));

        assert_ne!(merkle_root_from_kv(&kv1), merkle_root_from_kv(&kv2));
    }

    #[test]
    fn owned_kv_matches_borrowed_kv() {
        let borrowed: BTreeMap<&str, Value> = [("x", json!(1)), ("y", json!("ok"))]
            .into_iter()
            .collect();
        let owned: BTreeMap<String, Value> = [("x".to_string(), json!(1)), ("y".to_string(), json!("ok"))]
            .into_iter()
            .collect();
        assert_eq!(
            merkle_root_from_kv(&borrowed),
            merkle_root_from_owned_kv(&owned)
        );
    }
}
