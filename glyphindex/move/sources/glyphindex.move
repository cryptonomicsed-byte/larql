/// Move port of the GlyphIndex sovereign-memory contract
/// (spec: OSOVM/GLYPHINDEX_SPEC.md; canonical reference:
/// Vantage/backend/glyph_index.py).
///
/// Move's role in the polyglot contract is the *verifiable, on-chain*
/// subset: GIX-FOLD-v1 folding, Odù linkage, keyless GIX1 envelope audit,
/// and the Sui-anchorable Merkle root — everything a chain needs to verify
/// receipts and anchors without holding keys or plaintext. Graph verbs and
/// sealing stay off-chain (larql, mnemopi, Vantage).
///
/// The unit tests embed the same frozen cross-language vectors asserted by
/// every other leg (Rust, TypeScript, Zero, Go, Elixir, Julia, Clojure,
/// Python).
module glyphindex::glyphindex {
    use std::hash;

    /// GIX-FOLD-v1 maps into the 63,422 valid printable BMP scalars.
    const FOLD_TOTAL: u64 = 63422;
    const R1_START: u64 = 0x0020;
    const R1_COUNT: u64 = 0xD7FF - 0x0020 + 1;
    const R2_START: u64 = 0xE000;
    const R2_COUNT: u64 = 0xFDCF - 0xE000 + 1;
    const R3_START: u64 = 0xFDF0;

    const EBadDigest: u64 = 1;
    const EBadEntry: u64 = 2;

    /// Fold a 32-byte digest onto its display-glyph code point.
    public fun glyph_fold_codepoint(digest: &vector<u8>): u64 {
        assert!(digest.length() == 32, EBadDigest);
        let mut rem: u64 = 0;
        let mut i = 0;
        while (i < digest.length()) {
            rem = (rem * 256 + (digest[i] as u64)) % FOLD_TOTAL;
            i = i + 1;
        };
        if (rem < R1_COUNT) return R1_START + rem;
        let rem = rem - R1_COUNT;
        if (rem < R2_COUNT) return R2_START + rem;
        R3_START + rem - R2_COUNT
    }

    /// Digital Calabash linkage: digest[0] is the base Odu (0..255).
    public fun odu_base(digest: &vector<u8>): u64 {
        assert!(digest.length() == 32, EBadDigest);
        digest[0] as u64
    }

    /// Composed Odu: top two digest bytes (0..65535).
    public fun odu_composed(digest: &vector<u8>): u64 {
        assert!(digest.length() == 32, EBadDigest);
        (digest[0] as u64) * 256 + (digest[1] as u64)
    }

    /// Keyless structural audit of a sealed GIX1 blob:
    /// "GIX1" | version(0x01) | flags(bit0=zlib only) | nonce(12) | ct||tag(16).
    public fun gix1_audit(blob: &vector<u8>): bool {
        if (blob.length() < 34) return false;
        if (blob[0] != 71 || blob[1] != 73 || blob[2] != 88 || blob[3] != 49) return false;
        if (blob[4] != 1) return false;
        blob[5] <= 1
    }

    /// Frozen empty-vault Merkle root: SHA-256("GIX1:empty").
    public fun empty_root(): vector<u8> {
        x"58cc47f0d238cea8bb764f7a927a54b398c8baf5de0a2332c03008038c3fd9a8"
    }

    /// Merkle root over sealed blobs, the value anchored on Sui:
    /// leaf = SHA-256(canonical_id bytes || blob_sha256), leaves sorted by
    /// canonical id, odd leaf promoted unchanged. `ids` are the raw 32-byte
    /// canonical ids and `blob_hashes` the SHA-256 of each sealed blob,
    /// index-aligned.
    public fun merkle_root(ids: &vector<vector<u8>>, blob_hashes: &vector<vector<u8>>): vector<u8> {
        assert!(ids.length() == blob_hashes.length(), EBadEntry);
        if (ids.length() == 0) return empty_root();

        // Insertion-sort indices by canonical id (byte-lexicographic).
        let mut order = vector<u64>[];
        let mut i = 0;
        while (i < ids.length()) {
            let mut j = order.length();
            while (j > 0 && lt(&ids[i], &ids[order[j - 1]])) {
                j = j - 1;
            };
            order.insert(i, j);
            i = i + 1;
        };

        let mut level = vector<vector<u8>>[];
        let mut k = 0;
        while (k < order.length()) {
            let idx = order[k];
            assert!(ids[idx].length() == 32, EBadEntry);
            let mut leaf = ids[idx];
            leaf.append(blob_hashes[idx]);
            level.push_back(hash::sha2_256(leaf));
            k = k + 1;
        };

        while (level.length() > 1) {
            let mut next = vector<vector<u8>>[];
            let mut p = 0;
            while (p + 1 < level.length()) {
                let mut pair = level[p];
                pair.append(level[p + 1]);
                next.push_back(hash::sha2_256(pair));
                p = p + 2;
            };
            if (level.length() % 2 == 1) {
                next.push_back(level[level.length() - 1]);
            };
            level = next;
        };
        level[0]
    }

    /// Byte-lexicographic less-than over equal-length byte vectors.
    fun lt(a: &vector<u8>, b: &vector<u8>): bool {
        let mut i = 0;
        let n = if (a.length() < b.length()) a.length() else b.length();
        while (i < n) {
            if (a[i] < b[i]) return true;
            if (a[i] > b[i]) return false;
            i = i + 1;
        };
        a.length() < b.length()
    }

    // ---- frozen cross-language vectors --------------------------------------

    #[test]
    fun fold_matches_frozen_vectors() {
        // SHA-256 digests of the five frozen chunks (see ../vectors.json).
        let vectors: vector<vector<u8>> = vector[
            x"e32866670f27c0ccaeda5facc74fcfc3f8c17b18bcae2fb9dc150d91c601db1b", // Àṣẹ
            x"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // hello
            x"44bb6336e45b2f5daf764930ac1d1f2798ad92c34048f0395686ac4509a0a7ec", // GlyphIndex
            x"bdf299182a61f04e31c6445f96a6a68d927d7e6cd9c56f883c8f1cc7cfac8683", // 😊🚀 Unicode test
            x"cca6a38cbd2874b7f2b4809ba11ee5177660c4ad5fb4851991414722729fd523", // Ọ̀rúnmìlà
        ];
        let codepoints: vector<u64> = vector[21841, 23636, 13726, 64591, 17963];
        let bases: vector<u64> = vector[227, 44, 68, 189, 204];
        let composed: vector<u64> = vector[58152, 11506, 17595, 48626, 52390];
        let mut i = 0;
        while (i < vectors.length()) {
            assert!(glyph_fold_codepoint(&vectors[i]) == codepoints[i]);
            assert!(odu_base(&vectors[i]) == bases[i]);
            assert!(odu_composed(&vectors[i]) == composed[i]);
            i = i + 1;
        };
    }

    #[test]
    fun sha256_of_hello_rederives_canonical_id() {
        let digest = hash::sha2_256(b"hello");
        assert!(digest == x"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fun gix1_audit_checks_envelope_structure() {
        let mut blob = b"GIX1";
        blob.push_back(1); // version
        blob.push_back(0); // flags
        let mut i = 0;
        while (i < 28) {
            blob.push_back(0);
            i = i + 1;
        };
        assert!(gix1_audit(&blob));
        // zlib flag is valid
        *&mut blob[5] = 1;
        assert!(gix1_audit(&blob));
        // unknown flags rejected
        *&mut blob[5] = 2;
        assert!(!gix1_audit(&blob));
        // unknown version rejected
        *&mut blob[5] = 0;
        *&mut blob[4] = 9;
        assert!(!gix1_audit(&blob));
        // short blob rejected
        let short = b"GIX1";
        assert!(!gix1_audit(&short));
    }

    #[test]
    fun merkle_root_matches_frozen_and_cross_language_vectors() {
        assert!(merkle_root(&vector[], &vector[]) == empty_root());

        // Cross-language vector: golden-fixture ids with
        // blob_sha256 = SHA-256(ascii canonical_id). Root asserted
        // identically by Rust, TypeScript, Go, Elixir, Julia, Clojure,
        // and Python legs.
        let hex_ids: vector<vector<u8>> = vector[
            b"e32866670f27c0ccaeda5facc74fcfc3f8c17b18bcae2fb9dc150d91c601db1b",
            b"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            b"44bb6336e45b2f5daf764930ac1d1f2798ad92c34048f0395686ac4509a0a7ec",
            b"bdf299182a61f04e31c6445f96a6a68d927d7e6cd9c56f883c8f1cc7cfac8683",
            b"cca6a38cbd2874b7f2b4809ba11ee5177660c4ad5fb4851991414722729fd523",
        ];
        let raw_ids: vector<vector<u8>> = vector[
            x"e32866670f27c0ccaeda5facc74fcfc3f8c17b18bcae2fb9dc150d91c601db1b",
            x"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            x"44bb6336e45b2f5daf764930ac1d1f2798ad92c34048f0395686ac4509a0a7ec",
            x"bdf299182a61f04e31c6445f96a6a68d927d7e6cd9c56f883c8f1cc7cfac8683",
            x"cca6a38cbd2874b7f2b4809ba11ee5177660c4ad5fb4851991414722729fd523",
        ];
        let mut blob_hashes = vector<vector<u8>>[];
        let mut i = 0;
        while (i < hex_ids.length()) {
            blob_hashes.push_back(hash::sha2_256(hex_ids[i]));
            i = i + 1;
        };
        let root = merkle_root(&raw_ids, &blob_hashes);
        assert!(root == x"b6c97879f0b04824c626cef414c8be9f459abd853743e013b25ccb34256015ed");
    }
}
