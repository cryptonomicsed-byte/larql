package glyphindex

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type vectors struct {
	Fold []struct {
		Text        string  `json:"text"`
		CanonicalID string  `json:"canonical_id"`
		Codepoint   uint32  `json:"codepoint"`
		OduBase     uint8   `json:"odu_base"`
		OduComposed uint16  `json:"odu_composed"`
	} `json:"fold"`
	Merkle struct {
		EmptyRoot  string `json:"empty_root"`
		VectorRoot string `json:"vector_root"`
	} `json:"merkle"`
	Walk struct {
		StartText   string `json:"start_text"`
		Depth1Count int    `json:"depth_1_count"`
		Depth2Count int    `json:"depth_2_count"`
	} `json:"walk"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	data, err := os.ReadFile("../vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func loadFixture(t *testing.T) ([]byte, Wire) {
	t.Helper()
	data, err := os.ReadFile("../glyph-graph-snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	w, err := ParseWire(data)
	if err != nil {
		t.Fatal(err)
	}
	return data, w
}

func TestFrozenFoldVectors(t *testing.T) {
	for _, vec := range loadVectors(t).Fold {
		digest := ContentHash(vec.Text)
		if CanonicalID(digest) != vec.CanonicalID {
			t.Fatalf("%s: canonical id mismatch", vec.Text)
		}
		if uint32(GlyphFold(digest)) != vec.Codepoint {
			t.Fatalf("%s: fold mismatch", vec.Text)
		}
		base, composed := OduLink(digest)
		if base != vec.OduBase || composed != vec.OduComposed {
			t.Fatalf("%s: odu mismatch", vec.Text)
		}
	}
}

func TestGoldenFixtureRoundTripAndWalk(t *testing.T) {
	raw, wire := loadFixture(t)
	graph, err := FromWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Len() != 5 {
		t.Fatalf("expected 5 nodes, got %d", graph.Len())
	}

	// Semantic re-serialization equality against the committed bytes.
	emitted, err := json.Marshal(graph.ToWire())
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(emitted, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatal("wire round-trip is not structurally identical")
	}

	v := loadVectors(t)
	start := CanonicalID(ContentHash(v.Walk.StartText))
	d1, err := graph.Walk(start, 1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := graph.Walk(start, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(d1) != v.Walk.Depth1Count || len(d2) != v.Walk.Depth2Count {
		t.Fatalf("walk counts %d/%d, want %d/%d", len(d1), len(d2), v.Walk.Depth1Count, v.Walk.Depth2Count)
	}

	hello := CanonicalID(ContentHash("hello"))
	desc, err := graph.Describe(hello)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Node.WalrusBlobID == nil || *desc.Node.WalrusBlobID != "walrus://vault/hello-chunk" {
		t.Fatal("hello node lost its walrus locator")
	}
	if len(graph.SelectByTag("topic:greeting")) != 1 {
		t.Fatal("tag select failed")
	}
}

func TestMergeSemantics(t *testing.T) {
	mine := NewGraph()
	shared := NodeFromChunk("shared chunk", 0)
	only := NodeFromChunk("only mine", 1)
	if err := mine.Insert(shared); err != nil {
		t.Fatal(err)
	}
	if err := mine.Insert(only); err != nil {
		t.Fatal(err)
	}
	if err := mine.Link(shared.CanonicalID, only.CanonicalID, "follows"); err != nil {
		t.Fatal(err)
	}

	theirs := NewGraph()
	peer := NodeFromChunk("shared chunk", 99)
	peer.Tags = []string{"from:peer"}
	locator := "walrus://peer/blob"
	peer.WalrusBlobID = &locator
	fresh := NodeFromChunk("only theirs", 3)
	_ = theirs.Insert(peer)
	_ = theirs.Insert(fresh)
	_ = theirs.Link(peer.CanonicalID, fresh.CanonicalID, "rem-cluster")

	nodesAdded, edgesAdded := mine.Merge(theirs)
	if nodesAdded != 1 || edgesAdded != 1 {
		t.Fatalf("merge stats %d/%d", nodesAdded, edgesAdded)
	}
	merged := mine.Get(shared.CanonicalID)
	if merged.Ts != 0 {
		t.Fatal("earliest ts must win")
	}
	if merged.WalrusBlobID == nil || *merged.WalrusBlobID != locator {
		t.Fatal("existing-nil locator must adopt peer locator")
	}
	if nodesAdded, edgesAdded = mine.Merge(theirs); nodesAdded != 0 || edgesAdded != 0 {
		t.Fatal("merge must be idempotent")
	}
}

func TestInferSharedOdu(t *testing.T) {
	graph := NewGraph()
	a := NodeFromChunk("seed-a", 0)
	_ = graph.Insert(a)
	inserted := false
	for i := 0; i < 4096 && !inserted; i++ {
		candidate := NodeFromChunk("probe-"+string(rune('0'+i%10))+string(rune('0'+(i/10)%10))+string(rune('0'+(i/100)%10))+string(rune('0'+(i/1000)%10)), 1)
		if candidate.OduBase == a.OduBase && candidate.CanonicalID != a.CanonicalID {
			_ = graph.Insert(candidate)
			inserted = true
		}
	}
	if !inserted {
		t.Fatal("no shared-base probe found")
	}
	if graph.InferSharedOdu() != 1 {
		t.Fatal("expected one inferred edge")
	}
	if graph.InferSharedOdu() != 0 {
		t.Fatal("infer must be idempotent")
	}
}

func TestGix1AuditAndMerkle(t *testing.T) {
	blob := make([]byte, 34)
	copy(blob, "GIX1")
	blob[4] = 1
	if !Gix1Audit(blob) {
		t.Fatal("valid envelope rejected")
	}
	blob[5] = 2
	if Gix1Audit(blob) {
		t.Fatal("unknown flags accepted")
	}
	if Gix1Audit(blob[:20]) {
		t.Fatal("short blob accepted")
	}

	v := loadVectors(t)
	root, err := MerkleRoot(nil)
	if err != nil || root != v.Merkle.EmptyRoot {
		t.Fatalf("empty root %s", root)
	}
	_, wire := loadFixture(t)
	var entries []MerkleEntry
	for id := range wire.Nodes {
		entries = append(entries, MerkleEntry{CanonicalID: id, BlobSha256: sha256.Sum256([]byte(id))})
	}
	root, err = MerkleRoot(entries)
	if err != nil || root != v.Merkle.VectorRoot {
		t.Fatalf("vector root %s", root)
	}
}
