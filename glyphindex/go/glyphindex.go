// Package glyphindex is the Go port of the GlyphIndex sovereign-memory
// contract (spec: OSOVM/GLYPHINDEX_SPEC.md; canonical reference:
// Vantage/backend/glyph_index.py).
//
// It implements the portable, keyless surface: GIX-FOLD-v1 folding, Odù
// linkage, the content-addressed GlyphGraph with LQL-style verbs
// (DESCRIBE / SELECT / WALK / INFER) plus A2A merge, the cross-language
// JSON wire format, GIX1 structural audit, and the Sui-anchorable Merkle
// root. Conformance is proven against the shared frozen vectors and golden
// snapshot fixture in ../vectors.json and ../glyph-graph-snapshot.json.
package glyphindex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// FoldTotal is the number of valid printable BMP scalars GIX-FOLD-v1 maps into.
const FoldTotal = 63422

var foldRanges = [3][2]uint32{
	{0x0020, 0xD7FF - 0x0020 + 1},
	{0xE000, 0xFDCF - 0xE000 + 1},
	{0xFDF0, 0xFFFD - 0xFDF0 + 1},
}

// GIX1EmptyRoot is the frozen empty-vault Merkle root: SHA-256("GIX1:empty").
const GIX1EmptyRoot = "58cc47f0d238cea8bb764f7a927a54b398c8baf5de0a2332c03008038c3fd9a8"

// ContentHash returns SHA-256 of the chunk's UTF-8 bytes.
func ContentHash(text string) [32]byte {
	return sha256.Sum256([]byte(text))
}

// CanonicalID is the hex form of a content hash — the true address.
func CanonicalID(digest [32]byte) string {
	return hex.EncodeToString(digest[:])
}

// GlyphFold folds a digest onto its display glyph (big-endian mod).
func GlyphFold(digest [32]byte) rune {
	var rem uint64
	for _, b := range digest {
		rem = (rem<<8 | uint64(b)) % FoldTotal
	}
	idx := uint32(rem)
	for _, r := range foldRanges {
		if idx < r[1] {
			return rune(r[0] + idx)
		}
		idx -= r[1]
	}
	panic("unreachable: fold index exceeds range total")
}

// OduLink returns the Digital Calabash linkage (base, composed).
func OduLink(digest [32]byte) (uint8, uint16) {
	return digest[0], uint16(digest[0])<<8 | uint16(digest[1])
}

// GlyphNode is the metadata projection of one sealed memory chunk.
type GlyphNode struct {
	CanonicalID  string   `json:"canonical_id"`
	Glyph        string   `json:"glyph"`
	OduBase      uint8    `json:"odu_base"`
	OduComposed  uint16   `json:"odu_composed"`
	Ts           float64  `json:"ts"`
	Tags         []string `json:"tags"`
	WalrusBlobID *string  `json:"walrus_blob_id"`
}

// NodeFromChunk builds the node for a plaintext chunk (plaintext not retained).
func NodeFromChunk(chunk string, ts float64) GlyphNode {
	digest := ContentHash(chunk)
	base, composed := OduLink(digest)
	return GlyphNode{
		CanonicalID: CanonicalID(digest),
		Glyph:       string(GlyphFold(digest)),
		OduBase:     base,
		OduComposed: composed,
		Ts:          ts,
		Tags:        []string{},
	}
}

// GlyphEdge is a typed edge between two memory nodes.
type GlyphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}

// Description is the DESCRIBE output for a node.
type Description struct {
	Node     GlyphNode
	Outgoing []GlyphEdge
	Incoming []GlyphEdge
}

// GlyphGraph is the in-memory glyph knowledge graph.
type GlyphGraph struct {
	nodes map[string]*GlyphNode
	edges map[GlyphEdge]struct{}
}

func NewGraph() *GlyphGraph {
	return &GlyphGraph{nodes: map[string]*GlyphNode{}, edges: map[GlyphEdge]struct{}{}}
}

func (g *GlyphGraph) Len() int       { return len(g.nodes) }
func (g *GlyphGraph) EdgeCount() int { return len(g.edges) }

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func dedupeSort(tags []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	sort.Strings(out) // byte-wise, matching Rust BTreeSet<String> order
	return out
}

func (g *GlyphGraph) Insert(node GlyphNode) error {
	if !validID(node.CanonicalID) {
		return fmt.Errorf("canonical id must be 64 lowercase hex chars")
	}
	node.Tags = dedupeSort(node.Tags)
	g.nodes[node.CanonicalID] = &node
	return nil
}

func (g *GlyphGraph) Get(id string) *GlyphNode { return g.nodes[id] }

func (g *GlyphGraph) Link(from, to, relation string) error {
	for _, id := range []string{from, to} {
		if _, ok := g.nodes[id]; !ok {
			return fmt.Errorf("unknown node %s", id)
		}
	}
	g.edges[GlyphEdge{From: from, To: to, Relation: relation}] = struct{}{}
	return nil
}

func (g *GlyphGraph) sortedEdges() []GlyphEdge {
	out := make([]GlyphEdge, 0, len(g.edges))
	for e := range g.edges {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Relation < out[j].Relation
	})
	return out
}

func (g *GlyphGraph) sortedIDs() []string {
	ids := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Describe returns node metadata plus incident edges.
func (g *GlyphGraph) Describe(id string) (Description, error) {
	node, ok := g.nodes[id]
	if !ok {
		return Description{}, fmt.Errorf("unknown node %s", id)
	}
	d := Description{Node: *node}
	for _, e := range g.sortedEdges() {
		if e.From == id {
			d.Outgoing = append(d.Outgoing, e)
		}
		if e.To == id {
			d.Incoming = append(d.Incoming, e)
		}
	}
	return d, nil
}

// SelectByTag filters nodes carrying a tag, in canonical-id order.
func (g *GlyphGraph) SelectByTag(tag string) []GlyphNode {
	var out []GlyphNode
	for _, id := range g.sortedIDs() {
		node := g.nodes[id]
		for _, t := range node.Tags {
			if t == tag {
				out = append(out, *node)
				break
			}
		}
	}
	return out
}

// Walk is a depth-limited undirected BFS in discovery order, start excluded.
func (g *GlyphGraph) Walk(start string, depth int) ([]GlyphNode, error) {
	if _, ok := g.nodes[start]; !ok {
		return nil, fmt.Errorf("unknown node %s", start)
	}
	edges := g.sortedEdges()
	seen := map[string]struct{}{start: {}}
	type qe struct {
		id string
		d  int
	}
	queue := []qe{{start, 0}}
	var out []GlyphNode
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.d == depth {
			continue
		}
		for _, e := range edges {
			var next string
			switch cur.id {
			case e.From:
				next = e.To
			case e.To:
				next = e.From
			default:
				continue
			}
			if _, ok := seen[next]; ok {
				continue
			}
			seen[next] = struct{}{}
			out = append(out, *g.nodes[next])
			queue = append(queue, qe{next, cur.d + 1})
		}
	}
	return out, nil
}

// InferSharedOdu materializes "shared-odu" edges between nodes whose Odù
// share a base byte. Returns how many new edges were added.
func (g *GlyphGraph) InferSharedOdu() int {
	ids := g.sortedIDs()
	added := 0
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if g.nodes[ids[i]].OduBase != g.nodes[ids[j]].OduBase {
				continue
			}
			edge := GlyphEdge{From: ids[i], To: ids[j], Relation: "shared-odu"}
			if _, ok := g.edges[edge]; !ok {
				g.edges[edge] = struct{}{}
				added++
			}
		}
	}
	return added
}

// Merge unions another projection: tags union, earliest ts wins, existing
// locators are never dropped. Returns (nodesAdded, edgesAdded); idempotent.
func (g *GlyphGraph) Merge(other *GlyphGraph) (int, int) {
	nodesAdded := 0
	for _, id := range other.sortedIDs() {
		theirs := other.nodes[id]
		if existing, ok := g.nodes[id]; ok {
			existing.Tags = dedupeSort(append(existing.Tags, theirs.Tags...))
			if theirs.Ts < existing.Ts {
				existing.Ts = theirs.Ts
			}
			if existing.WalrusBlobID == nil {
				existing.WalrusBlobID = theirs.WalrusBlobID
			}
			continue
		}
		copied := *theirs
		copied.Tags = dedupeSort(copied.Tags)
		g.nodes[id] = &copied
		nodesAdded++
	}
	edgesAdded := 0
	for edge := range other.edges {
		if _, ok := g.edges[edge]; !ok {
			g.edges[edge] = struct{}{}
			edgesAdded++
		}
	}
	return nodesAdded, edgesAdded
}

// Wire is the cross-language JSON shape.
type Wire struct {
	Nodes map[string]GlyphNode `json:"nodes"`
	Edges []GlyphEdge          `json:"edges"`
}

// ToWire serializes with deterministic edge ordering.
func (g *GlyphGraph) ToWire() Wire {
	nodes := make(map[string]GlyphNode, len(g.nodes))
	for id, node := range g.nodes {
		nodes[id] = *node
	}
	return Wire{Nodes: nodes, Edges: g.sortedEdges()}
}

// FromWire loads a graph from the wire shape.
func FromWire(w Wire) (*GlyphGraph, error) {
	g := NewGraph()
	for _, node := range w.Nodes {
		if err := g.Insert(node); err != nil {
			return nil, err
		}
	}
	for _, e := range w.Edges {
		if err := g.Link(e.From, e.To, e.Relation); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// ParseWire decodes wire JSON bytes.
func ParseWire(data []byte) (Wire, error) {
	var w Wire
	err := json.Unmarshal(data, &w)
	return w, err
}

// Gix1Audit is the keyless structural audit of a sealed GIX1 blob:
// "GIX1" | version(0x01) | flags(bit0=zlib only) | nonce(12) | ct||tag(16).
func Gix1Audit(blob []byte) bool {
	return len(blob) >= 34 && string(blob[:4]) == "GIX1" && blob[4] == 1 && blob[5] <= 1
}

// MerkleEntry pairs a canonical id with the SHA-256 of its sealed blob.
type MerkleEntry struct {
	CanonicalID string
	BlobSha256  [32]byte
}

// MerkleRoot computes the Sui-anchorable root: leaf = SHA-256(id bytes ||
// blob hash), leaves sorted by canonical id, odd leaf promoted unchanged.
func MerkleRoot(entries []MerkleEntry) (string, error) {
	if len(entries) == 0 {
		return GIX1EmptyRoot, nil
	}
	sorted := append([]MerkleEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CanonicalID < sorted[j].CanonicalID })
	level := make([][32]byte, 0, len(sorted))
	for _, e := range sorted {
		idBytes, err := hex.DecodeString(e.CanonicalID)
		if err != nil || len(idBytes) != 32 {
			return "", fmt.Errorf("canonical id must be 64 hex chars")
		}
		level = append(level, sha256.Sum256(append(idBytes, e.BlobSha256[:]...)))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, sha256.Sum256(append(level[i][:], level[i+1][:]...)))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return hex.EncodeToString(level[0][:]), nil
}
