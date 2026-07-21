# Julia port of the GlyphIndex sovereign-memory contract
# (spec: OSOVM/GLYPHINDEX_SPEC.md; canonical reference:
# Vantage/backend/glyph_index.py).
#
# Portable, keyless surface: GIX-FOLD-v1 folding, Odù linkage, the
# content-addressed GlyphGraph with LQL-style verbs (DESCRIBE / SELECT /
# WALK / INFER) plus A2A merge, the cross-language JSON wire format, GIX1
# structural audit, and the Sui-anchorable Merkle root. Dependency-free
# beyond the SHA standard library: ships its own minimal JSON codec.
#
# Run the conformance suite:  julia glyphindex.jl

module GlyphIndex

using SHA

export content_hash, canonical_id, glyph_fold, odu_link, node_from_chunk,
    GlyphGraph, insert!, link!, describe, select_by_tag, walk, infer_shared_odu!,
    merge_graphs!, to_wire, from_wire, gix1_audit, merkle_root, EMPTY_ROOT

const FOLD_RANGES = [(0x0020, 0xD7FF - 0x0020 + 1), (0xE000, 0xFDCF - 0xE000 + 1), (0xFDF0, 0xFFFD - 0xFDF0 + 1)]
const FOLD_TOTAL = sum(last.(FOLD_RANGES))
const EMPTY_ROOT = "58cc47f0d238cea8bb764f7a927a54b398c8baf5de0a2332c03008038c3fd9a8"

content_hash(text::AbstractString) = sha256(Vector{UInt8}(codeunits(text)))

canonical_id(digest::Vector{UInt8}) = bytes2hex(digest)

function glyph_fold(digest::Vector{UInt8})
    rem = UInt64(0)
    for byte in digest
        rem = (rem << 8 | UInt64(byte)) % UInt64(FOLD_TOTAL)
    end
    idx = Int(rem)
    for (start, count) in FOLD_RANGES
        idx < count && return string(Char(Int(start) + idx))
        idx -= count
    end
    error("unreachable: fold index exceeds range total")
end

odu_link(digest::Vector{UInt8}) = (Int(digest[1]), Int(digest[1]) << 8 | Int(digest[2]))

function node_from_chunk(chunk::AbstractString, ts::Real)
    digest = content_hash(chunk)
    base, composed = odu_link(digest)
    Dict{String,Any}(
        "canonical_id" => canonical_id(digest),
        "glyph" => glyph_fold(digest),
        "odu_base" => base,
        "odu_composed" => composed,
        "ts" => ts,
        "tags" => String[],
        "walrus_blob_id" => nothing,
    )
end

mutable struct GlyphGraph
    nodes::Dict{String,Dict{String,Any}}
    edges::Set{NTuple{3,String}}
end

GlyphGraph() = GlyphGraph(Dict(), Set())

function insert!(graph::GlyphGraph, node::Dict{String,Any})
    id = node["canonical_id"]
    occursin(r"^[0-9a-f]{64}$", id) || error("canonical id must be 64 lowercase hex chars")
    normalized = copy(node)
    normalized["tags"] = sort(unique(String.(node["tags"])))
    graph.nodes[id] = normalized
    graph
end

function link!(graph::GlyphGraph, from::String, to::String, relation::String)
    for id in (from, to)
        haskey(graph.nodes, id) || error("unknown node $id")
    end
    push!(graph.edges, (from, to, relation))
    graph
end

sorted_edges(graph::GlyphGraph) = sort(collect(graph.edges))

function describe(graph::GlyphGraph, id::String)
    haskey(graph.nodes, id) || error("unknown node $id")
    edges = sorted_edges(graph)
    (node = graph.nodes[id],
        outgoing = [e for e in edges if e[1] == id],
        incoming = [e for e in edges if e[2] == id])
end

select_by_tag(graph::GlyphGraph, tag::String) =
    [graph.nodes[id] for id in sort(collect(keys(graph.nodes))) if tag in graph.nodes[id]["tags"]]

function walk(graph::GlyphGraph, start::String, depth::Int)
    haskey(graph.nodes, start) || error("unknown node $start")
    edges = sorted_edges(graph)
    seen = Set([start])
    queue = [(start, 0)]
    out = Dict{String,Any}[]
    while !isempty(queue)
        (id, d) = popfirst!(queue)
        d == depth && continue
        for (from, to, _) in edges
            next = from == id ? to : (to == id ? from : nothing)
            (next === nothing || next in seen) && continue
            push!(seen, next)
            push!(out, graph.nodes[next])
            push!(queue, (next, d + 1))
        end
    end
    out
end

function infer_shared_odu!(graph::GlyphGraph)
    ids = sort(collect(keys(graph.nodes)))
    added = 0
    for i in eachindex(ids), j in (i+1):lastindex(ids)
        graph.nodes[ids[i]]["odu_base"] == graph.nodes[ids[j]]["odu_base"] || continue
        edge = (ids[i], ids[j], "shared-odu")
        if !(edge in graph.edges)
            push!(graph.edges, edge)
            added += 1
        end
    end
    added
end

function merge_graphs!(graph::GlyphGraph, other::GlyphGraph)
    nodes_added = 0
    for id in sort(collect(keys(other.nodes)))
        theirs = other.nodes[id]
        if haskey(graph.nodes, id)
            existing = graph.nodes[id]
            existing["tags"] = sort(unique(vcat(existing["tags"], theirs["tags"])))
            existing["ts"] = min(existing["ts"], theirs["ts"])
            existing["walrus_blob_id"] === nothing && (existing["walrus_blob_id"] = theirs["walrus_blob_id"])
        else
            insert!(graph, theirs)
            nodes_added += 1
        end
    end
    edges_added = length(setdiff(other.edges, graph.edges))
    union!(graph.edges, other.edges)
    (nodes_added, edges_added)
end

to_wire(graph::GlyphGraph) = Dict{String,Any}(
    "nodes" => graph.nodes,
    "edges" => [Dict("from" => e[1], "to" => e[2], "relation" => e[3]) for e in sorted_edges(graph)],
)

function from_wire(wire::Dict{String,Any})
    graph = GlyphGraph()
    for node in values(wire["nodes"])
        insert!(graph, Dict{String,Any}(node))
    end
    for edge in wire["edges"]
        link!(graph, edge["from"], edge["to"], edge["relation"])
    end
    graph
end

gix1_audit(blob::Vector{UInt8}) =
    length(blob) >= 34 && blob[1:4] == b"GIX1" && blob[5] == 0x01 && blob[6] <= 0x01

function merkle_root(entries::Vector{Tuple{String,Vector{UInt8}}})
    isempty(entries) && return EMPTY_ROOT
    sorted = sort(entries; by = first)
    level = [sha256(vcat(hex2bytes(id), blob_hash)) for (id, blob_hash) in sorted]
    while length(level) > 1
        next = Vector{Vector{UInt8}}()
        for i in 1:2:length(level)-1
            push!(next, sha256(vcat(level[i], level[i+1])))
        end
        isodd(length(level)) && push!(next, level[end])
        level = next
    end
    bytes2hex(level[1])
end

# ---- minimal JSON codec -----------------------------------------------------

module Json

function decode(text::AbstractString)
    value, pos = _value(text, firstindex(text))
    pos = _ws(text, pos)
    pos > lastindex(text) || error("trailing JSON content")
    value
end

function _ws(s, pos)
    while pos <= lastindex(s) && s[pos] in (' ', '\t', '\n', '\r')
        pos = nextind(s, pos)
    end
    pos
end

function _value(s, pos)
    pos = _ws(s, pos)
    c = s[pos]
    c == '{' && return _object(s, pos)
    c == '[' && return _array(s, pos)
    c == '"' && return _string(s, pos)
    startswith(SubString(s, pos), "null") && return (nothing, pos + 4)
    startswith(SubString(s, pos), "true") && return (true, pos + 4)
    startswith(SubString(s, pos), "false") && return (false, pos + 5)
    _number(s, pos)
end

function _object(s, pos)
    out = Dict{String,Any}()
    pos = _ws(s, nextind(s, pos))
    if s[pos] == '}'
        return (out, nextind(s, pos))
    end
    while true
        key, pos = _string(s, _ws(s, pos))
        pos = _ws(s, pos)
        s[pos] == ':' || error("expected ':'")
        value, pos = _value(s, nextind(s, pos))
        out[key] = value
        pos = _ws(s, pos)
        if s[pos] == ','
            pos = _ws(s, nextind(s, pos))
        elseif s[pos] == '}'
            return (out, nextind(s, pos))
        else
            error("bad object")
        end
    end
end

function _array(s, pos)
    out = Any[]
    pos = _ws(s, nextind(s, pos))
    if s[pos] == ']'
        return (out, nextind(s, pos))
    end
    while true
        value, pos = _value(s, pos)
        push!(out, value)
        pos = _ws(s, pos)
        if s[pos] == ','
            pos = _ws(s, nextind(s, pos))
        elseif s[pos] == ']'
            return (out, nextind(s, pos))
        else
            error("bad array")
        end
    end
end

function _string(s, pos)
    s[pos] == '"' || error("expected string")
    buf = IOBuffer()
    pos = nextind(s, pos)
    while true
        c = s[pos]
        if c == '"'
            return (String(take!(buf)), nextind(s, pos))
        elseif c == '\\'
            pos = nextind(s, pos)
            esc = s[pos]
            if esc == 'u'
                hex = SubString(s, nextind(s, pos), nextind(s, pos, 4))
                print(buf, Char(parse(Int, hex; base = 16)))
                pos = nextind(s, pos, 4)
            else
                mapped = Dict('"' => '"', '\\' => '\\', '/' => '/', 'b' => '\b', 'f' => '\f', 'n' => '\n', 'r' => '\r', 't' => '\t')
                print(buf, mapped[esc])
            end
        else
            print(buf, c)
        end
        pos = nextind(s, pos)
    end
end

function _number(s, pos)
    stop = pos
    while stop <= lastindex(s) && (isdigit(s[stop]) || s[stop] in ('-', '+', '.', 'e', 'E'))
        stop = nextind(s, stop)
    end
    text = SubString(s, pos, prevind(s, stop))
    if occursin(r"[.eE]", text)
        (parse(Float64, text), stop)
    else
        (parse(Int, text), stop)
    end
end

encode(value::Nothing) = "null"
encode(value::Bool) = value ? "true" : "false"
encode(value::Integer) = string(value)
function encode(value::AbstractFloat)
    isinteger(value) ? string(Int(value)) * ".0" : string(value)
end
function encode(value::AbstractString)
    escaped = replace(value, "\\" => "\\\\", "\"" => "\\\"", "\n" => "\\n", "\t" => "\\t", "\r" => "\\r")
    "\"" * escaped * "\""
end
encode(value::AbstractVector) = "[" * join(map(encode, value), ",") * "]"
function encode(value::AbstractDict)
    body = join(["$(encode(String(k))):$(encode(value[k]))" for k in sort(collect(keys(value)))], ",")
    "{" * body * "}"
end

end # module Json

end # module GlyphIndex

# ---- conformance ------------------------------------------------------------

if abspath(PROGRAM_FILE) == @__FILE__
    using .GlyphIndex
    const GI = GlyphIndex
    const J = GlyphIndex.Json

    dir = dirname(@__FILE__)
    vectors = J.decode(read(joinpath(dir, "..", "vectors.json"), String))
    fixture_raw = read(joinpath(dir, "..", "glyph-graph-snapshot.json"), String)
    fixture = J.decode(fixture_raw)

    check(cond, label) = cond || error("conformance failure: $label")

    for vec in vectors["fold"]
        digest = GI.content_hash(vec["text"])
        check(GI.canonical_id(digest) == vec["canonical_id"], "canonical id $(vec["text"])")
        check(Int(only(GI.glyph_fold(digest))) == vec["codepoint"], "fold $(vec["text"])")
        base, composed = GI.odu_link(digest)
        check(base == vec["odu_base"] && composed == vec["odu_composed"], "odu $(vec["text"])")
    end

    graph = GI.from_wire(fixture)
    check(length(graph.nodes) == 5, "node count")
    check(J.decode(J.encode(GI.to_wire(graph))) == fixture, "wire round-trip structural equality")

    start = GI.canonical_id(GI.content_hash(vectors["walk"]["start_text"]))
    check(length(GI.walk(graph, start, 1)) == vectors["walk"]["depth_1_count"], "walk depth 1")
    check(length(GI.walk(graph, start, 2)) == vectors["walk"]["depth_2_count"], "walk depth 2")

    hello = GI.canonical_id(GI.content_hash("hello"))
    described = GI.describe(graph, hello)
    check(described.node["walrus_blob_id"] == "walrus://vault/hello-chunk", "hello locator")
    check(length(GI.select_by_tag(graph, "topic:greeting")) == 1, "tag select")

    mine = GI.GlyphGraph()
    GI.insert!(mine, GI.node_from_chunk("shared chunk", 0))
    GI.insert!(mine, GI.node_from_chunk("only mine", 1))
    peer = GI.node_from_chunk("shared chunk", 99)
    peer["tags"] = ["from:peer"]
    peer["walrus_blob_id"] = "walrus://peer/blob"
    theirs = GI.GlyphGraph()
    GI.insert!(theirs, peer)
    GI.insert!(theirs, GI.node_from_chunk("only theirs", 3))
    nodes_added, edges_added = GI.merge_graphs!(mine, theirs)
    check(nodes_added == 1 && edges_added == 0, "merge stats")
    shared_id = GI.canonical_id(GI.content_hash("shared chunk"))
    check(mine.nodes[shared_id]["ts"] == 0, "earliest ts wins")
    check(mine.nodes[shared_id]["walrus_blob_id"] == "walrus://peer/blob", "locator adopted")
    n2, e2 = GI.merge_graphs!(mine, theirs)
    check(n2 == 0 && e2 == 0, "merge idempotent")

    blob = vcat(Vector{UInt8}(b"GIX1"), UInt8[1, 0], zeros(UInt8, 28))
    check(GI.gix1_audit(blob), "gix1 audit accepts")
    bad = copy(blob); bad[5] = 0x09
    check(!GI.gix1_audit(bad), "bad version rejected")

    check(GI.merkle_root(Tuple{String,Vector{UInt8}}[]) == vectors["merkle"]["empty_root"], "empty merkle root")
    entries = [(id, GI.content_hash(id)) for id in collect(keys(fixture["nodes"]))]
    check(GI.merkle_root(entries) == vectors["merkle"]["vector_root"], "merkle vector root")

    println("glyphindex julia conformance ok")
end
