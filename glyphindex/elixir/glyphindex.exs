# Elixir port of the GlyphIndex sovereign-memory contract
# (spec: OSOVM/GLYPHINDEX_SPEC.md; canonical reference:
# Vantage/backend/glyph_index.py).
#
# Portable, keyless surface: GIX-FOLD-v1 folding, Odù linkage, the
# content-addressed GlyphGraph with LQL-style verbs (DESCRIBE / SELECT /
# WALK / INFER) plus A2A merge, the cross-language JSON wire format, GIX1
# structural audit, and the Sui-anchorable Merkle root. Dependency-free:
# ships its own minimal JSON codec so it runs on any OTP.
#
# Run the conformance suite:  elixir glyphindex.exs

defmodule GlyphIndex.Json do
  @moduledoc "Minimal JSON codec (decode + canonical sorted-key encode)."

  def decode!(bin) do
    {value, rest} = value(skip_ws(bin))
    "" = skip_ws(rest)
    value
  end

  defp skip_ws(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: skip_ws(rest)
  defp skip_ws(bin), do: bin

  defp value(<<"null", rest::binary>>), do: {nil, rest}
  defp value(<<"true", rest::binary>>), do: {true, rest}
  defp value(<<"false", rest::binary>>), do: {false, rest}
  defp value(<<?", rest::binary>>), do: string(rest, [])
  defp value(<<?{, rest::binary>>), do: object(skip_ws(rest), %{})
  defp value(<<?[, rest::binary>>), do: array(skip_ws(rest), [])
  defp value(bin), do: number(bin)

  defp string(<<?", rest::binary>>, acc), do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp string(<<?\\, esc, rest::binary>>, acc) do
    case esc do
      ?u ->
        <<hex::binary-size(4), tail::binary>> = rest
        string(tail, [<<String.to_integer(hex, 16)::utf8>> | acc])

      _ ->
        mapped = %{?" => ?", ?\\ => ?\\, ?/ => ?/, ?b => ?\b, ?f => ?\f, ?n => ?\n, ?r => ?\r, ?t => ?\t}
        string(rest, [Map.fetch!(mapped, esc) | acc])
    end
  end

  defp string(<<c::utf8, rest::binary>>, acc), do: string(rest, [<<c::utf8>> | acc])

  defp object(<<?}, rest::binary>>, acc), do: {acc, rest}

  defp object(bin, acc) do
    <<?", rest::binary>> = skip_ws(bin)
    {key, rest} = string(rest, [])
    <<?:, rest::binary>> = skip_ws(rest)
    {val, rest} = value(skip_ws(rest))

    case skip_ws(rest) do
      <<?,, tail::binary>> -> object(skip_ws(tail), Map.put(acc, key, val))
      <<?}, tail::binary>> -> {Map.put(acc, key, val), tail}
    end
  end

  defp array(<<?], rest::binary>>, acc), do: {Enum.reverse(acc), rest}

  defp array(bin, acc) do
    {val, rest} = value(bin)

    case skip_ws(rest) do
      <<?,, tail::binary>> -> array(skip_ws(tail), [val | acc])
      <<?], tail::binary>> -> {Enum.reverse([val | acc]), tail}
    end
  end

  defp number(bin) do
    {digits, rest} = take_number(bin, [])
    text = IO.iodata_to_binary(Enum.reverse(digits))

    if String.contains?(text, [".", "e", "E"]) do
      {String.to_float(text), rest}
    else
      {String.to_integer(text), rest}
    end
  end

  defp take_number(<<c, rest::binary>>, acc) when c in ?0..?9 or c in [?-, ?+, ?., ?e, ?E],
    do: take_number(rest, [c | acc])

  defp take_number(bin, acc), do: {acc, bin}

  def encode(nil), do: "null"
  def encode(true), do: "true"
  def encode(false), do: "false"
  def encode(value) when is_integer(value), do: Integer.to_string(value)
  def encode(value) when is_float(value), do: Float.to_string(value)

  def encode(value) when is_binary(value) do
    escaped =
      value
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
      |> String.replace("\n", "\\n")
      |> String.replace("\t", "\\t")
      |> String.replace("\r", "\\r")

    "\"" <> escaped <> "\""
  end

  def encode(value) when is_list(value), do: "[" <> Enum.map_join(value, ",", &encode/1) <> "]"

  def encode(value) when is_map(value) do
    body =
      value
      |> Map.keys()
      |> Enum.sort()
      |> Enum.map_join(",", fn key -> encode(key) <> ":" <> encode(Map.fetch!(value, key)) end)

    "{" <> body <> "}"
  end
end

defmodule GlyphIndex do
  @moduledoc "Content-addressed glyph memory graph with LQL-style verbs."

  @fold_ranges [{0x0020, 0xD7FF - 0x0020 + 1}, {0xE000, 0xFDCF - 0xE000 + 1}, {0xFDF0, 0xFFFD - 0xFDF0 + 1}]
  @fold_total Enum.sum(Enum.map(@fold_ranges, &elem(&1, 1)))
  @empty_root "58cc47f0d238cea8bb764f7a927a54b398c8baf5de0a2332c03008038c3fd9a8"

  def empty_root, do: @empty_root

  def content_hash(text), do: :crypto.hash(:sha256, text)

  def canonical_id(digest), do: Base.encode16(digest, case: :lower)

  def glyph_fold(digest) do
    idx = for(<<byte <- digest>>, reduce: 0, do: (rem -> Integer.mod(rem * 256 + byte, @fold_total)))
    fold_pick(idx, @fold_ranges)
  end

  defp fold_pick(idx, [{start, count} | rest]) do
    if idx < count, do: <<start + idx::utf8>>, else: fold_pick(idx - count, rest)
  end

  def odu_link(<<b0, b1, _::binary>>), do: {b0, b0 * 256 + b1}

  def node_from_chunk(chunk, ts) do
    digest = content_hash(chunk)
    {base, composed} = odu_link(digest)

    %{
      "canonical_id" => canonical_id(digest),
      "glyph" => glyph_fold(digest),
      "odu_base" => base,
      "odu_composed" => composed,
      "ts" => ts,
      "tags" => [],
      "walrus_blob_id" => nil
    }
  end

  def new_graph, do: %{nodes: %{}, edges: MapSet.new()}

  def insert(graph, node) do
    id = node["canonical_id"]

    unless is_binary(id) and byte_size(id) == 64 and String.match?(id, ~r/^[0-9a-f]{64}$/) do
      raise ArgumentError, "canonical id must be 64 lowercase hex chars"
    end

    normalized = Map.put(node, "tags", node["tags"] |> Enum.uniq() |> Enum.sort())
    %{graph | nodes: Map.put(graph.nodes, id, normalized)}
  end

  def link(graph, from, to, relation) do
    for id <- [from, to], not Map.has_key?(graph.nodes, id) do
      raise ArgumentError, "unknown node #{id}"
    end

    %{graph | edges: MapSet.put(graph.edges, {from, to, relation})}
  end

  defp sorted_edges(graph), do: graph.edges |> MapSet.to_list() |> Enum.sort()

  def describe(graph, id) do
    node = Map.fetch!(graph.nodes, id)
    edges = sorted_edges(graph)

    %{
      node: node,
      outgoing: Enum.filter(edges, fn {from, _, _} -> from == id end),
      incoming: Enum.filter(edges, fn {_, to, _} -> to == id end)
    }
  end

  def select_by_tag(graph, tag) do
    graph.nodes |> Map.keys() |> Enum.sort() |> Enum.map(&graph.nodes[&1]) |> Enum.filter(&(tag in &1["tags"]))
  end

  def walk(graph, start, depth) do
    unless Map.has_key?(graph.nodes, start), do: raise(ArgumentError, "unknown node #{start}")
    edges = sorted_edges(graph)
    do_walk(graph, edges, [{start, 0}], MapSet.new([start]), depth, [])
  end

  defp do_walk(_graph, _edges, [], _seen, _depth, out), do: Enum.reverse(out)

  defp do_walk(graph, edges, [{id, d} | queue], seen, depth, out) do
    if d == depth do
      do_walk(graph, edges, queue, seen, depth, out)
    else
      {queue, seen, out} =
        Enum.reduce(edges, {queue, seen, out}, fn {from, to, _}, {queue, seen, out} ->
          next =
            cond do
              from == id -> to
              to == id -> from
              true -> nil
            end

          if next != nil and not MapSet.member?(seen, next) do
            {queue ++ [{next, d + 1}], MapSet.put(seen, next), [graph.nodes[next] | out]}
          else
            {queue, seen, out}
          end
        end)

      do_walk(graph, edges, queue, seen, depth, out)
    end
  end

  def infer_shared_odu(graph) do
    ids = graph.nodes |> Map.keys() |> Enum.sort()

    pairs =
      for {a, i} <- Enum.with_index(ids),
          b <- Enum.drop(ids, i + 1),
          graph.nodes[a]["odu_base"] == graph.nodes[b]["odu_base"],
          do: {a, b, "shared-odu"}

    added = Enum.count(pairs, &(not MapSet.member?(graph.edges, &1)))
    {%{graph | edges: Enum.into(pairs, graph.edges)}, added}
  end

  def merge(graph, other) do
    {nodes, nodes_added} =
      Enum.reduce(Enum.sort(Map.keys(other.nodes)), {graph.nodes, 0}, fn id, {nodes, count} ->
        theirs = other.nodes[id]

        case nodes[id] do
          nil ->
            {Map.put(nodes, id, theirs), count + 1}

          existing ->
            updated =
              existing
              |> Map.put("tags", (existing["tags"] ++ theirs["tags"]) |> Enum.uniq() |> Enum.sort())
              |> Map.put("ts", min(existing["ts"], theirs["ts"]))
              |> Map.put("walrus_blob_id", existing["walrus_blob_id"] || theirs["walrus_blob_id"])

            {Map.put(nodes, id, updated), count}
        end
      end)

    new_edges = MapSet.difference(other.edges, graph.edges)
    {%{nodes: nodes, edges: MapSet.union(graph.edges, other.edges)}, nodes_added, MapSet.size(new_edges)}
  end

  def to_wire(graph) do
    %{
      "nodes" => graph.nodes,
      "edges" =>
        Enum.map(sorted_edges(graph), fn {from, to, relation} ->
          %{"from" => from, "to" => to, "relation" => relation}
        end)
    }
  end

  def from_wire(%{"nodes" => nodes, "edges" => edges}) do
    graph = Enum.reduce(Map.values(nodes), new_graph(), &insert(&2, &1))
    Enum.reduce(edges, graph, fn %{"from" => f, "to" => t, "relation" => r}, g -> link(g, f, t, r) end)
  end

  def gix1_audit(blob) do
    byte_size(blob) >= 34 and binary_part(blob, 0, 4) == "GIX1" and :binary.at(blob, 4) == 1 and
      :binary.at(blob, 5) <= 1
  end

  def merkle_root([]), do: @empty_root

  def merkle_root(entries) do
    leaves =
      entries
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {id, blob_hash} ->
        :crypto.hash(:sha256, Base.decode16!(id, case: :lower) <> blob_hash)
      end)

    reduce_level(leaves) |> Base.encode16(case: :lower)
  end

  defp reduce_level([root]), do: root

  defp reduce_level(level) do
    level
    |> Enum.chunk_every(2)
    |> Enum.map(fn
      [a, b] -> :crypto.hash(:sha256, a <> b)
      [odd] -> odd
    end)
    |> reduce_level()
  end
end

# ---- conformance ------------------------------------------------------------

defmodule GlyphIndex.Conformance do
  def assert!(true, _label), do: :ok
  def assert!(other, label), do: raise("conformance failure: #{label} (got #{inspect(other)})")

  def run do
    dir = Path.dirname(__ENV__.file)
    vectors = GlyphIndex.Json.decode!(File.read!(Path.join(dir, "../vectors.json")))
    fixture_raw = File.read!(Path.join(dir, "../glyph-graph-snapshot.json"))
    fixture = GlyphIndex.Json.decode!(fixture_raw)

    for vec <- vectors["fold"] do
      digest = GlyphIndex.content_hash(vec["text"])
      assert!(GlyphIndex.canonical_id(digest) == vec["canonical_id"], "canonical id #{vec["text"]}")
      <<cp::utf8>> = GlyphIndex.glyph_fold(digest)
      assert!(cp == vec["codepoint"], "fold #{vec["text"]}")
      {base, composed} = GlyphIndex.odu_link(digest)
      assert!(base == vec["odu_base"] and composed == vec["odu_composed"], "odu #{vec["text"]}")
    end

    graph = GlyphIndex.from_wire(fixture)
    assert!(map_size(graph.nodes) == 5, "node count")
    reencoded = GlyphIndex.Json.decode!(GlyphIndex.Json.encode(GlyphIndex.to_wire(graph)))
    assert!(reencoded == fixture, "wire round-trip structural equality")

    start = GlyphIndex.canonical_id(GlyphIndex.content_hash(vectors["walk"]["start_text"]))
    assert!(length(GlyphIndex.walk(graph, start, 1)) == vectors["walk"]["depth_1_count"], "walk depth 1")
    assert!(length(GlyphIndex.walk(graph, start, 2)) == vectors["walk"]["depth_2_count"], "walk depth 2")

    hello = GlyphIndex.canonical_id(GlyphIndex.content_hash("hello"))
    described = GlyphIndex.describe(graph, hello)
    assert!(described.node["walrus_blob_id"] == "walrus://vault/hello-chunk", "hello locator")
    assert!(length(GlyphIndex.select_by_tag(graph, "topic:greeting")) == 1, "tag select")

    mine =
      GlyphIndex.new_graph()
      |> GlyphIndex.insert(GlyphIndex.node_from_chunk("shared chunk", 0))
      |> GlyphIndex.insert(GlyphIndex.node_from_chunk("only mine", 1))

    peer =
      GlyphIndex.node_from_chunk("shared chunk", 99)
      |> Map.put("tags", ["from:peer"])
      |> Map.put("walrus_blob_id", "walrus://peer/blob")

    theirs =
      GlyphIndex.new_graph()
      |> GlyphIndex.insert(peer)
      |> GlyphIndex.insert(GlyphIndex.node_from_chunk("only theirs", 3))

    {merged, nodes_added, edges_added} = GlyphIndex.merge(mine, theirs)
    assert!(nodes_added == 1 and edges_added == 0, "merge stats")
    shared_id = GlyphIndex.canonical_id(GlyphIndex.content_hash("shared chunk"))
    assert!(merged.nodes[shared_id]["ts"] == 0, "earliest ts wins")
    assert!(merged.nodes[shared_id]["walrus_blob_id"] == "walrus://peer/blob", "locator adopted")
    {_, n2, e2} = GlyphIndex.merge(merged, theirs)
    assert!(n2 == 0 and e2 == 0, "merge idempotent")

    blob = "GIX1" <> <<1, 0>> <> :binary.copy(<<0>>, 28)
    assert!(GlyphIndex.gix1_audit(blob), "gix1 audit accepts")
    assert!(not GlyphIndex.gix1_audit("GIX1" <> <<9, 0>> <> :binary.copy(<<0>>, 28)), "bad version rejected")

    assert!(GlyphIndex.merkle_root([]) == vectors["merkle"]["empty_root"], "empty merkle root")

    entries = for id <- Map.keys(fixture["nodes"]), do: {id, :crypto.hash(:sha256, id)}
    assert!(GlyphIndex.merkle_root(entries) == vectors["merkle"]["vector_root"], "merkle vector root")

    IO.puts("glyphindex elixir conformance ok")
  end
end

GlyphIndex.Conformance.run()
