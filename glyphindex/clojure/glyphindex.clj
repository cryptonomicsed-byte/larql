;; Clojure port of the GlyphIndex sovereign-memory contract
;; (spec: OSOVM/GLYPHINDEX_SPEC.md; canonical reference:
;; Vantage/backend/glyph_index.py).
;;
;; Portable, keyless surface: GIX-FOLD-v1 folding, Odù linkage, the
;; content-addressed GlyphGraph (immutable maps + LQL-style verbs
;; DESCRIBE / SELECT / WALK / INFER plus A2A merge), the cross-language
;; JSON wire format, GIX1 structural audit, and the Sui-anchorable
;; Merkle root.
;;
;; Run the conformance suite (needs clojure + org.clojure/data.json jars):
;;   java -cp "/opt/clj/*" clojure.main glyphindex.clj

(ns glyphindex
  (:require [clojure.data.json :as json])
  (:import [java.security MessageDigest]
           [java.nio.charset StandardCharsets]))

(def fold-ranges [[0x0020 (+ (- 0xD7FF 0x0020) 1)]
                  [0xE000 (+ (- 0xFDCF 0xE000) 1)]
                  [0xFDF0 (+ (- 0xFFFD 0xFDF0) 1)]])
(def fold-total (reduce + (map second fold-ranges)))
(def empty-root "58cc47f0d238cea8bb764f7a927a54b398c8baf5de0a2332c03008038c3fd9a8")

(defn sha256 ^bytes [^bytes data]
  (.digest (MessageDigest/getInstance "SHA-256") data))

(defn content-hash ^bytes [^String text]
  (sha256 (.getBytes text StandardCharsets/UTF_8)))

(defn bytes->hex [^bytes bs]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn hex->bytes ^bytes [^String hex]
  (byte-array (map #(unchecked-byte (Integer/parseInt (subs hex % (+ % 2)) 16))
                   (range 0 (count hex) 2))))

(defn canonical-id [^bytes digest] (bytes->hex digest))

(defn glyph-fold [^bytes digest]
  (let [idx (reduce (fn [rem b] (mod (+ (* rem 256) (bit-and b 0xff)) fold-total)) 0 digest)]
    (loop [idx idx, ranges fold-ranges]
      (let [[start count*] (first ranges)]
        (if (< idx count*)
          (String. (Character/toChars (+ start idx)))
          (recur (- idx count*) (rest ranges)))))))

(defn odu-link [^bytes digest]
  (let [b0 (bit-and (aget digest 0) 0xff)
        b1 (bit-and (aget digest 1) 0xff)]
    [b0 (bit-or (bit-shift-left b0 8) b1)]))

(defn node-from-chunk [chunk ts]
  (let [digest (content-hash chunk)
        [base composed] (odu-link digest)]
    {"canonical_id" (canonical-id digest)
     "glyph" (glyph-fold digest)
     "odu_base" base
     "odu_composed" composed
     "ts" ts
     "tags" []
     "walrus_blob_id" nil}))

(def empty-graph {:nodes {} :edges #{}})

(defn insert [graph node]
  (let [id (get node "canonical_id")]
    (when-not (and (string? id) (re-matches #"[0-9a-f]{64}" id))
      (throw (ex-info "canonical id must be 64 lowercase hex chars" {:id id})))
    (assoc-in graph [:nodes id] (update node "tags" #(vec (sort (distinct %)))))))

(defn link [graph from to relation]
  (doseq [id [from to]]
    (when-not (contains? (:nodes graph) id)
      (throw (ex-info (str "unknown node " id) {}))))
  (update graph :edges conj [from to relation]))

(defn- sorted-edges [graph] (sort (vec (:edges graph))))

(defn describe [graph id]
  (let [node (or (get-in graph [:nodes id])
                 (throw (ex-info (str "unknown node " id) {})))
        edges (sorted-edges graph)]
    {:node node
     :outgoing (filterv #(= (first %) id) edges)
     :incoming (filterv #(= (second %) id) edges)}))

(defn select-by-tag [graph tag]
  (->> (sort (keys (:nodes graph)))
       (map (:nodes graph))
       (filterv #(some #{tag} (get % "tags")))))

(defn walk [graph start depth]
  (when-not (contains? (:nodes graph) start)
    (throw (ex-info (str "unknown node " start) {})))
  (let [edges (sorted-edges graph)]
    (loop [queue (conj clojure.lang.PersistentQueue/EMPTY [start 0])
           seen #{start}
           out []]
      (if (empty? queue)
        out
        (let [[id d] (peek queue)
              queue (pop queue)]
          (if (= d depth)
            (recur queue seen out)
            (let [[queue seen out]
                  (reduce (fn [[queue seen out] [from to _]]
                            (let [next (cond (= from id) to (= to id) from :else nil)]
                              (if (and next (not (seen next)))
                                [(conj queue [next (inc d)]) (conj seen next) (conj out (get-in graph [:nodes next]))]
                                [queue seen out])))
                          [queue seen out]
                          edges)]
              (recur queue seen out))))))))

(defn infer-shared-odu [graph]
  (let [ids (vec (sort (keys (:nodes graph))))
        pairs (for [i (range (count ids))
                    j (range (inc i) (count ids))
                    :when (= (get-in graph [:nodes (ids i) "odu_base"])
                             (get-in graph [:nodes (ids j) "odu_base"]))]
                [(ids i) (ids j) "shared-odu"])
        added (count (remove (:edges graph) pairs))]
    [(update graph :edges into pairs) added]))

(defn merge-graphs [graph other]
  (let [[nodes nodes-added]
        (reduce (fn [[nodes added] id]
                  (let [theirs (get-in other [:nodes id])]
                    (if-let [existing (nodes id)]
                      [(assoc nodes id
                              (-> existing
                                  (assoc "tags" (vec (sort (distinct (concat (existing "tags") (theirs "tags"))))))
                                  (assoc "ts" (min (existing "ts") (theirs "ts")))
                                  (assoc "walrus_blob_id" (or (existing "walrus_blob_id") (theirs "walrus_blob_id")))))
                       added]
                      [(assoc nodes id theirs) (inc added)])))
                [(:nodes graph) 0]
                (sort (keys (:nodes other))))
        new-edges (remove (:edges graph) (:edges other))]
    [{:nodes nodes :edges (into (:edges graph) (:edges other))}
     nodes-added
     (count new-edges)]))

(defn to-wire [graph]
  {"nodes" (:nodes graph)
   "edges" (mapv (fn [[from to relation]] {"from" from "to" to "relation" relation})
                 (sorted-edges graph))})

(defn from-wire [wire]
  (let [graph (reduce insert empty-graph (vals (get wire "nodes")))]
    (reduce (fn [g e] (link g (get e "from") (get e "to") (get e "relation")))
            graph
            (get wire "edges"))))

(defn gix1-audit [^bytes blob]
  (and (>= (alength blob) 34)
       (= "GIX1" (String. blob 0 4 StandardCharsets/US_ASCII))
       (= 1 (bit-and (aget blob 4) 0xff))
       (<= (bit-and (aget blob 5) 0xff) 1)))

(defn merkle-root [entries]
  (if (empty? entries)
    empty-root
    (let [leaves (->> entries
                      (sort-by first)
                      (mapv (fn [[id ^bytes blob-hash]]
                              (sha256 (byte-array (concat (hex->bytes id) blob-hash))))))]
      (loop [level leaves]
        (if (= 1 (count level))
          (bytes->hex (first level))
          (recur (into (mapv (fn [[a b]] (sha256 (byte-array (concat a b))))
                             (partition 2 level))
                       (when (odd? (count level)) [(last level)]))))))))

;; ---- conformance ------------------------------------------------------------

(defn check [cond label]
  (when-not cond (throw (ex-info (str "conformance failure: " label) {}))))

(let [dir (or (some-> (System/getProperty "glyphindex.dir")) ".")
      vectors (json/read-str (slurp (str dir "/../vectors.json")))
      fixture (json/read-str (slurp (str dir "/../glyph-graph-snapshot.json")))]

  (doseq [vec* (get vectors "fold")]
    (let [digest (content-hash (get vec* "text"))
          [base composed] (odu-link digest)]
      (check (= (canonical-id digest) (get vec* "canonical_id")) (str "canonical id " (get vec* "text")))
      (check (= (.codePointAt ^String (glyph-fold digest) 0) (get vec* "codepoint")) (str "fold " (get vec* "text")))
      (check (and (= base (get vec* "odu_base")) (= composed (get vec* "odu_composed"))) (str "odu " (get vec* "text")))))

  (let [graph (from-wire fixture)]
    (check (= 5 (count (:nodes graph))) "node count")
    (check (= (json/read-str (json/write-str (to-wire graph))) fixture) "wire round-trip structural equality")

    (let [start (canonical-id (content-hash (get-in vectors ["walk" "start_text"])))]
      (check (= (count (walk graph start 1)) (get-in vectors ["walk" "depth_1_count"])) "walk depth 1")
      (check (= (count (walk graph start 2)) (get-in vectors ["walk" "depth_2_count"])) "walk depth 2"))

    (let [hello (canonical-id (content-hash "hello"))
          described (describe graph hello)]
      (check (= "walrus://vault/hello-chunk" (get-in described [:node "walrus_blob_id"])) "hello locator")
      (check (= 1 (count (select-by-tag graph "topic:greeting"))) "tag select"))

    (let [entries (mapv (fn [id] [id (sha256 (.getBytes ^String id StandardCharsets/US_ASCII))])
                        (keys (get fixture "nodes")))]
      (check (= (merkle-root []) (get-in vectors ["merkle" "empty_root"])) "empty merkle root")
      (check (= (merkle-root entries) (get-in vectors ["merkle" "vector_root"])) "merkle vector root")))

  (let [mine (-> empty-graph
                 (insert (node-from-chunk "shared chunk" 0))
                 (insert (node-from-chunk "only mine" 1)))
        peer (-> (node-from-chunk "shared chunk" 99)
                 (assoc "tags" ["from:peer"])
                 (assoc "walrus_blob_id" "walrus://peer/blob"))
        theirs (-> empty-graph (insert peer) (insert (node-from-chunk "only theirs" 3)))
        [merged nodes-added edges-added] (merge-graphs mine theirs)
        shared-id (canonical-id (content-hash "shared chunk"))]
    (check (and (= 1 nodes-added) (= 0 edges-added)) "merge stats")
    (check (= 0 (get-in merged [:nodes shared-id "ts"])) "earliest ts wins")
    (check (= "walrus://peer/blob" (get-in merged [:nodes shared-id "walrus_blob_id"])) "locator adopted")
    (let [[_ n2 e2] (merge-graphs merged theirs)]
      (check (and (= 0 n2) (= 0 e2)) "merge idempotent")))

  (let [blob (byte-array (concat (.getBytes "GIX1" StandardCharsets/US_ASCII) [1 0] (repeat 28 0)))
        bad (byte-array (concat (.getBytes "GIX1" StandardCharsets/US_ASCII) [9 0] (repeat 28 0)))]
    (check (gix1-audit blob) "gix1 audit accepts")
    (check (not (gix1-audit bad)) "bad version rejected"))

  (println "glyphindex clojure conformance ok"))
