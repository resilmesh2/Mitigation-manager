;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.state.attack-graph
  (:require
   [clojure.spec.alpha :as s]
   [mitigation-engine.state.common :as c]
   [mitigation-engine.state.node :as n]))

(s/def ::nodes (c/list ::n/node))
(s/def ::initial-node ::c/id)

(s/def ::attack-graph (c/dict ::c/id ::c/description ::nodes ::initial-node))

(c/defdb attack-graphs "data/attack-graphs.edn" ::attack-graph)

(defn clean
  "Purge all ongoing attacks."
  [attack-graph]
  (assoc attack-graph :attacks []))

(defn get [id]
  (first (filter #(= (:id %) id) @attack-graphs)))

(defn nodes [attack-graph]
  (:nodes attack-graph))

(defn get-node [attack-graph node-id]
  (first (filter #(= (:id %) node-id) (nodes attack-graph))))

(defn get-next-nodes [attack-graph node-id]
  (:next (get-node attack-graph node-id)))

(defn get-previous-nodes [attack-graph node-id]
  (:previous (get-node attack-graph node-id)))

(defn get-initial-node [attack-graph]
  (get-node attack-graph (:initial-node attack-graph)))
