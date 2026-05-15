;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.state.node
  (:require
   [taoensso.telemere :as t]
   [clojure.set :as set]
   [clojure.spec.alpha :as s]
   [mitigation-engine.queries :as q]
   [mitigation-engine.state.common :as c]))

(s/def ::mitre-ids (c/list ::c/mitre-id))
(s/def ::extract map?)
(s/def ::next (c/list ::c/id))
(s/def ::previous (c/list ::c/id))

(s/def ::node (c/dict ::c/id ::c/description ::mitre-ids ::c/conditions ::extract ::next ::previous))

(defn triggered? [node alert ctx]
  ;; An alert triggers a node if all the node's MITRE IDs are also in
  ;; the alert, and if all conditions are true.
  (let [mitre-id-match (set/subset? (set (:mitre-ids node)) (set (:mitre-ids alert)))
        condition-match (update-vals (:conditions node) #(q/run % alert ctx))]
    (t/log! {:level :debug
             :data {:node (:id node)
                    :description (:description node)
                    :mitre-id-match mitre-id-match
                    :condition-match condition-match}
             :msg "Checking if node was triggered"})
    (and mitre-id-match (every? some? (vals condition-match)))))
