;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.state.attack
  (:require
   [taoensso.telemere :as t]
   [clojure.spec.alpha :as s]
   [mitigation-engine.queries :as q]
   [mitigation-engine.state.alert :as a]
   [mitigation-engine.state.attack-graph :as at]
   [mitigation-engine.state.common :as c]
   [mitigation-engine.state.node :as n]))

(s/def ::attack-graph-id uuid?)
(s/def ::attack-front (c/list ::c/id))
(s/def ::ctx map?)

(s/def ::attack (c/dict ::attack-graph-id ::ctx ::attack-front))

(c/defdb attacks "data/attacks.edn" ::attack)

(defn advanced? [attack alert]
  ;; An alert advances an attack if one of the nodes in the attack
  ;; front is triggered by the alert.
  (let [attack-graph (at/get (:attack-graph-id attack))
        ctx (:ctx attack)]
    (some #(n/triggered? % alert ctx)
          (:attack-front attack))))

(defn new
  "Create a new attack from an alert and the node it triggers."
  [alert node-id attack-graph]
  (let [attack-graph-id (:id attack-graph)
        node (at/get-node attack-graph node-id)
        ctx (update-vals (:extract node) #(q/run % alert nil))]
    (t/log! {:level :debug
             :data {:attack-graph attack-graph-id
                    :initial-node node-id
                    :alert alert
                    :ctx ctx}
             :msg "New attack created"})
    {:attack-graph-id attack-graph-id
     :ctx ctx
     :attack-front (or (at/get-next-nodes attack-graph node-id) (list))}))

(defn update
  "Return the attack, unless it is triggered by the alert in which case
   return the attack modified accordingly."
  [attack alert]
  (let [attack-graph (at/get (:attack-graph-id attack))
        ctx (:ctx attack)
        updates (map (fn [node]
                       (cond
                         (n/triggered? (at/get-node attack-graph node) alert ctx)
                         (do
                           (t/log! {:level :debug
                                    :data {:node node
                                           :alert alert}
                                    :msg "Node triggered"})
                           {:next (at/get-next-nodes attack-graph node)
                            :ctx (update-vals (:extract node) #(q/run % alert ctx))})

                         :else {:next (list node)
                                :ctx nil}))
                     (:attack-front attack))
        new-attack-front (flatten (map :next updates))
        new-ctx (apply merge (keep :ctx updates))]
    (-> attack
        (assoc :attack-front new-attack-front)
        (clojure.core/update :ctx merge new-ctx))))
