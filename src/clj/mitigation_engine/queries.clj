;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.queries)

(declare ^:dynamic *alert*)
(declare ^:dynamic *ctx*)

(defn run [query alert ctx]
  (let [type (first query)
        v (second query)]
    (case type
      :static v
      :alert (-> alert (get v) (or nil))
      :ctx (-> ctx (get v) (or nil))
      :eval (binding [*alert* alert
                      *ctx* ctx
                      *ns* (find-ns 'mitigation-engine.queries)]
              (eval v)))))
