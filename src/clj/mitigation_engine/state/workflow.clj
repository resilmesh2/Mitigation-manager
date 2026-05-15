;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.state.workflow
  (:require
   [taoensso.telemere :as t]
   [clojure.spec.alpha :as s]
   [mitigation-engine.queries :as q]
   [mitigation-engine.state.common :as c]
   [mitigation-engine.state.attack :as a])
  (:import
   (java.net URI)
   (es.um.mitigation_engine.model Workflow WorkflowInstance MitreTechnique Parameter ParameterType)))

(s/def ::cost double?)
(s/def ::url #(try (URI. %) true (catch Exception _ false)))
(s/def ::mitre-ids (c/list ::c/mitre-id))

(s/def ::workflow (c/dict ::c/description ::url ::mitre-ids ::cost ::c/parameters ::c/conditions))

(c/defdb workflows "data/workflows.edn" ::workflow)

(s/def ::workflow-instance (c/dict ::c/mitre-id ::cost ::cost-factor))

(defn to-java [workflow]
  (when (s/valid? ::workflow workflow)
    (let [technique (set (map #(MitreTechnique. %)
                              (:mitre-ids workflow)))
          parameters (set (map #(Parameter. (first %)
                                            (ParameterType/ANY))
                               (:parameters workflow)))
          cost (:cost workflow)]
      (Workflow. technique parameters cost (:url workflow) (:description workflow)))))

(defn from-java [workflow]
  {:description (.getDescription workflow)
   :url (.getUrl workflow)
   :mitre-ids (set (map #(.getId %) (.getTargets workflow)))
   :cost (.getCost workflow)
   :params (into {} (for [param (.getParameters workflow)]
                      [(.getName param) nil]))})

(defn generate-instances [workflow alert]
  (keep (fn [attack]
          (let [ctx (:ctx attack)
                conditions (update-vals (:conditions workflow) #(q/run % alert ctx))
                parameters (update-vals (:parameters workflow) #(q/run % alert ctx))]
            (t/log! {:level :debug
                     :data {:workflow-signature workflow
                            :associated-attack attack
                            :conditions conditions
                            :parameters parameters}
                     :msg "Attempting to generate workflow"})
            (when (every? some? (vals conditions))
              (t/log! {:level :debug
                       :data {:workflow-signature workflow
                              :associated-attack attack
                              :parameters parameters}
                       :msg "Workflow instance generated"})
              (WorkflowInstance. (to-java workflow) parameters 1.0))))
        @a/attacks))
