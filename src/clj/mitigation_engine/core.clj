;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.core
  (:require
   [taoensso.telemere :as t]
   [clojure.core.async :as async]
   [aero.core :refer [read-config]]
   [mitigation-engine.repr :as repr]
   [mitigation-engine.state.alert :as a]
   [mitigation-engine.state.attack :as at]
   [mitigation-engine.state.attack-graph :as ag]
   [mitigation-engine.state.node :as n]
   [mitigation-engine.state.workflow :as wf]
   [mitigation-engine.state.workflow-instance :as wi]
   [mount.core :as mount])
  (:import
   (es.um.mitigation_engine MitigationEngine MitigationConstraintProvider)
   (es.um.mitigation_engine.model Mitigation)
   (org.optaplanner.core.api.solver SolutionManager)
   (org.optaplanner.core.api.score.buildin.hardsoft HardSoftScore)
   (org.optaplanner.core.api.solver SolverFactory)
   (org.optaplanner.core.config.solver SolverConfig)
   (org.optaplanner.core.config.solver.termination TerminationConfig)
   (org.optaplanner.core.config.score.director ScoreDirectorFactoryConfig)))

(mount/defstate config
                :start (read-config (clojure.java.io/file "config.edn")))

(def impacted-nodes (async/chan 100))

(defn prune-attacks []
  (t/log! {:level :debug
           :msg "Removing attack instances with no attack front"})
  (swap! at/attacks (fn [attacks]
                      (vec (filter #(not (empty? (:attack-front %)))
                                   attacks)))))

(defn update-state [alert]
  (t/log! "Updating existing attacks")
  (t/trace! {:id :existing-attack-update
             :level :debug
             :msg nil}
            (swap! at/attacks (fn [attacks] (vec (map #(at/update % alert) attacks)))))
  (t/log! "Creating new attack instances")
  (t/trace! {:id :new-attack-create
             :level :debug
             :msg nil}
            (run! (fn [attack-graph]
                    (let [initial-node (ag/get-initial-node attack-graph)]
                      (when (n/triggered? initial-node alert nil)
                        (t/log! {:level :debug
                                 :data {:node initial-node
                                        :alert alert}
                                 :msg "Initial node triggered"})
                        (swap! at/attacks conj (at/new alert (:id initial-node) attack-graph)))))
                  @ag/attack-graphs)))

(defn solve [alert parameters]
  (let [from-java (fn [solution]
                    (map #(assoc {}
                                 :alert (a/from-java (.getAlert %))
                                 :workflow (wi/from-java (.getWorkflow %)))
                         (filter #(and (.getAlert %)
                                       (.getWorkflow %))
                                 (.getMitigations solution))))
        alerts (seq (list alert))
        workflows (seq @wf/workflows)
        mitigation-slots 10
        seconds-limit 1

        _ (t/log! {:level :debug
                   :data {:alerts alerts
                          :workflows  workflows}
                   :msg "Solver inputs"})

        java-alerts (map a/to-java alerts)
        java-workflows (t/trace! {:id :workflow-instantiation
                                  :level :debug
                                  :msg nil}
                                 (flatten (map #(wf/generate-instances % alert) workflows)))
        java-mitigations (take mitigation-slots (repeatedly #(Mitigation.)))

        _ (t/log! {:data {:alerts (count java-alerts)
                          :workflows  (count java-workflows)
                          :mitigation-slots (count java-mitigations)
                          :seconds-limit seconds-limit}
                   :msg "Running solver"})

        problem (doto (MitigationEngine.)
                  (.setAlerts java-alerts)
                  (.setWorkflows java-workflows)
                  (.setMitigations java-mitigations))
        termination-config (doto (TerminationConfig.)
                             (.setSecondsSpentLimit seconds-limit))
        solver-config (doto (SolverConfig.)
                        (.withSolutionClass MitigationEngine)
                        (.withConstraintProviderClass MitigationConstraintProvider)
                        (.withTerminationConfig termination-config)
                        (.withEntityClasses
                         (into-array Class [Mitigation])))
        factory (SolverFactory/create solver-config)
        solver (.buildSolver factory)
        solution (t/trace! {:id :solver-execution
                            :level :debug
                            :msg nil}
                           (.solve solver problem))
        score (-> solution (.getScore))]
    (t/log! {:data {:solution solution
                    :score (str score)}
             :msg "Solution found"})

    (cond
      (.isFeasible score)
      (doseq [w (from-java solution)]
        (wi/run (:workflow w)))
      :else
      (let [summary (-> (SolutionManager/create factory)
                        (.explain solution)
                        (.getSummary))]
        (t/log! {:data {:summary summary}
                 :msg "Solution explanation"})))))

(defn handle-alert [alert]
  (t/log! {:data {:alert alert}
           :msg "Handling alert"})
  (t/trace! {:level :debug
             :id :alert-handling
             :msg nil}
            (do
              (update-state alert)
              (solve alert nil)
              (prune-attacks))))
