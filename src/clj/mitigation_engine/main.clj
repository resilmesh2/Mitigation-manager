;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.main
  (:gen-class)
  (:require
   [taoensso.telemere :as t]
   [mount.core :as mount]
   [mitigation-engine.core :as core]

   ;; Import all namespaces with side effects.  Explicitly import
   ;; namespaces even if they're implicitly loaded from a different
   ;; one.

   ;; defdb
   [mitigation-engine.state.alert]
   [mitigation-engine.state.attack-graph]
   [mitigation-engine.state.workflow]
   [mitigation-engine.state.attack]
   ;; defstate
   [mitigation-engine.core]
   [mitigation-engine.csap]
   [mitigation-engine.nats]
   [mitigation-engine.server]))

(defn- start []
  (t/log! "Starting server")
  (binding [*err* (java.io.StringWriter.)]
    (t/trace! {:level :debug
               :id :state-start
               :msg nil}
              (mount/start))))

(defn- stop []
  (t/log! "Stopping server")
  (binding [*err* (java.io.StringWriter.)]
    (t/trace! {:level :debug
               :id :state-stop
               :msg nil}
              (mount/stop))))

(defn -main  [& args]
  (.. Runtime getRuntime (addShutdownHook (Thread. stop)))
  (try
    (start)
    (t/set-min-level! (:minimum-logging-level core/config))
    (t/set-ns-filter! {:disallow (:disallowed-logging-namespaces core/config)})
    @(promise)
    (catch InterruptedException e
      (t/log! {:level :warn
               :msg "SIGINT received"})
      (stop))
    (catch RuntimeException e
      (t/log! {:level :error
               :data {:exception e}
               :msg "RuntimeException caught"})
      (stop))))
