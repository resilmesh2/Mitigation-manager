;; Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
;; Gomez (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the
;; project root for details.

(ns mitigation-engine.csap
  (:require
   [neo4j-clj.core :as neo4j]
   [mount.core :as mount]
   [mitigation-engine.core :as core]))

(defn- start-client []
  (let [host (:csap-host core/config)
        port (:csap-port core/config)
        uri (java.net.URI. (str "bolt://" host \: port))
        username (:csap-username core/config)
        password (:csap-password core/config)]
    (neo4j/connect uri username password)))

(defn- stop-client [client]
  (neo4j/disconnect client))

(mount/defstate client
          :start (start-client)
          :stop (stop-client client))

;; Execute query
(defn check [query & [params]]
  (with-open [session (neo4j/get-session client)]
    (neo4j/with-transaction client tx
      (doall (neo4j/execute tx query (or params {}))))))
