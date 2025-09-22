CREATE TABLE IF NOT EXISTS Conditions (
    identifier INTEGER PRIMARY KEY,
    condition_name TEXT,
    condition_description TEXT,
    params TEXT NOT NULL DEFAULT '{}',
    args TEXT NOT NULL DEFAULT '{}',
    checkstring TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS AttackNodes (
    identifier INTEGER PRIMARY KEY,
    prv INT,
    nxt INT,
    technique TEXT NOT NULL,
    conditions TEXT DEFAULT NULL,
    probabilities TEXT DEFAULT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS AttackGraphs (
    identifier INTEGER PRIMARY KEY,
    attack_name TEXT,
    initial_node INT
);

CREATE TABLE IF NOT EXISTS Attacks (
    identifier INTEGER PRIMARY KEY,
    attack_graph INT,
    attack_front INT,
    context TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS Workflows (
    identifier INTEGER PRIMARY KEY,
    workflow_name TEXT,
    workflow_desc TEXT NULL,
    url TEXT,
    effective_attacks TEXT,
    cost INT,
    params TEXT NOT NULL DEFAULT '{}',
    args TEXT NOT NULL DEFAULT '{}',
    conditions TEXT DEFAULT NULL
);


-- * Convention for manually assigned identifiers
--
-- Attack graphs, workflows: IDs are split in blocks of 10.
--
-- 0X - Testing
-- 1X - Pilot 1
-- 2X - Pilot 2
--
-- Attack nodes, conditions: IDs are split in blocks of 100.
--
-- 0XX - Testing
-- 1XX - Pilot 1
-- 2XX - Pilot 2
--
-- Conditions: TBD
--
-- Workflows: TBD
--
--
-- * Other conventions
--
-- When creating attack graphs from existing Attack Flow graphs, try
-- to keep a 1:1 mapping.  If the only relevant step is step 7, use
-- the 7th available identifier for the flow.  This will help in case
-- earlier steps that previously couldn't be detected/mitigated
-- suddenly become relevant.


-- * Test attack graphs

-- Example attack graph 1: Someone connects, adds +x to a script, then gets ransomware somewhere and runs it.
INSERT OR IGNORE INTO AttackGraphs
(identifier, attack_name, initial_node)
VALUES (1,
       'Test - ncat to ransomware',
       1);

INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description)
VALUES (1,
        NULL,
        2,
       'T1041',
       'Remote connection using ncat');

INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description, conditions)
VALUES (2,
        1,
        3,
       'T1222.002',
       'Python script execution permission change',
       '1 2');

INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description, conditions)
VALUES (3,
        2,
        NULL,
       'T1204.002',
       'Ransomware script download',
       '1 3');

-- * Pilot 1 attack graphs

-- CARM: DoS attack

INSERT OR IGNORE INTO AttackGraphs
(identifier, attack_name, initial_node)
VALUES (10,
       'Pilot 1 - CARM - DoS',
        105);


INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description, conditions)
VALUES (105,
        NULL,
        NULL,
       'T1499',
       'DoS attack using Slowrolis',
       '101 102');

-- CARM: Bruteforce attack

INSERT OR IGNORE INTO AttackGraphs
(identifier, attack_name, initial_node)
VALUES (11,
       'Pilot 1 - CARM - Bruteforce',
        115);


INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description, conditions)
VALUES (115,
        NULL,
        NULL,
       'T1110',
       'Bruteforce attack using Hydra',
       '101 103');

-- * Conditions

-- File is Python script
INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (1,
       'File is a Python script',
       'The file triggering the alert ends in ".py"',
       '{}',
       '{"path": "file_path"}',
       '(and (is-not None parameters) ((. (get parameters "path") endswith) ".py"))');

-- File is executable
INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (2,
       'File is executable',
       'The file triggering the alert has executable permissions',
       '{}',
       '{"permissions": "file_permissions"}',
       '(and (is-not None parameters) (in "x" (get parameters "permissions")))');

-- File is ransomware (starts with "zerologon")
INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (3,
       'File is ransomware',
       'The file triggering the alert is ransomware.',
       '{}',
       '{"path": "file_path"}',
       '(and (is-not None parameters) (in "zerologon" (get parameters "path")))');

-- Firewall exists in affected network
INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (101,
       'Firewall available',
       'An actionable firewall is available in the network.',
       '{"firewall_network": "10.185.2.96/28"}',
       '{"victim_ip": "flow_destination_ip"}',
       '(and (is-not None parameters)(in "victim_ip" parameters)(is-not None (get parameters "victim_ip"))(do (import ipaddress)(in (ipaddress.ip_address (get parameters "victim_ip"))(ipaddress.ip_network (get parameters "firewall_network")))))');

-- Flow Processor alert refers to DoS attack
INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (102,
       'DoS alert type',
       'The Flow Processor alert corresponds to a DoS attack.',
       '{"valid_identifiers": ["Slowloris"]}',
       '{"attack_type": "flow_attack_type"}',
       '(and (is-not None parameters)(in "attack_type" parameters)(in (get parameters "attack_type") (get parameters "valid_identifiers")))');

-- Flow Processor alert refers to bruteforce attack
INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (103,
       'Bruteforce alert type',
       'The Flow Processor alert corresponds to a bruteforce attack.',
       '{"valid_identifiers": ["Bruteforce"]}',
       '{"attack_type": "flow_attack_type"}',
       '(and (is-not None parameters)(in "attack_type" parameters)(in (get parameters "attack_type") (get parameters "valid_identifiers")))');


-- # (try (setv results (await (isim_manager.run_query ((. (get parameters "query") format) (get parameters "victim_ip")) {}))) (return (> (length results) 0)) (except [e Exception] (log.debug "An unknown exception ocurred: %s" e) (return False)))


-- * Workflows

-- File deletion
INSERT OR IGNORE INTO Workflows
(identifier, workflow_name, workflow_desc, url, effective_attacks, cost, args)
VALUES (1,
       'delete_file',
       'Deletes a file',
       'http://shuffle-frontend/api/v1/hooks/webhook_6b219a4d-9723-4607-b6c6-6e56f790650c',
       'T1222.002',
       1,
       '{"sha1_after": "file_hash","file_path":"file_path","actuator_ip":"agent_ip","agent_id":"agent_id"}');

-- Remote connection termination
INSERT OR IGNORE INTO Workflows
(identifier, workflow_name, workflow_desc, url, effective_attacks, cost, args)
VALUES (2,
       'close_conn',
       'Closes a remote connection.',
       'http://shuffle-frontend/api/v1/hooks/webhook_aa2e31ea-dd3e-4471-ad4e-3f032bdb381d',
       'T1041 T1219',
       10,
       '{"actuator_ip":"agent_ip","src_port":"connection_src_port","dst_port":"connection_dst_port","dst_ip":"connection_dst_ip","pid":"connection_pid","agent_id":"agent_id"}');

-- Ransomware mitigation
INSERT OR IGNORE INTO Workflows
(identifier, workflow_name, workflow_desc, url, effective_attacks, cost, args)
VALUES (3,
       'handle_ransomware',
       'Mitigate a ransomware attack',
       'http://shuffle-frontend/api/v1/hooks/webhook_1d5366eb-8006-45a3-8fff-e764c283b811',
       'T1204.002',
       5,
       '{"sha1_after": "file_hash","file_path":"file_path","actuator_ip":"agent_ip","agent_id":"agent_id"}');

-- Packet filtering
INSERT OR IGNORE INTO Workflows
(identifier, workflow_name, workflow_desc, url, effective_attacks, cost, params, args)
VALUES (11,
       'filter_packets',
       'Drop network packets from IP address',
       'http://shuffle-frontend/api/v1/hooks/webhook_fcf6d1e8-c7e6-46ae-aaf8-75e9fc47b0f0',
       'T1499 T1110',
       5,
       '{"firewall_ip": "10.185.2.98"}',
       '{"attacker_ip": "flow_source_ip"}');
