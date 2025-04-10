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


-- Example attack graph 1: Someone connects, adds +x to a script, then gets ransomware somewhere and runs it.
INSERT OR IGNORE INTO AttackGraphs
(identifier, attack_name, initial_node)
VALUES (100,
       'Spooky ncat connection leads to ransomware',
       100);

INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description)
VALUES (100,
       NULL,
       101,
       'T1041',
       'Someone randomly connects using ncat');

INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description, conditions)
VALUES (101,
       100,
       102,
       'T1222.002',
       'Someone decides to adds +x to a Python script',
       '100 101');

INSERT OR IGNORE INTO AttackNodes
(identifier, prv, nxt, technique, description, conditions)
VALUES (102,
       101,
       NULL,
       'T1204.002',
       'Someone downloads a known Python ransomware script using the previous Python script, and the rest is history',
       '100 102');

-- Some conditions are defined in order to filter out unwanted alerts.
INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (100,
       'File is a Python script',
       'The file triggering the alert ends in ".py"',
       '{}',
       '{"path": "file_path"}',
       '(and (is-not None parameters) ((. (get parameters "path") endswith) ".py"))');

INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (101,
       'File is executable',
       'The file triggering the alert has executable permissions',
       '{}',
       '{"permissions": "file_permissions"}',
       '(and (is-not None parameters) (in "x" (get parameters "permissions")))');

INSERT OR IGNORE INTO Conditions
(identifier, condition_name, condition_description, params, args, checkstring)
VALUES (102,
       'File is ransomware',
       'The file triggering the alert is ransomware.',
       '{}',
       '{"path": "file_path"}',
       '(and (is-not None parameters) (in "zerologon" (get parameters "path")))');

-- Example workflows: close ncat connection, delete file, handle ransomware.
INSERT OR IGNORE INTO Workflows
(identifier, workflow_name, workflow_desc, url, effective_attacks, cost, args)
VALUES (100,
       'delete_file',
       'Deletes a file',
       'http://shuffle-frontend/api/v1/hooks/webhook_6b219a4d-9723-4607-b6c6-6e56f790650c',
       'T1222.002',
       1,
       '{"sha1_after": "file_hash","file_path":"file_path","actuator_ip":"agent_ip","agent_id":"agent_id"}');

INSERT OR IGNORE INTO Workflows
(identifier, workflow_name, workflow_desc, url, effective_attacks, cost, args)
VALUES (101,
       'close_conn',
       'Closes a remote connection.',
       'http://shuffle-frontend/api/v1/hooks/webhook_aa2e31ea-dd3e-4471-ad4e-3f032bdb381d',
       'T1041 T1219',
       10,
       '{"actuator_ip":"agent_ip","src_port":"connection_src_port","dst_port":"connection_dst_port","dst_ip":"connection_dst_ip","pid":"connection_pid","agent_id":"agent_id"}');


INSERT OR IGNORE INTO Workflows
(identifier, workflow_name, workflow_desc, url, effective_attacks, cost, args)
VALUES (103,
       'handle_ransomware',
       'Mitigate a ransomware attack',
       'http://shuffle-frontend/api/v1/hooks/webhook_1d5366eb-8006-45a3-8fff-e764c283b811',
       'T1204.002',
       5,
       '{"sha1_after": "file_hash","file_path":"file_path","actuator_ip":"agent_ip","agent_id":"agent_id"}');
