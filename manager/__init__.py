from asyncio import Condition

from sanic import Blueprint, HTTPResponse, Request, json, empty
import hy

from manager.config import log, version
from manager.model import AttackNode, Condition, DummyCondition, Workflow
from manager.state import StateManager, get_state_manager
from manager.tasks import handle_alert

bp_manager = Blueprint('manager')
bg_manager = Blueprint.group(bp_manager)


@bp_manager.get('/version')
def version_endpoint(*_) -> HTTPResponse:
    """Return a JSON object with version information.

    openapi:
    ---
    responses:
      '200':
        description: Version information
        content:
          application/json:
            schema:
              type: object
              required:
                - version
                - major
                - minor
              properties:
                version:
                  type: string
                  description: The complete Mitigation Manager version string
                  examples:
                     - "v1.0"
                major:
                  type: integer
                  description: The major version
                  format: int32
                  examples:
                    - 1
                minor:
                  type: integer
                  description: The minor version
                  format: int32
                  examples:
                    - 0
    """  # noqa: W505 RUF100
    return json({
        'version': f'v{version}',
        'major': int(version.split('.')[0]),
        'minor': int(version.split('.')[1]),
    })


@bp_manager.post('/alert')
async def post_alert(request: Request) -> HTTPResponse:
    """Process an alert.

    openapi:
    ---
    requestBody:
      description: The alert to process.
      content:
        application/json:
          schema:
            type: object
            description: A Wazuh alert in JSON format.
          example:
            timestamp: '2024-10-22T09:18:46.153+0000'
            rule:
              level: 8
              description: Execute permission added to python script.
              id: '100003'
              mitre:
                id:
                  - T1222.002
                tactic:
                  - Defense Evasion
                technique:
                  - Linux and Mac File and Directory Permissions Modification
              firedtimes: 4
              mail: false
              groups:
                - syscheck
            agent:
              id: '001'
              name: eeb0036baf28
              ip: 192.168.200.200
            manager:
              name: wazuh.manager
            id: '1729588726.22091'
            full_log: |
              File '/tmp/zerologon_tester.py' modified
              Mode: realtime
              Changed attributes: permission
              Permissions changed from 'rw-r--r--' to 'rwxr-xr-x'
            syscheck:
              path: /tmp/zerologon_tester.py
              mode: realtime
              size_after: '3041'
              perm_before: rw-r--r--
              perm_after: rwxr-xr-x
              uid_after: '0'
              gid_after: '0'
              md5_after: 0008432c27c43f9fe58e9bf191f9c6cf
              sha1_after: 84dc56d99268f70619532536f8445f56609547c7
              sha256_after: b8ae48c2e46c28f1004e006348af557c7d912036b9ead88be67bca2bafde01d3
              uname_after: root
              gname_after: root
              mtime_after: '2024-10-22T09:16:02'
              inode_after: 151477998
              changed_attributes:
                - permission
              event: modified
            decoder:
              name: syscheck_integrity_changed
            location: syscheck
    """  # noqa: W505 RUF100
    alert = request.json
    log.info('Received new alert')
    if 'rule' in alert:
        log.debug(alert['rule']['description'])
    await handle_alert(alert)
    return empty(200)


@bp_manager.get('/condition')
async def get_condition(request: Request) -> HTTPResponse:
    """Retrieve a condition.

    openapi:
    ---
    operationId: getCondition
    parameters:
      - name: id
        in: query
        description: The condition's ID.
        required: true
        schema:
          type: integer
          example: 123
    responses:
      '200':
        description: The condition object.
        content:
          application/json:
            schema:
              type: object
              required:
                - identifier
                - params
                - args
                - query
                - checks
              properties:
                  identifier:
                    type: integer
                    description: The identifier.
                    example: 123
                  name:
                    type: string
                    description: The condition name.
                    example: check_equal
                  description:
                    type: string
                    description: A description of the condition.
                    example: Checks that 3+2 is equal to 3*2
                  params:
                    type: object
                    description: The parameters.
                    properties:
                      ^([a-zA-Z_])+$:
                        description: A key-value parameter pair.
                        example: 192.168.1.1
                  args:
                    type: object
                    description: The arguments.
                    properties:
                      ^([a-zA-Z_])+$:
                        type: string
                        description: A key-alert key argument pair.
                        example: alert.device.ip_address
                  check:
                    type: string
                    description: A Hy expression to run to check if the condition has been met.
                    example: "(== (+ 3 2) (* 3 2))"
            example:
              identifier: 123
              name: check_equal
              description: Checks that 3+2 is equal to 3*2
              params:
                port: 22
              args:
                ip_address: alert.device.ip_address
              check: "(== (+ 3 2) (* 3 2))"
      '404':
        description: No condition with such ID was found.
    """  # noqa: W505 RUF100
    condition = await get_state_manager().retrieve_condition(int(request.args.get('id')))
    return json(StateManager.to_dict(condition)) if condition is not None else empty(404)


@bp_manager.post('/condition')
async def post_condition(request: Request) -> HTTPResponse:
    """Store a condition.

    openapi:
    ---
    operationId: postCondition
    requestBody:
      description: The condition to store.
      content:
        application/json:
          schema:
            type: object
            required:
              - identifier
              - params
              - args
              - query
              - checks
            properties:
                identifier:
                  type: integer
                  description: The identifier.
                  example: 123
                name:
                  type: string
                  description: The condition name.
                  example: check_equal
                description:
                  type: string
                  description: A description of the condition.
                  example: Checks that 3+2 is equal to 3*2
                params:
                  type: object
                  description: The parameters.
                  properties:
                    ^([a-zA-Z_])+$:
                      description: A key-value parameter pair.
                      example: 192.168.1.1
                args:
                  type: object
                  description: The arguments.
                  properties:
                    ^([a-zA-Z_])+$:
                      type: string
                      description: A key-alert key argument pair.
                      example: alert.device.ip_address
                check:
                  type: string
                  description: A Hy expression to run to check if the condition has been met.
                  example: "(== (+ 3 2) (* 3 2))"
          example:
            identifier: 123
            name: check_equal
            description: Checks that 3+2 is equal to 3*2
            params:
              port: 22
            args:
              ip_address: alert.device.ip_address
            check: "(== (+ 3 2) (* 3 2))"
    responses:
      '200':
        description: Success
    """  # noqa: W505 RUF100
    condition = request.json
    if condition is None:
        return empty(400)
    log.info('Parsing condition')
    await get_state_manager().store_condition(Condition(condition['identifier'],
                                                        condition['name'],
                                                        condition['description'],
                                                        condition['params'],
                                                        condition['args'],
                                                        condition['check']))

    return empty(200)


@bp_manager.get('/node')
async def get_node(request: Request) -> HTTPResponse:
    """Retrieve a node.

    openapi:
    ---
    operationId: getNode
    parameters:
      - name: id
        in: query
        description: The node's ID.
        required: true
        schema:
          type: integer
          example: 123
    responses:
      '200':
        description: The node object.
        content:
          application/json:
            schema:
              type: object
              required:
                - identifier
                - technique
                - conditions
                - probabilities
              properties:
                identifier:
                  type: integer
                  description: The identifier.
                  example: 123
                technique:
                  type: string
                  description: The associated MITRE ATT&CK technique.
                  example: T0001
                conditions:
                  type: array
                  description: The list of condition IDs.
                  items:
                    type: integer
                    example: 123
                probabilities:
                  type: array
                  description: The history of probabilities.
                  items:
                    type: number
                    format: float
                    example: 0.77
            example:
              identifier: 123
              technique: T0001
              conditions:
                - 456
                - 789
              probabilities:
                - 0.1
                - 0.5
                - 0.44
                - 0.98
      '404':
        description: No node with such ID was found.
    """  # noqa: W505 RUF100
    node = await get_state_manager().retrieve_node(int(request.args.get('id')))
    return json(StateManager.to_dict(node)) if node is not None else empty(404)


@bp_manager.post('/node')
async def post_node(request: Request) -> HTTPResponse:
    """Store a node.

    openapi:
    ---
    operationId: postNode
    requestBody:
      content:
        application/json:
          schema:
            type: object
            required:
              - identifier
              - technique
              - conditions
              - probabilities
            properties:
              identifier:
                type: integer
                description: The identifier.
                example: 123
              technique:
                type: string
                description: The associated MITRE ATT&CK technique.
                example: T0001
              conditions:
                type: array
                description: The list of condition IDs.
                items:
                  type: integer
                  example: 123
              probabilities:
                type: array
                description: The history of probabilities.
                items:
                  type: number
                  format: float
                  example: 0.77
          example:
            identifier: 123
            technique: T0001
            conditions:
              - 456
              - 789
            probabilities:
              - 0.1
              - 0.5
              - 0.44
              - 0.98
    """  # noqa: W505 RUF100
    node = request.json
    log.info('Parsing node')
    await get_state_manager().store_node(AttackNode(node['identifier'],
                                                    node['technique'],
                                                    [DummyCondition(c_id) for c_id in node['conditions']],
                                                    node['probabilities']))
    return empty(200)


@bp_manager.get('/workflow')
async def get_workflow(request: Request) -> HTTPResponse:
    """Retrieve a workflow.

    openapi:
    ---
    operationId: getWorkflow
    parameters:
      - name: id
        in: query
        description: The workflow's ID.
        required: true
        schema:
          type: integer
          example: 123
    responses:
      '200':
        description: The workflow object.
        content:
          application/json:
            schema:
              type: object
              required:
                - identifier
                - name
                - description
                - url
                - effective_attacks
                - cost
                - params
                - args
                - conditions
              properties:
                identifier:
                  type: integer
                  description: The identifier.
                  example: 123
                name:
                  type: string
                  description: The name of the workflow.
                  example: delete_file
                description:
                  type: string
                  description: The workflow description
                  example: Deletes a file.
                url:
                  type: string
                  description: An URL pointing to the workflow.
                  example: https://workflows.example.org/execute/123-456-789
                effective_attacks:
                  type: array
                  description: The list of MITRE ATT&CK identifiers this workflow can mitigate.
                  items:
                    type: string
                    example: T0000
                cost:
                  type: int
                  description: The cost of applying this workflow.
                  example: 10
                params:
                  type: object
                  description: The parameters.
                  properties:
                    ^([a-zA-Z_])+$:
                      description: A key-value parameter pair.
                      example: 192.168.1.1
                args:
                  type: object
                  description: The arguments.
                  properties:
                    ^([a-zA-Z_])+$:
                      type: string
                      description: A key-alert key argument pair.
                      example: alert.device.ip_address
                conditions:
                  type: array
                  description: The list of condition identifiers that must be satisfied before the workflow can run.
                  items:
                    type: integer
                    example: 123
            example:
              identifier: 123
              name: delete_file
              description: Deletes a file.
              url: https://workflows.example.org/execute/123-456-789
              effective_attacks:
                - T0001
                - T0002.1
                - T0002.2
              cost: 10
              params:
                port: 22
              args:
                ip_address: alert.device.ip_address
              conditions:
                - 123
      '404':
        description: No workflow with such ID was found.
    """  # noqa: W505 RUF100
    workflow = await get_state_manager().retrieve_workflow(int(request.args.get('id')))
    return json(StateManager.to_dict(workflow)) if workflow is not None else empty(404)


@bp_manager.post('/workflow')
async def post_workflow(request: Request) -> HTTPResponse:
    """Store a workflow.

    openapi:
    ---
    operationId: postWorkflow
    requestBody:
      content:
        application/json:
          schema:
            type: object
            required:
              - identifier
              - name
              - description
              - url
              - effective_attacks
              - cost
              - params
              - args
              - conditions
            properties:
              identifier:
                type: integer
                description: The identifier.
                example: 123
              name:
                type: string
                description: The name of the workflow.
                example: delete_file
              description:
                type: string
                description: The workflow description
                example: Deletes a file.
              url:
                type: string
                description: An URL pointing to the workflow.
                example: https://workflows.example.org/execute/123-456-789
              effective_attacks:
                type: array
                description: The list of MITRE ATT&CK identifiers this workflow can mitigate.
                items:
                  type: string
                  example: T0000
              cost:
                type: int
                description: The cost of applying this workflow.
                example: 10
              params:
                type: object
                description: The parameters.
                properties:
                  ^([a-zA-Z_])+$:
                    description: A key-value parameter pair.
                    example: 192.168.1.1
              args:
                type: object
                description: The arguments.
                properties:
                  ^([a-zA-Z_])+$:
                    type: string
                    description: A key-alert key argument pair.
                    example: alert.device.ip_address
              conditions:
                type: array
                description: The list of condition identifiers that must be satisfied before the workflow can run.
                items:
                  type: integer
                  example: 123
          example:
            identifier: 123
            name: delete_file
            description: Deletes a file.
            url: https://workflows.example.org/execute/123-456-789
            effective_attacks:
              - T0001
              - T0002.1
              - T0002.2
            cost: 10
            params:
              port: 22
            args:
              ip_address: alert.device.ip_address
    """  # noqa: W505 RUF100
    workflow = request.json
    log.info('Parsing workflow')
    await get_state_manager().store_workflow(Workflow(workflow['identifier'],
                                                      workflow['name'],
                                                      workflow['description'],
                                                      workflow['url'],
                                                      workflow['effective_attacks'],
                                                      workflow['cost'],
                                                      workflow['params'],
                                                      workflow['args'],
                                                      [DummyCondition(i) for i in workflow['conditions']]))
    return empty(200)
