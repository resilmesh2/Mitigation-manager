import asyncio
import datetime
import json
import signal
from typing import Callable

import nats
from nats.aio.msg import Msg
import requests

# Mitigation Engine. Subscriber de NATS que recibe todo el log de la
# alerta de Wazuh y la procesa eligiendo un Workflow (y potencialmente
# un comando OpenC2) para enviar un POST a laAPI de Shuffle para la
# ejecucion de un workflow

# CRUSOE GraphQL endpoint
CRUSOE_GRAPHQL_URL = 'http://localhost:4001/graphql'
# JSON Content-type Header
CONTENT_TYPE_HEADER = {'Content-Type': 'application/json'}
# Broker PubSub
NATS_BROKER = 'nats://nats:4222'
# Alerts topic
NATS_SUBJECT = 'alerts'
# Workflows file
WORKFLOWS_FILE = 'workflows.json'

# Existent workflows pool.  Loaded from JSON file
workflows = {}


class Lock:
    free = False

    def __init__(self) -> None:
        signal.signal(signal.SIGINT, self._terminate)
        signal.signal(signal.SIGTERM, self._terminate)

    def _terminate(self, *_):
        self.free = True


# Get workflow capabilities from file
def get_workflows():
    global workflows
    with open(WORKFLOWS_FILE, 'r') as workflows_file:
        workflows = json.load(workflows_file)


# Mitigation decision process. Rule-based for testing mitigation
# results.  To be evolved with CRUSOE
def choose_mitigation(alert: dict) -> dict:
    match alert['rule']['id']:
        case '100002':  # close-conn
            return workflows['workflows'][1]
        case '100003':  # delete-file
            return workflows['workflows'][0]
        case '100004':  # delete-file
            return workflows['workflows'][2]
    # No match
    msg = f'No workflow available for rule ID {alert["rule"]["id"]}'
    raise ValueError(msg)


# Create execution argument for Shuffle workflow execution
def create_execution_arg(workflow: dict, alert: dict) -> dict:
    w0 = workflows['workflows'][0]['workflow_name']
    w1 = workflows['workflows'][1]['workflow_name']
    w2 = workflows['workflows'][2]['workflow_name']

    if workflow['workflow_name'] in [w0, w2]:
        # Caso delete_file y ransomware
        return {
            'sha1_after': alert['syscheck']['sha1_after'],
            'file_path': alert['syscheck']['path'],
            'actuator_ip': alert['agent']['ip'],
            'agent_id': alert['agent']['id'],
        }
    if workflow['workflow_name'] in [w1]:
        # Edge case: no data field
        if 'data' not in alert:
            name = workflows['workflows'][1]['workflow_name']
            msg = f'Workflow "{name}" requires "data" field inside the alert'
            raise ValueError(msg)
        return {
            'actuator_ip': alert['agent']['ip'],
            'dst_ip': alert['data']['dst_ip'],
            'dst_port': alert['data']['dst_port'],
            'src_port': alert['data']['src_port'],
            'pid': alert['data']['pid'],
            'agent_id': alert['agent']['id'],
        }

    msg = f'Unknown workflow "{workflow["workflow_name"]}"'
    raise ValueError(msg)


# Return MITRE ATTCK IDs from Wazuh threat alert
def get_attack_mitre_techniques_id(alert: dict) -> list[str]:
    return alert['rule']['mitre']['id']


# Mapping of Threat and Workflows MITRE ATTCK ID to form an initial
# set of valid workflows
def get_valid_workflows(attack_mitre_techniques_id: list[str]) -> list[dict]:
    ret = []
    for workflow in workflows['workflows']:
        for addressed_attack in workflow['address_attacks']:
            if addressed_attack['mitre_id'] in attack_mitre_techniques_id:
                ret.append(workflow)
                break
    return ret


# TODO. Will represent CRUSOE info query for supporting decision
# process
def query_crusoe_information(query: dict):
    request = requests.post(
        CRUSOE_GRAPHQL_URL, json=query, headers=CONTENT_TYPE_HEADER, verify=False
    )
    if request.status_code == 200:
        response = json.loads(request.content)
        return response
    else:
        return None


# Main method that groups all algorithm steps.  Triggered when alert
# received in pubsub topic
def select_workflow(alert: dict):
    # Obtención de las MITRE ID Techniques del ataque
    mitre_ids = get_attack_mitre_techniques_id(alert)

    # Obtención subconjunto de workflows válidos en base a mapeo MITRE ID
    names = [w['workflow_name'] for w in get_valid_workflows(mitre_ids)]
    print(f'Found the following valid workflows: {names}')

    # TODO Query situational awareness information from CRUSOE
    # crusoe_info = query_crusoe_information()

    # Decisión de workflow entre el subconjunto de válidos
    # selected_workflow = choose_mitigation(valid_workflows, alert, crusoe_info)
    selected_workflow = choose_mitigation(alert)

    # Creación del argumento de ejecución para Shuffle
    execution_arg = create_execution_arg(selected_workflow, alert)

    # Ejecución workflow seleccionado en Shuffle
    requests.post(
        selected_workflow['workflow_webhook'], json=execution_arg, verify=False
    )


async def main(free: Callable[[], bool]):
    async def handler(msg: Msg):
        try:
            alert = json.loads(msg.data.decode())
            print(f'Received new alert: {alert["rule"]["description"]}')
            inicio = datetime.datetime.now()
            select_workflow(alert)
            fin = datetime.datetime.now()

            print(f'Mitigation applied in {fin - inicio}')
        except ValueError as e:
            print(f'Error while mitigating alert: {e}')
        except Exception as e:
            print(f'Caught unknown exception ({type(e)}): {e}')

    print('Obtaining workflows...')
    get_workflows()
    print('Connecting to NATS...')
    sub = await nats.connect(servers=[NATS_BROKER])
    print('Subscribing to alerts...')
    sub = await sub.subscribe(NATS_SUBJECT, cb=handler)
    print('Ready to mitigate')
    while not free():
        await asyncio.sleep(3)
    print('Terminating gracefully')
    await sub.unsubscribe()


if __name__ == '__main__':
    lock = Lock()

    def free():
        return lock.free

    asyncio.run(main(free))
