import asyncio
import datetime
import json
import signal

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

# Get workflow capabilities from file
def get_workflows():
    global workflows
    with open(WORKFLOWS_FILE, 'r') as workflows_file:
        workflows = json.load(workflows_file)

# Mitigation decision process. Rule-based for testing mitigation
# results.  To be evolved with CRUSOE
def choose_mitigation(alert: dict) -> str | None:
    match alert['rule']['id']:
        case '100002':  # close-conn
            return workflows['workflows'][1]['workflow_webhook']
        case '100003':  # delete-file
            return workflows['workflows'][0]['workflow_webhook']
        case '100004':  # delete-file
            return workflows['workflows'][2]['workflow_webhook']
    # No match
    return None

# Create execution argument for Shuffle workflow execution
def create_execution_arg(workflow: str, alert: dict) -> dict:
    w0 = workflows['workflows'][0]['workflow_webhook']
    w1 = workflows['workflows'][1]['workflow_webhook']
    w2 = workflows['workflows'][2]['workflow_webhook']
    if workflow == w0 or workflow == w2:
        # Caso delete_file y ransomware
        return {
            'sha1_after': alert['syscheck']['sha1_after'],
            'file_path': alert['syscheck']['path'],
            'actuator_ip': alert['agent']['ip'],
            'agent_id': alert['agent']['id']
        }
    if workflow == w1:
        # Caso close conn
        return {
            'actuator_ip': alert['agent']['ip'],
            'dst_ip': alert['data']['dst_ip'],
            'dst_port': alert['data']['dst_port'],
            'src_port': alert['data']['src_port'],
            'pid': alert['data']['pid'],
            'agent_id': alert['agent']['id']
        }

    raise ValueError('Unknown workflow', workflow)

# Return MITRE ATTCK IDs from Wazuh threat alert
def get_attack_mitre_techniques_id(alert: dict) -> list[str]:
    return alert['rule']['mitre']['id']


# Mapping of Threat and Workflows MITRE ATTCK ID to form an initial
# set of valid workflows
def get_valid_workflows(attack_mitre_techniques_id: list[str]):
    valid_workflows = []
    # Recorrer lista de workflows del JSON
    for workflow in workflows['workflows']:
        for addressed_attack in workflow['address_attacks']:
            if addressed_attack['mitre_id'] in attack_mitre_techniques_id:
                valid_workflows.append(workflow)
                break

    # Se crea el diccionario (JSON) con los workflows válidos que se
    # devuelve.  Se mantiene la misma estructura de JSON de
    # capabilities
    valid_workflows_dict = {'workflows': valid_workflows}
    return valid_workflows_dict


# TODO. Will represent CRUSOE info query for supporting decision
# process
def query_crusoe_information(query: dict):
    request = requests.post(CRUSOE_GRAPHQL_URL, json=query, headers=CONTENT_TYPE_HEADER, verify=False)
    if request.status_code == 200:
        response = json.loads(request.content)
        return response
    else:
        return None


# Main method that groups all algorithm steps.  Triggered when alert
# received in pubsub topic
def select_workflow(alert_log):
    alert_json = json.loads(alert_log)

    # Obtención de las MITRE ID Techniques del ataque
    mitre_ids = get_attack_mitre_techniques_id(alert_json)

    # Obtención subconjunto de workflows válidos en base a mapeo MITRE ID
    valid_workflows = get_valid_workflows(mitre_ids)
    print(f'Found a total of {len(valid_workflows)} valid workflows')

    # TODO Query situational awareness information from CRUSOE
    # crusoe_info = query_crusoe_information()

    # Decisión de workflow entre el subconjunto de válidos
    # selected_workflow = choose_mitigation(valid_workflows, alert_json, crusoe_info)
    selected_workflow = choose_mitigation(alert_json)

    # Edge case: no workflow
    if selected_workflow is None:
        raise ValueError('No workflow selected')

    # Creación del argumento de ejecución para Shuffle
    execution_arg = create_execution_arg(selected_workflow, alert_json)

    # Ejecución workflow seleccionado en Shuffle
    requests.post(selected_workflow, json=execution_arg, verify=False)


async def main(handler):

    async def message_handler(msg: Msg):
        try:
            print(f'Received a message on "{msg.subject} {msg.reply}"')
            print(f'Message contents: {msg.data.decode()}')
            alert_log = msg.data.decode()

            inicio = datetime.datetime.now()
            select_workflow(alert_log)
            fin = datetime.datetime.now()

            print(f'Mitigation applied in {fin - inicio} seconds')
        except Exception as e:
            print(f'Caught exception ({type(e)}): "{e}"')

    print('Obtaining workflows...')
    get_workflows()
    print('Connecting to NATS...')
    nc = await nats.connect(servers=[NATS_BROKER])
    print('Subscribing to alerts...')
    sub = await nc.subscribe(NATS_SUBJECT, cb=message_handler)
    print('Ready to mitigate')
    while True:
        await asyncio.sleep(5)
        if handler.terminated:
            break
    print('Terminating gracefully')


class Terminator:
    terminated = False

    def __init__(self) -> None:
        signal.signal(signal.SIGINT, self._terminate)
        signal.signal(signal.SIGTERM, self._terminate)

    def _terminate(self, *_):
        self.terminated = True


if __name__ == '__main__':
    asyncio.run(main(Terminator()))
