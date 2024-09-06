import json
import nats
import sys
import asyncio
import requests
import datetime

#Mitigation Engine. Subscriber de NATS que recibe todo el log de la alerta de Wazuh y 
#la procesa eligiendo un Workflow (y potencialmente un comando OpenC2) para enviar un POST a laAPI de Shuffle para la ejecucion de un workflow

#CRUSOE GraphQL endpoint
CRUSOE_GRAPHQL_URL = 'http://localhost:4001/graphql'
#JSON Content-type Header
CONTENT_TYPE_HEADER = {'Content-Type': 'application/json'}
#Broker PubSub
NATS_BROKER = 'nats://localhost:4222'
#Alerts topic
NATS_SUBJECT = 'alerts'

#Existent workflows pool. Loaded from JSON file
workflows = {}

ncat_fired = False

#Get workflow capabilities from file
def get_workflows():
    global workflows
    with open('workflows.json', 'r') as workflows_file:
        workflows = json.load(workflows_file)

#Mitigation decision process. Rule-based for testing mitigation results. To be evolved with CRUSOE 
def choose_mitigation(alert):
    global ncat_fired
    rule_id = alert['rule']['id']
    if rule_id == "100002": #Caso close conn
        return workflows['workflows'][1]['workflow_webhook']
    elif rule_id == "100003": #Caso delete file
        return workflows['workflows'][0]['workflow_webhook']
    elif rule_id == "100004": #Caso delete file
        return workflows['workflows'][2]['workflow_webhook']

    return None

#Create execution argument for Shuffle workflow execution
def create_execution_arg(workflow, alert):
    arg = {}
    if (workflow == workflows['workflows'][0]['workflow_webhook']) or (workflow == workflows['workflows'][2]['workflow_webhook']):
        #Caso delete_file y ransomware
        arg = {
                "sha1_after": alert['syscheck']['sha1_after'],
                "file_path": alert['syscheck']['path'],
                "actuator_ip": alert['agent']['ip'], 
                "agent_id": alert['agent']['id']
            }

    elif workflow == workflows['workflows'][1]['workflow_webhook']:
        #Caso close conn
        arg = {
                "actuator_ip": alert['agent']['ip'],
                "dst_ip": alert['data']['dst_ip'],
                "dst_port": alert['data']['dst_port'],
                "src_port": alert['data']['src_port'],
                "pid": alert['data']['pid'],
                "agent_id": alert['agent']['id']
            }

    return json.dumps(arg)


#Return MITRE ATTCK IDs from Wazuh threat alert
def get_attack_mitre_techniques_id(alert):
    return alert['rule']['mitre']['id']


#Mapping of Threat and Workflows MITRE ATTCK ID to form an initial set of valid workflows
def get_valid_workflows(attack_mitre_techniques_id):
    valid_workflows = []
    #Recorrer lista de workflows del JSON
    for workflow in workflows['workflows']:
        for addressed_attack in workflow['address_attacks']:
            if addressed_attack['mitre_id'] in attack_mitre_techniques_id:
                valid_workflows.append(workflow)
                break
    
    #Se crea el diccionario (JSON) con los workflows válidos que se devuelve
    #Se mantiene la misma estructura de JSON de capabilities
    valid_workflows_dict = {"workflows": valid_workflows}
    return valid_workflows_dict


#TODO. Will represent CRUSOE info query for supporting decision process
def query_crusoe_information(query):
    request = requests.post(CRUSOE_GRAPHQL_URL, data=json.dumps(query), headers=CONTENT_TYPE_HEADER, verify=False)
    if request.status_code == 200:
        response = json.loads(request.content)
        return response
    else:
        return None


#Main method that groups all algorithm steps. Triggered when alert received in pubsub topic
def select_workflow(alert_log):
    global ncat_fired
    alert_json = json.loads(alert_log)

    #Obtención de las MITRE ID Techniques del ataque
    mitre_ids = get_attack_mitre_techniques_id(alert_json)
    
    #Obtención subconjunto de workflows válidos en base a mapeo MITRE ID 
    valid_workflows = get_valid_workflows(mitre_ids)
    print("VALID WORKFLOWS")
    print(valid_workflows)

    #TODO Query situational awareness information from CRUSOE
    #crusoe_info = query_crusoe_information()
    
    #Decisión de workflow entre el subconjunto de válidos 
    #selected_workflow = choose_mitigation(valid_workflows, alert_json, crusoe_info)
    selected_workflow = choose_mitigation(alert_json)

    #Creación del argumento de ejecución para Shuffle
    execution_arg = create_execution_arg(selected_workflow, alert_json)

    #Ejecución workflow seleccionado en Shuffle
    if alert_json['rule']['id'] != "100002" or not ncat_fired:
        response = requests.post(selected_workflow, data=execution_arg, verify=False)
    if alert_json['rule']['id'] == "100002":
        ncat_fired = True


async def main():
    nc = await nats.connect(servers=[NATS_BROKER])
    sub = await nc.subscribe(NATS_SUBJECT)

    get_workflows()
    while True:
        try:
            async for msg in sub.messages:
                print(f"Received a message on '{msg.subject} {msg.reply}': {msg.data.decode()}")
                alert_log = msg.data.decode()
                inicio = datetime.datetime.now()
                
                select_workflow(alert_log)

                fin = datetime.datetime.now()
                tiempo = str(fin - inicio)
                print("TIEMPO ALGORITMO: ", tiempo)
        except Exception as e:
          pass

if __name__ == '__main__':
    asyncio.run(main())
