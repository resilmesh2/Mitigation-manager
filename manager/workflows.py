from aiohttp import ClientSession

from manager.config import getenv, log


def validate(workflow: dict) -> bool:
    fields = ['webhook', 'name', 'performs', 'mitigates', 'prevents', 'set_cost', 'variable_cost']
    if any(f not in workflow for f in fields):
        return False

    return True

async def execute(workflow: dict) -> dict:
    # TLDR: call whatever endpoint to run the workflow with the
    # specified parameters, then return a dict containing whether the
    # workflow was successful or not.
    workflow_url = f'http://{getenv("SHUFFLE_HOST")}:{getenv("SHUFFLE_PORT")}/api/v1/hooks/webhook_{workflow["webhook"]}'
    async with ClientSession() as client:
        async with client.get(workflow_url) as response:
            if response.status == 200:
                return {
                    'success': True
                }
            else:
                log.debug('Workflow request failed with status code %s', response.status)
                log.debug(await response.text())
                return {
                    'success': False,
                    'status': response.status,
                    'body': await response.text()
                }

def successful(results: dict) -> bool:
    # TLDR: check whether the results say that the workflow executed
    # correctly or not.
    return results['success']


def error(results: dict) -> str:
    # TLDR: return a formatted string with debug info on why the
    # workflow failed.
    return f'HTTP status code {results["status"]}'

# Scope: the level at which the workflow operates.  The higher the
# scope is, the more effective and disruptive the mitigation usually
# is.
#
# - Resource level :: Impacts only files/folders.  Some of these might
# - be mission-critical for certain processes, but in general the
# - mitigations will have low impact.
#
# - Process level :: Impacts process execution.
#
# - Device level :: Impacts the device where the alert was received.
# - Mitigations belonging to this level can include changes to the
# - network, so long as they don't impact the execution of other
# - devices (f.e. by restricting specific outbound trafic).
#
# - Network level :: Impacts the subnet/s the device belongs to.
#
# - Global level :: Impacts all devices managed by the MIT-MAN.
async def get() -> list[dict]:
    return [
        {
            'name': 'delete_file',
            'webhook': '6b219a4d-9723-4607-b6c6-6e56f790650c',
            'performs': ['D3-FEV'],
            'mitigates': ['T1204.002'],
            'prevents': ['T1222.002'],
            'set_cost': 1,
            'variable_cost': {
                '': 0,
            },
        },
        {
            'name': 'close_conn',
            'type': ['D3-PT', 'D3-ST'],
            'webhook': 'aa2e31ea-dd3e-4471-ad4e-3f032bdb381d',
            'attacks': ['T1041', 'T1219'],
            'set_cost': 10,
        },
        {
            'name': 'handle_ransomware',
            'webhook': '1d5366eb-8006-45a3-8fff-e764c283b811',
            'attacks': ['T1204.002'],
            'set_cost': 5,
        },
        {
            'name': 'shutdown_interface',
            'webhook': None,
            'attacks': ['T1041, T1219'],
            'set_cost': 5,
        },
    ]
