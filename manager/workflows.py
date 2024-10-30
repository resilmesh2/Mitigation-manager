from aiohttp import ClientSession

from manager.config import getenv, log
from manager.model import AttackNode


def validate(workflow: dict) -> bool:
    fields = ['webhook', 'name', 'performs', 'mitigates', 'set_cost', 'variable_cost']
    return not any(f not in workflow for f in fields)


async def execute(workflow: dict) -> dict:
    # TLDR: call whatever endpoint to run the workflow with the
    # specified parameters, then return a dict containing whether the
    # workflow was successful or not.
    workflow_url = f'http://{getenv("SHUFFLE_HOST")}:{getenv("SHUFFLE_PORT")}/api/v1/hooks/webhook_{workflow["webhook"]}'
    async with ClientSession() as client, client.get(workflow_url) as response:
        if response.status == 200:
            return {
                'success': True,
            }
        log.debug('Workflow request failed with status code %s', response.status)
        log.debug(await response.text())
        return {
            'success': False,
            'status': response.status,
            'body': await response.text(),
        }


def successful(results: dict) -> bool:
    # TLDR: check whether the results say that the workflow executed
    # correctly or not.
    return results['success']


def error(results: dict) -> str:
    # TLDR: return a formatted string with debug info on why the
    # workflow failed.
    return f'HTTP status code {results["status"]}'


async def locate(node: AttackNode) -> dict | None:
    """Retrieve the optimal workflow to mitigate an attack."""
    return {}


async def get() -> list[dict]:
    return [
        {
            'name': 'delete_file',
            'webhook': '6b219a4d-9723-4607-b6c6-6e56f790650c',
            'performs': ['D3-FEV'],
            'mitigates': ['T1204.002'],
            'set_cost': 1,
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
