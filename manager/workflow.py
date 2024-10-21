from aiohttp import ClientSession

from manager.config import log


async def execute(workflow: dict) -> dict:
    # TLDR: call whatever endpoint to run the workflow with the
    # specified parameters, then return a dict containing whether the
    # workflow was successful or not.
    workflow_url = f'http://shuffle-frontend/api/v1/hooks/webhook_{workflow["webhook"]}'
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
