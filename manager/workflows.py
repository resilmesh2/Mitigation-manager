from manager.model import AttackNode, Workflow
from manager.state import get_handler


async def locate(node: AttackNode) -> Workflow | None:
    """Retrieve the optimal workflow to mitigate an attack."""
    valid_workflows = await get_handler().retrieve_applicable_workflows(node.technique)

    if len(valid_workflows) == 0:
        return None
    # Current technique: get the lowest cost workflow
    return sorted(valid_workflows, key=lambda w: w.cost)[0]


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
