from manager.model import AttackNode, Workflow
from manager.state import get_handler


async def locate(node: AttackNode) -> Workflow | None:
    """Retrieve the optimal workflow to mitigate an attack."""
    valid_workflows = await get_handler().retrieve_applicable_workflows(node.technique)

    if len(valid_workflows) == 0:
        return None
    # Current technique: get the lowest cost workflow
    return sorted(valid_workflows, key=lambda w: w.cost)[0]
