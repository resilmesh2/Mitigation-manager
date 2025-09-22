# Copyright (C) 2025 Ekam Puri Nieto (UMU), Antonio Skarmeta Gomez
# (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the project
# root for details.

from manager.config import log
from manager.model import AttackNode, Workflow
from manager.state import get_state_manager


async def locate(node: AttackNode) -> Workflow | None:
    """Retrieve the optimal workflow to mitigate an attack."""
    valid_workflows = await get_state_manager().retrieve_applicable_workflows(node.technique)

    log.debug('Applicable workflows for attack %s: %s', node.technique, [w.name for w in valid_workflows])

    if len(valid_workflows) == 0:
        return None
    # Current technique: get the lowest cost workflow
    return sorted(valid_workflows, key=lambda w: w.cost)[0]
