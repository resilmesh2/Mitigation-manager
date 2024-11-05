from __future__ import annotations

from asyncio import gather
from typing import TYPE_CHECKING

from manager import config

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from manager.model import Alert, AttackNode


async def _retrieve_state() -> list[AttackNode]:
    """Return the list of current attack graphs.

    The graphs are represented as a list of the last fulfilled attack
    nodes, each linked to the previous/next nodes to form the attack
    graph.
    """
    return []


async def _retrieve_potential_graphs(technique: str) -> list[AttackNode]:
    """Return a list of potential new attack graphs.

    The return structure is the same as in _retrieve_state(), but
    representing instead the already fulfilled attack nodes of attack
    graphs not considered before.
    """
    return []


async def _update_state(_prev: AttackNode, _next: AttackNode):
    """Update the new latest node in an attack graph."""


async def _update_probabilities(_nodes: list[AttackNode]):
    """Update the probabilities of a list of nodes."""


async def update(alert: Alert) -> tuple[list[AttackNode], list[AttackNode], list[AttackNode]]:
    """Update the local state with an alert.

    Return 3 lists of nodes that should be mitigated:
    - Nodes previously executed in the attack graphs.
    - Nodes immediately related by the alert.
    - Nodes further along in the active attack graphs.
    """
    state = await _retrieve_state()
    tasks: list[Coroutine] = []

    new_state: list[AttackNode] = []
    old_state: list[AttackNode] = []

    past: list[AttackNode] = []
    present: list[AttackNode] = []
    future: list[AttackNode] = []
    # 1: Advance local state if necessary.
    for node in state:
        _next = node.nxt
        if _next is None:
            # Attack finished, but we might want to mitigate the
            # attack tree.  Keep it for now.
            continue
        if alert.rule_id == _next.technique:
            tasks.append(_update_state(node, _next))
            new_state.append(_next)
            old_state.append(node)

    # 2: Update probability percentages.
    all_nodes = {n for node in state for n in node.all()}
    tasks.append(_update_probabilities([n for n in all_nodes if n.update_probability(alert)]))

    # Run all DB updates
    await gather(*tasks)

    # Update local state
    (state.remove(n) for n in old_state)
    state.extend(new_state)

    for node in state:
        # Past: judge based on risk history
        (past.append(n) for n in node.all_before() if n.historically_risky())
        # Present: only if it was related to this alert
        if alert.rule_id == node.technique:
            present.append(node)
        # Future: judge based on how likely it is
        (future.append(n) for n in node.all_after() if n.probability > config.PROBABILITY_TRESHOLD)

    return (past, present, future)
