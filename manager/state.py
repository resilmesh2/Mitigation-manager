from __future__ import annotations
from asyncio import gather
from typing import Coroutine

from aiosqlite import Cursor

from manager.model.state_manager import AttackNode

async def _retrieve_state() -> list[AttackNode]:
    """Return the list of current attack graphs.

    The graphs are represented as a list of the last fulfilled attack
    nodes, each linked to the previous/next nodes to form the attack
    graph.
    """


async def _retrieve_potential_graphs(technique: str) -> list[AttackNode]:
    """Return a list of potential new attack graphs.

    The return structure is the same as in _retrieve_state(), but
    representing instead the already fulfilled attack nodes of attack
    graphs not considered before.
    """


async def _update_state(prev: AttackNode, next: AttackNode):
    """Update the new latest node in an attack graph."""


async def _update_probabilities(nodes: list[AttackNode]):
    """Update the probabilities of a list of nodes."""



# TLDR: check MITRE IDs, see which attacks have taken place, see
# which preconditions have taken place, update DB based on it.
async def update(alert: dict):
    state = await _retrieve_state()

    # 1: Advance local state if necessary.  Run everything in parallel
    # for efficiency.
    tasks: list[Coroutine] = []
    for node in state:
        next = node.next_attack()
        if next is None:
            # ????
            break
        if alert['rule']['id'] == next.technique:
            tasks.append(_update_state(node, next))

    # 2: Update probability percentages.
    all_nodes = set([n for node in state for n in node.all_attack_nodes()])
    tasks.append(_update_probabilities([n for n in all_nodes if n.update_probability(alert)]))

    # Run all updates
    await gather(*tasks)





async def mitigations_needed() -> bool:
    # TLDR: check if based on the current state the probability of
    # going to the next state is high, combine it with the cost of
    # incurring the next state, combine it with the risk score(?), and
    # evaluate against the configured risk threshold.
    return True
