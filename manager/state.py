from __future__ import annotations

from asyncio import gather
from json import dumps, loads
from types import MappingProxyType
from typing import TYPE_CHECKING

from manager import config
from manager.model import AttackNode, Condition

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from aiosqlite import Connection, Row

    from manager.model import Alert


HANDLER: DatabaseHandler | None = None


def set_handler(hanlder: DatabaseHandler):
    """Set the global ISIM driver."""
    global HANDLER
    HANDLER = hanlder


def get_handler() -> DatabaseHandler:
    """Get the global ISIM driver."""
    global HANDLER
    if HANDLER is None:
        msg = 'Database handler was never set'
        raise Exception(msg)
    return HANDLER


class DatabaseHandler:

    CHECK_CODES = MappingProxyType({
        1: Condition.check_all_params_in_all_rows,
        2: Condition.check_all_params_in_any_row,
        3: Condition.check_any_param_in_all_rows,
        4: Condition.check_any_param_in_any_row,
    })

    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    async def retrieve_state(self) -> list[AttackNode]:
        """Return the list of current attack graphs.

        The graphs are represented as a list of the last fulfilled
        attack nodes, each linked to the previous/next nodes to form
        the attack graph.
        """
        return []

    async def retrieve_initial_nodes(self) -> list[AttackNode]:
        """Return the list of initial nodes for all attack graphs."""
        ret = []
        query_get_initial_nodes = (
            'SELECT'
            'FROM AttackGraphs'
            'WHERE taking_place = 1'
        )
        async with self.connection.execute(query_get_initial_nodes) as cursor:
            async for row in cursor:
                ret.append(AttackNode(*await self._extract_node_parameters(row)))
        return ret

    async def retrieve_condition(self, identifier: int) -> Condition | None:
        """Return the condition specified by the identifier.

        Returns `None` if the condition can't be found.
        """
        query = (
            'SELECT args, query, check_function'
            'FROM Conditions'
            f'WHERE id = {identifier}'
        )
        async with self.connection.execute(query) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            identifier = row['identifier']
            params = loads(row['params'])
            args = loads(row['args'])
            query = loads(row['query'])
            conditions = [DatabaseHandler.CHECK_CODES[int(c)]
                           for c in str(row['checks']).split(' ')]

            return Condition(identifier, params, args, query, conditions)

    async def _extract_node_parameters(self, row: Row) -> list:
        identifier = int(row['identifier'])
        technique: str = row['technique']
        conditions: list[Condition] = [x for x in [await self.retrieve_condition(int(c))
                                                   for c in row['conditions'].split(' ')]
                                       if x is not None]
        probabilities = [float(p) for p in row['probabilities'].split(' ')]
        return [identifier, technique, conditions, probabilities]

    async def retrieve_full_graph(self, initial_node: AttackNode) -> AttackNode:
        """Return an initial node's complete attack graph."""
        final_node = initial_node
        nxt = initial_node.identifier
        query_initial = (
            'SELECT *'
            'FROM AttackNodes'
            'WHERE id = ?'
        )
        query_recursive = (
            'SELECT *'
            'FROM AttackNodes'
            'WHERE prv = ?'
        )
        q = query_initial
        while True:
            async with self.connection.execute(q, (nxt,)) as cursor:
                if cursor.arraysize > 1:
                    msg = 'Multiple next nodes for attack node'
                    raise ValueError(msg)
                row = await cursor.fetchone()
                if row is None:
                    return final_node.first()
                final_node = final_node.then(*await self._extract_node_parameters(row))
                nxt = row['nxt']
                if nxt is None:
                    return final_node.first()
            q = query_recursive.format(nxt)

    def _retrieve_potential_graphs(self, technique: str) -> list[AttackNode]:
        """Return a list of potential new attack graphs.

        The return structure is the same as in _retrieve_state(), but
        representing instead the already fulfilled attack nodes of
        attack graphs not considered before.
        """
        return []

    async def update_state(self, _prev: AttackNode, _next: AttackNode):
        """Update the new latest node in an attack graph."""

    async def update_probabilities(self, _nodes: list[AttackNode]):
        """Update the probabilities of a list of nodes."""

    async def store_condition(self, condition: Condition) -> None:
        """Store a condition object."""
        query = 'INSERT INTO Conditions VALUES (?, ?, ?, ?, ?)'
        checks = ' '.join(str(i)
                          for i in DatabaseHandler.CHECK_CODES
                          if DatabaseHandler.CHECK_CODES[i] in condition.checks)
        await self.connection.execute(query, (condition.identifier,
                                              dumps(condition.params),
                                              dumps(condition.args),
                                              condition.query,
                                              checks))
        await self.connection.commit()


async def update(alert: Alert) -> tuple[list[AttackNode], list[AttackNode], list[AttackNode]]:
    """Update the local state with an alert.

    Return 3 lists of nodes that should be mitigated:
    - Nodes previously executed in the attack graphs.
    - Nodes immediately related by the alert.
    - Nodes further along in the active attack graphs.
    """
    state = await get_handler().retrieve_state()
    tasks: list[Coroutine] = []

    new_state: list[AttackNode] = []
    old_state: list[AttackNode] = []

    past: list[AttackNode] = []
    present: list[AttackNode] = []
    future: list[AttackNode] = []

    completed: list[AttackNode] = []
    # 1: Advance local state if necessary.
    for node in state:
        _next = node.nxt
        if _next is None:
            # Attack finished, but we might want to mitigate the
            # attack tree.  Keep it for now.
            completed.append(node.first())
            continue
        if alert.rule_id == _next.technique:
            tasks.append(get_handler().update_state(node, _next))
            new_state.append(_next)
            old_state.append(node)

    # 2: Update probability percentages.
    all_nodes = {n for node in state for n in node.all()}
    tasks.append(get_handler().update_probabilities([n for n in all_nodes if n.update_probability(alert)]))

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
