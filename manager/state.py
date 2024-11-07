from __future__ import annotations

import asyncio
from asyncio import gather
from json import dumps, loads
from types import MappingProxyType
from typing import TYPE_CHECKING, LiteralString, TypeVar

from manager import config
from manager.model import AttackNode, Condition

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from aiosqlite import Connection, Row

    from manager.model import Alert


HANDLER: DatabaseHandler | None = None


def set_handler(handler: DatabaseHandler):
    """Set the global ISIM driver."""
    global HANDLER
    HANDLER = handler


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

    T = TypeVar('T')

    @staticmethod
    def _mkstr(_list: list[T], f: Callable[[T], str] = str) -> str:
        return ' '.join(f(e) for e in _list)

    @staticmethod
    def _mklist(_list: str, f: Callable[[str], T]) -> list[T]:
        return [f(e) for e in _list.split(' ')]

    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    async def _extract_condition_parameters(self, row: Row) -> tuple[int, dict, dict, LiteralString, list[Callable]]:
        return (row['identifier'],
                loads(row['params']),
                loads(row['args']),
                row['query'],
                self._mklist(row['checks'], lambda s: DatabaseHandler.CHECK_CODES[int(s)]))

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
            return Condition(*await self._extract_condition_parameters(row))

    async def store_condition(self, condition: Condition) -> None:
        """Store a condition."""
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

    async def _extract_node_parameters(self, row: Row) -> tuple[int, str, list[Condition], list[float]]:
        identifier = int(row['identifier'])
        technique: str = row['technique']
        conditions = [await self.retrieve_condition(c) for c in self._mklist(row['condition'], int)]
        probabilities = [float(p) for p in row['probabilities'].split(' ')]
        return (identifier, technique, [e for e in conditions if e is not None], probabilities)

    async def retrieve_node(self, identifier: int) -> AttackNode | None:
        """Return the attack specified by the identifier.

        Returns `None` if the attack node can't be found.  This
        method does not return the full attack graph - the node's
        `prv` and `nxt` values will be `None`.
        """
        query = (
            'SELECT technique, conditions, probabilities, description'
            'FROM AttackNodes'
            f'WHERE id = {identifier}'
        )
        async with self.connection.execute(query) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return AttackNode(*await self._extract_node_parameters(row))

    async def store_node(self, node: AttackNode) -> None:
        """Store a node.

        The node's conditions don't have to be fully defined, they
        just need to contain the proper identifier.
        """
        query = 'INSERT INTO AttackNodes VALUES (?, ?, ?, ?, ?, ?, ?)'
        parameters = (node.identifier,
                      node.prv.identifier if node.prv is not None else None,
                      node.nxt.identifier if node.nxt is not None else None,
                      node.technique,
                      self._mkstr(node.conditions, lambda c: str(c.identifier)),
                      self._mkstr([node.probability, *node.probability_history]),
                      'description')
        await self.connection.execute(query, parameters)
        await self.connection.commit()

    async def retrieve_state(self) -> list[AttackNode]:
        """Return the list of current attack graphs.

        The graphs are represented as a list of the last fulfilled
        attack nodes, each linked to the previous/next nodes to form
        the attack graph.
        """
        return [await self._retrieve_full_graph(n) for n in await self._retrieve_initial_nodes()]

    async def _retrieve_initial_nodes(self) -> list[AttackNode]:
        """Return the list of initial nodes for active attack graphs.

        This method does not return full attack graphs - the nodes'
        `prv` and `nxt` values will be `None`.
        """
        ret = []
        query_get_initial_nodes = (
            'SELECT id, technique, conditions, probabilities, description'
            'FROM AttackGraphs'
            'WHERE taking_place = TRUE'
        )
        async with self.connection.execute(query_get_initial_nodes) as cursor:
            async for row in cursor:
                ret.append(AttackNode(*await self._extract_node_parameters(row)))
        return ret

    async def _retrieve_full_graph(self, initial_node: AttackNode) -> AttackNode:
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

    async def retrieve_potential_graphs(self, technique: str) -> list[AttackNode]:
        """Return a list of potential new attack graphs."""
        ret = []
        query = (
            'SELECT an.id AS identifier'
            'FROM AttackNodes AS an'
            'INNER JOIN AttackGraphs AS ag ON an.id = ag.starting_node'
            'WHERE an.technique = ?'
        )
        parameters = (technique,)
        async with self.connection.execute(query, parameters) as cursor:
            async for row in cursor:
                node = await self.retrieve_node(row['identifier'])
                if node is None:
                    continue
                ret.append(node)
        return ret

    async def mark_complete(self, node: AttackNode):
        """Mark the attack node as completed.

        If there is a next node, mark it as the new attack front.
        """
        tasks = []
        query = (
            'UPDATE AttackNodes'
            'SET ongoing = 0'
            'WHERE id = ?'
        )
        parameters = (node.identifier,)
        tasks.append(self.connection.execute(query, parameters))

        nxt = node.nxt
        if nxt is not None:
            query = (
                'UPDATE AttackNodes'
                'SET ongoing = 1'
                'WHERE id = ?'
            )
            parameters = (nxt.identifier,)
            tasks.append(self.connection.execute(query, parameters))

        tasks.append(self.connection.commit())
        await asyncio.gather(*tasks)

    async def update_probability(self, node: AttackNode, probability: float):
        """Update the probability of a node."""
        query = (
            'UPDATE Probabilities'
            'SET probabilities = ?'
            'WHERE id = ?'
        )
        parameters = (self._mkstr([probability, node.probability, *node.probability_history]), node.identifier)
        await self.connection.execute(query, parameters)


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
            tasks.append(get_handler().mark_complete(node))
            new_state.append(_next)
            old_state.append(node)

    # 2: Update probability percentages.
    tasks.extend([get_handler().update_probability(n, p)
                  for n, p in [(n, await n.update_probability(alert))
                               for node in state for n in node.all()]
                  if p >= 0])

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
