from __future__ import annotations

import asyncio
from asyncio import gather
from json import dumps, loads
from types import MappingProxyType
from typing import TYPE_CHECKING, LiteralString, TypeVar

from manager import config
from manager.model import AttackNode, Condition, MitreTechnique, Workflow, WorkflowUrl
from manager.config import log

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
    def _mkstr(_list: list[T], f: Callable[[T], str] = str) -> str | None:
        return ' '.join(f(e) for e in _list) if len(_list) > 0 else None

    @staticmethod
    def _mklist(_list: str | None, f: Callable[[str], T]) -> list[T]:
        return [f(e) for e in _list.split(' ')] if _list is not None else []

    @staticmethod
    def to_dict(item) -> dict | None:
        if type(item) is Condition:
            return {
                'identifier': item.identifier,
                'params': item.params,
                'args': item.args,
                'query': item.query,
                'checks': DatabaseHandler._mkchecklist(item.checks),
            }
        if type(item) is AttackNode:
            return {
                'identifier': item.identifier,
                'prv': item.prv.identifier if item.prv is not None else None,
                'nxt': item.nxt.identifier if item.nxt is not None else None,
                'technique': item.technique,
                'conditions': [c.identifier for c in item.conditions],
                'probabilities': item.probability_history,
                'description': None,
            }
        if type(item) is Workflow:
            return {
                'identifier': item.identifier,
                'name': item.name,
                'description': item.description,
                'url': item.url,
                'effective_attacks': item.effective_attacks,
                'cost': item.cost,
                'params': item.params,
                'args': item.args,
            }
        return None

    @staticmethod
    def _mkchecklist(_list: list[Callable]) -> list[int]:
        return [s for s in DatabaseHandler.CHECK_CODES if DatabaseHandler.CHECK_CODES[s] in _list]

    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    async def _extract_condition_parameters(self, row: Row) -> tuple[int, dict, dict, LiteralString, list[Callable]]:
        config.log.debug(row)
        config.log.debug(row.keys)
        return (row['identifier'],
                loads(row['params']),
                loads(row['args']),
                row['query'],
                self._mklist(row['checks'], lambda s: DatabaseHandler.CHECK_CODES[int(s)]))

    async def retrieve_condition(self, identifier: int) -> Condition | None:
        """Return the condition specified by the identifier.

        Returns `None` if the condition can't be found.
        """
        query = """
        SELECT identifier, params, args, query, checks
        FROM Conditions
        WHERE identifier = ?
        """
        parameters = (identifier,)
        async with self.connection.execute(query, parameters) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return Condition(*await self._extract_condition_parameters(row))

    async def store_condition(self, condition: Condition) -> None:
        """Store a condition."""
        query = 'INSERT INTO Conditions VALUES (?, ?, ?, ?, ?)'
        config.log.info(type(condition.checks))
        checks = self._mkstr([i
                              for i in DatabaseHandler.CHECK_CODES
                              if DatabaseHandler.CHECK_CODES[i] in condition.checks])
        await self.connection.execute(query, (condition.identifier,
                                              dumps(condition.params),
                                              dumps(condition.args),
                                              condition.query,
                                              checks))
        await self.connection.commit()

    async def _extract_node_parameters(self, row: Row) -> tuple[int, str, list[Condition], list[float]]:
        identifier = int(row['identifier'])
        technique: str = row['technique']
        conditions = [await self.retrieve_condition(c) for c in self._mklist(row['conditions'], int)]
        probabilities = self._mklist(row['probabilities'], float)
        return (identifier, technique, [e for e in conditions if e is not None], probabilities)

    async def retrieve_node(self, identifier: int) -> AttackNode | None:
        """Return the attack specified by the identifier.

        Returns `None` if the attack node can't be found.  This
        method does not return the full attack graph - the node's
        `prv` and `nxt` values will be `None`.
        """
        query = """
        SELECT identifier, technique, conditions, probabilities, description
        FROM AttackNodes
        WHERE identifier = ?
        """
        parameters = (identifier,)
        log.debug('Retrieving node ID %s', identifier)
        async with self.connection.execute(query, parameters) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return AttackNode(*await self._extract_node_parameters(row))

    async def store_node(self, node: AttackNode) -> None:
        """Store a node.

        The node's conditions don't have to be fully defined, they
        just need to contain the proper identifier.
        """
        query = """
        INSERT INTO AttackNodes
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        log.debug('Storing node ID %s', node.identifier)
        parameters = (node.identifier,
                      node.prv.identifier if node.prv is not None else None,
                      node.nxt.identifier if node.nxt is not None else None,
                      node.technique,
                      self._mkstr(node.conditions, lambda c: str(c.identifier)),
                      self._mkstr([node.probability, *node.probability_history]),
                      'description')
        await self.connection.execute(query, parameters)
        await self.connection.commit()

    async def _extract_workflow_parameters(self, row: Row) -> tuple[int,
                                                                    LiteralString,
                                                                    str,
                                                                    WorkflowUrl,
                                                                    list[MitreTechnique],
                                                                    int,
                                                                    dict,
                                                                    dict]:
        identifier = int(row['identifier'])
        name = row['workflow_name']
        desc = row['workflow_desc']
        url = row['url']
        effective_attacks = self._mklist(row['effective_attacks'], str)
        cost = int(row['cost'])
        params = loads(row['params'])
        args = loads(row['args'])
        return (identifier, name, desc, url, effective_attacks, cost, params, args)

    async def retrieve_workflow(self, identifier: int) -> Workflow | None:
        """Return the workflow specified by the identifier.

        Returns `None` if the workflow can't be found.
        """
        query = """
        SELECT identifier, workflow_name, workflow_desc, url, effective_attacks, cost, params, args
        FROM Workflows
        WHERE identifier = ?
        """
        parameters = (identifier,)
        log.debug('Retrieving workflow ID %s', identifier)
        async with self.connection.execute(query, parameters) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return Workflow(*await self._extract_workflow_parameters(row))

    async def store_workflow(self, workflow: Workflow) -> None:
        """Store a workflow.

        The workflow's conditions don't have to be fully defined, they
        just need to contain the proper identifier.
        """
        query = """
        INSERT INTO Workflows
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        parameters = (workflow.identifier,
                      workflow.name,
                      workflow.description,
                      workflow.url,
                      self._mkstr(workflow.effective_attacks),
                      workflow.cost,
                      dumps(workflow.params),
                      dumps(workflow.args))
        log.debug('Storing workflow ID %s', workflow.identifier)
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
        query = """
        SELECT an.identifier, an.technique, an.conditions, an.probabilities, an.description
        FROM AttackGraphs AS ag
        INNER JOIN AttackNodes AS an ON an.identifier = ag.initial_node
        WHERE ag.ongoing = TRUE
        """
        async with self.connection.execute(query) as cursor:
            async for row in cursor:
                ret.append(AttackNode(*await self._extract_node_parameters(row)))
        return ret

    async def _retrieve_full_graph(self, initial_node: AttackNode) -> AttackNode:
        """Return an initial node's complete attack graph.

        The node returned is the ongoing node.  If none of the
        subsequent nodes are the ongoing node, returns `initial_node`.
        """
        final_node = initial_node
        attack_front = initial_node
        query_for_first_nxt = """
        SELECT nxt
        FROM AttackNodes
        WHERE identifier = ?
        """
        async with self.connection.execute(query_for_first_nxt, (initial_node.identifier,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return initial_node
        nxt = row['nxt']
        query = """
        SELECT *
        FROM AttackNodes
        WHERE identifier = ?
        """
        while True:
            async with self.connection.execute(query, (nxt,)) as cursor:
                if cursor.arraysize > 1:
                    msg = 'Multiple next nodes for attack node'
                    raise ValueError(msg)
                row = await cursor.fetchone()
                if row is None:
                    return final_node.first()
                row_params = await self._extract_node_parameters(row)
                final_node = final_node.then(*row_params)
                ongoing = row['ongoing'] == 1
                if ongoing:
                    if attack_front is not initial_node:  # Means attack_front was already set
                        msg = 'Multiple ongoing nodes'
                        raise ValueError(msg)
                    attack_front = final_node
                nxt = row['nxt']
                if nxt is None:
                    return attack_front

    async def retrieve_potential_graphs(self, attacks: list[MitreTechnique]) -> list[AttackNode]:
        """Return a list of potential new attack graphs."""
        ret = []
        query = """
        SELECT an.identifier AS identifier
        FROM AttackNodes AS an
        INNER JOIN AttackGraphs AS ag ON an.identifier = ag.initial_node
        WHERE ag.ongoing = FALSE
        """
        query += f'\nAND ({" OR ".join("an.technique LIKE ?" for _ in attacks)})'
        parameters = (*[f'%{attack}%' for attack in attacks],)
        async with self.connection.execute(query, parameters) as cursor:
            async for row in cursor:
                node = await self.retrieve_node(row['identifier'])
                if node is None:
                    continue
                ret.append(node)
        return ret

    async def mark_complete(self, node: AttackNode):
        """Mark the attack node as completed.

        If there is a next node, mark it as the new attack front.  If
        there is no next node, mark the attack graph as no longer
        taking place.
        """
        tasks = []
        query = """
        UPDATE AttackNodes
        SET ongoing = FALSE
        WHERE identifier = ?
        """
        parameters = (node.identifier,)
        tasks.append(self.connection.execute(query, parameters))

        nxt = node.nxt
        if nxt is not None:
            query = """
            UPDATE AttackNodes
            SET ongoing = TRUE
            WHERE identifier = ?
            """
            parameters = (nxt.identifier,)
            tasks.append(self.connection.execute(query, parameters))
        else:
            query = """
            UPDATE AttackGraphs
            SET ongoing = FALSE
            WHERE initial_node = ?
            """
            parameters = (node.first().identifier,)
            tasks.append(self.connection.execute(query, parameters))

        await asyncio.gather(*tasks)
        await self.connection.commit()

    async def update_probability(self, node: AttackNode):
        """Update the probability of a node."""
        query = """
        UPDATE AttackNodes
        SET probabilities = ?
        WHERE identifier = ?
        """
        parameters = (self._mkstr(node.probability_history),
                      node.identifier)
        await self.connection.execute(query, parameters)
        await self.connection.commit()

    async def retrieve_applicable_workflows(self, attack: MitreTechnique) -> list[Workflow]:
        """Retrieve workflows able to mitigate a specific attack."""
        query = """
        SELECT identifier
        FROM Workflows
        WHERE effective_attacks LIKE ?
        """
        parameters = (f'%{attack}%',)

        ret = []
        async with self.connection.execute(query, parameters) as cursor:
            async for row in cursor:
                workflow = await self.retrieve_workflow(row['identifier'])
                if workflow is not None:
                    ret.append(workflow)
        return ret

    async def update_new_attack_graph(self, node: AttackNode):
        """Mark attack graph as having started taking place."""
        tasks = []
        query = """
        UPDATE AttackGraphs
        SET ongoing = TRUE
        WHERE initial_node = ?
        """
        parameters = (node.identifier,)
        tasks.append(self.connection.execute(query, parameters))

        query = """
        UPDATE AttackNodes
        SET ongoing = TRUE
        WHERE identifier = ?
        """
        tasks.append(self.connection.execute(query, parameters))
        await asyncio.gather(*tasks)
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
    log.debug('Advancing local state for %s nodes', len(state))
    for node in state:
        _next = node.nxt
        if _next is None:
            # Attack finished, but we might want to mitigate the
            # attack tree.  Keep it for now.
            log.debug('Attack graph with starting node ID %s was completed by this alert',
                      node.first().identifier)
            completed.append(node.first())
            continue
        if alert.rule_id == _next.technique:
            log.debug('Advancing state for node ID %s (to node ID %s)',
                      node.identifier,
                      _next.identifier)
            tasks.append(get_handler().mark_complete(node))
            new_state.append(_next)
            old_state.append(node)

    # 2: Add new attack graphs to the local state
    new_attack_graphs = await get_handler().retrieve_potential_graphs(alert.rule_mitre_ids)
    log.debug('Retrieved %s new attack graphs', len(new_attack_graphs))
    new_state.extend(new_attack_graphs)
    tasks.extend([get_handler().update_new_attack_graph(n)
                  for n in new_attack_graphs])

    # 3: Update probability percentages
    log.debug('Updating probabilities for all nodes')
    tasks.extend([get_handler().update_probability(n)
                  for n, p in [(n, await n.update_probability(alert))
                               for node in state for n in node.all()]
                  if p])

    # Run all DB updates
    log.debug('Running %s DB tasks...', len(tasks))
    await gather(*tasks)
    log.debug('DB tasks executed')

    # Update local state
    (state.remove(n) for n in old_state)
    state.extend(new_state)

    log.debug('Updated local state now contains %s attack node/s', len(state))

    for node in state:
        # Past: judge based on risk history
        for n in node.all_before():
            if n.historically_risky():
                past.append(n)
        # Present: only if it was related to this alert
        if node.technique in alert.rule_mitre_ids:
            present.append(node)
        # Future: judge based on how likely it is
        for n in node.all_after():
            if n.probability > config.PROBABILITY_TRESHOLD:
                future.append(n)

    return (past, present, future)
