from __future__ import annotations

from json import dumps, loads
from types import MappingProxyType
from typing import TYPE_CHECKING, LiteralString, TypeVar

from manager import config
from manager.model import AttackNode, Condition, MitreTechnique, Workflow, WorkflowUrl
from manager.config import InvalidEnvironmentError, log

if TYPE_CHECKING:
    from collections.abc import Callable

    from aiosqlite import Connection, Row

    from manager.model import Alert


STATE_MANAGER: StateManager | None = None


def set_state_manager(state_manager: StateManager):
    """Set the global state manager."""
    global STATE_MANAGER
    STATE_MANAGER = state_manager


def get_state_manager() -> StateManager:
    """Get the global state manager."""
    global STATE_MANAGER
    if STATE_MANAGER is None:
        msg = 'State manager was never set'
        raise InvalidEnvironmentError(msg)
    return STATE_MANAGER


class InvalidDatabaseStateError(Exception):
    """Raised when a core database constraint is broken."""


class StateManager:
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
    def to_dict(item: Condition | AttackNode | Workflow) -> dict | None:
        """Return a JSON-friendly representation of the item."""
        if type(item) is Condition:
            return {
                'identifier': item.identifier,
                'params': item.params,
                'args': item.args,
                'query': item.query,
                'check': item.check,
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
        return [s for s in StateManager.CHECK_CODES if StateManager.CHECK_CODES[s] in _list]

    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    async def _extract_condition_parameters(self, row: Row) -> tuple[int, dict, dict, LiteralString, str]:
        return (row['identifier'],
                loads(row['params']),
                loads(row['args']),
                row['query'],
                row['check'])

    async def retrieve_condition(self, identifier: int) -> Condition | None:
        """Return the condition specified by the identifier.

        Returns `None` if the condition can't be found.
        """
        query = """
        SELECT identifier, params, args, query, check
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
        await self.connection.execute(query, (condition.identifier,
                                              dumps(condition.params),
                                              dumps(condition.args),
                                              condition.query,
                                              condition.check))

    async def _row_to_node_parameters(self, row: Row) -> tuple[int, str, list[Condition], list[float]]:
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
        async with self.connection.execute(query, parameters) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return AttackNode(*await self._row_to_node_parameters(row))

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
        await self.connection.execute(query, parameters)

    async def retrieve_state(self) -> list[AttackNode]:
        """Return the list of current attack graphs.

        The graphs are represented as a list of the last fulfilled
        attack nodes, each linked to the previous/next nodes to form
        the attack graph.
        """
        return [await self.retrieve_full_graph(n) for n in await self._retrieve_initial_nodes()]

    async def _retrieve_initial_nodes(self) -> list[AttackNode]:
        """Return the list of initial nodes for active attack graphs.

        This method does not return full attack graphs - the nodes'
        `prv` and `nxt` values will be `None`.
        """
        ret = []
        query = """
        SELECT an.*
        FROM AttackGraphs AS ag
        INNER JOIN AttackNodes AS an ON an.identifier = ag.initial_node
        WHERE ag.attack_front IS NOT NULL
        """
        async with self.connection.execute(query) as cursor:
            async for row in cursor:
                ret.append(AttackNode(*await self._row_to_node_parameters(row)))
        return ret

    async def retrieve_full_graph(self, initial_node: AttackNode) -> AttackNode:
        """Return an initial node's complete attack graph.

        The node returned is the ongoing node.  If none of the
        subsequent nodes are the ongoing node, returns `initial_node`.
        This function modifies `initial_node`'s `nxt` value.
        """
        # Retrieve the next node in the attack graph
        final_node = initial_node
        ret = None
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

        # Retrieve the attack front
        query_for_attack_front = """
        SELECT attack_front
        FROM AttackGraphs
        WHERE initial_node = ?
        """
        async with self.connection.execute(query_for_attack_front, (initial_node.identifier,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                msg = 'Initial node does not belong to an attack graph'
                raise InvalidDatabaseStateError(msg)
            attack_front = row['attack_front']

        if attack_front is None or attack_front == initial_node.identifier:
            ret = initial_node

        # Edge case: graphs of length 1
        if nxt is None:
            # Set the initial node values just in case
            initial_node.nxt = None
            return attack_front

        # Retrieve the remainder of the attack graph
        query = """
        SELECT *
        FROM AttackNodes
        WHERE identifier = ?
        """
        while True:
            async with self.connection.execute(query, (nxt,)) as cursor:
                if cursor.arraysize > 1:
                    msg = 'Multiple next nodes for attack node'
                    raise InvalidDatabaseStateError(msg)
                row = await cursor.fetchone()
                if row is None:
                    return final_node.first()
                row_params = await self._row_to_node_parameters(row)
                final_node = final_node.then(*row_params)
                if attack_front == final_node.identifier:
                    ret = final_node
                nxt = row['nxt']
                if nxt is None:
                    if ret is None:  # This should never happen
                        msg = 'Attack front is neither None nor any of the nodes in the attack graph'
                        raise InvalidDatabaseStateError(msg)
                    return ret

    async def retrieve_new_graphs(self, alert: Alert) -> list[AttackNode]:
        """Return a list of eligible new attack graphs.

        An attack graph is eligible if its initial node is triggered
        by the given alert.
        """
        ret = []
        # Edge case: attackless alert
        if not alert.has_mitre_attacks():
            return ret
        query_retrieve = """
        SELECT an.identifier AS identifier
        FROM AttackNodes AS an
        INNER JOIN AttackGraphs AS ag ON an.identifier = ag.initial_node
        WHERE ag.attack_front IS NULL
        """
        query_retrieve += f'AND ({" OR ".join("an.technique LIKE ?" for _ in alert.rule_mitre_ids)})'
        parameters_retrieve = (*[f'%{attack}%' for attack in alert.rule_mitre_ids],)
        async with self.connection.execute(query_retrieve, parameters_retrieve) as cursor:
            async for row in cursor:
                node = await self.retrieve_node(row['identifier'])
                if node is None:
                    msg = 'Missing initial node'
                    raise InvalidDatabaseStateError(msg)
                node = await self.retrieve_full_graph(node)
                ret.append(node)
        return ret

    async def mark_complete(self, node: AttackNode) -> bool:
        """Mark the attack node as completed.

        If there is a next node, mark it as the new attack front and
        return `False`.  If there is no next node, mark the attack
        graph as no longer taking place and return `True`.
        """
        attack_front = None if node.nxt is None else node.nxt.identifier

        query = """
        UPDATE AttackGraphs
        SET attack_front = ?
        WHERE initial_node = ?
        """
        parameters = (attack_front, node.first().identifier)
        await self.connection.execute(query, parameters)
        return attack_front is None

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


async def update(alert: Alert) -> tuple[list[AttackNode], list[AttackNode], list[AttackNode]]:
    """Update the local state with an alert.

    Return 3 lists of nodes that should be mitigated:
    - Nodes previously executed in the attack graphs.
    - Nodes immediately related by the alert.
    - Nodes further along in the active attack graphs.
    """
    state = await get_state_manager().retrieve_state()

    new_state: list[AttackNode] = []
    old_state: list[AttackNode] = []

    past: list[AttackNode] = []
    present: list[AttackNode] = []
    future: list[AttackNode] = []

    completed: list[AttackNode] = []

    log.debug('Attack front before retrieving new attack graphs: %s', [n.identifier for n in state])

    # 1: Add new attack graphs to the local state
    new_attack_graphs = await get_state_manager().retrieve_new_graphs(alert)
    log.debug('Retrieved %s new attack graphs', len(new_attack_graphs))
    state.extend(new_attack_graphs)

    # 2: Advance local state if necessary.
    log.info('Advancing attack front')
    log.debug('Current attack front:  %s', [n.identifier for n in state])
    for node in state:
        if alert.triggers(node):
            await get_state_manager().mark_complete(node)
            if node.nxt is not None:
                log.debug('Advancing state from node %s to %s', node.identifier, node.nxt.identifier)
                new_state.append(node.nxt)
            else:
                # Attack finished, but we might want to mitigate the
                # attack tree.  Keep it for now.
                log.debug('Attack graph with starting node %s was completed by this alert',
                          node.first().identifier)
                completed.append(node.first())
            old_state.append(node)
            continue
        log.debug('Node %s did not change state', node.identifier)

    # 3: Update probability percentages
    log.debug('Updating probabilities')
    for n, p in [(n, await n.update_probability(alert)) for node in state for n in node.all()]:
        if p:
            await get_state_manager().update_probability(n)

    # Run all DB updates
    log.debug('Committing changes to DB')
    await get_state_manager().connection.commit()

    # Update local state
    for n in old_state:
        state.remove(n)
    state.extend(new_state)

    log.debug('The updated attack front is: %s', [n.identifier for n in state])
    log.info('Evaluating attack front')

    for node in state:
        # Past: judge based on risk history
        for n in node.all_before():
            if n.historically_risky():
                log.debug('Node %s has been historically very risky, appending', n.identifier)
                past.append(n)
        # Present: only if it was related to this alert
        if node.technique in alert.rule_mitre_ids:
            log.debug('Node %s is directly impacted by the alert, appending', node.identifier)
            present.append(node)
        # Future: judge based on how likely it is
        for n in node.all_after():
            if n.probability > config.PROBABILITY_TRESHOLD:
                log.debug('Node %s is very likely to occur in the future, appending', n.identifier)
                future.append(n)

    return (past, present, future)
