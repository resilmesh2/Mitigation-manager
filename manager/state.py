from __future__ import annotations

from json import dumps, loads
from typing import TYPE_CHECKING, LiteralString, TypeVar

from manager import config
from manager.config import InvalidEnvironmentError, log
from manager.model import Attack, AttackNode, Condition, MitreTechnique, Workflow

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
                'name': item.name,
                'description': item.description,
                'params': item.params,
                'args': item.args,
                'check': item.check,
            }
        if type(item) is AttackNode:
            return {
                'identifier': item.identifier,
                'prv': item.prv.identifier if item.prv is not None else None,
                'nxt': item.nxt.identifier if item.nxt is not None else None,
                'technique': item.technique,
                'conditions': [StateManager.to_dict(c) for c in item.conditions],
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
                'checks': [StateManager.to_dict(c) for c in item.conditions],
            }
        return None

    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    async def _row_to_condition(self, row: Row) -> Condition:
        identifier = int(row['identifier'])
        condition_name: str = row['condition_name']
        condition_description: str = row['condition_description']
        params: dict = loads(row['params'])
        args: dict = loads(row['args'])
        checkstring: str = row['checkstring']
        return Condition(identifier, condition_name, condition_description, params, args, checkstring)

    async def retrieve_condition(self, identifier: int) -> Condition | None:
        """Return the condition specified by the identifier.

        Returns `None` if the condition can't be found.
        """
        query = """
        SELECT *
        FROM Conditions
        WHERE identifier = ?
        """
        parameters = (identifier,)
        async with self.connection.execute(query, parameters) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return await self._row_to_condition(row)

    async def store_condition(self, condition: Condition) -> None:
        """Store a condition."""
        query = """
        INSERT INTO Conditions
        (identifier, condition_name, condition_description, params, args, checkstring)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        await self.connection.execute(query, (condition.identifier,
                                              condition.name,
                                              condition.description,
                                              dumps(condition.params),
                                              dumps(condition.args),
                                              condition.check))

    async def _row_to_attack_node(self, row: Row) -> AttackNode:
        identifier = int(row['identifier'])
        technique = row['technique']
        conditions = [c
                      for c in [await self.retrieve_condition(c)
                                for c in self._mklist(row['conditions'], int)]
                      if c is not None]
        probabilities = self._mklist(row['probabilities'], float)
        description = row['description']
        return AttackNode(identifier, technique, conditions, probabilities, description)

    async def retrieve_node(self, identifier: int) -> AttackNode | None:
        """Return the attack specified by the identifier.

        Returns `None` if the attack node can't be found.  This
        method does not return the full attack graph - the node's
        `prv` and `nxt` values will be `None`.
        """
        query = """
        SELECT *
        FROM AttackNodes
        WHERE identifier = ?
        """
        parameters = (identifier,)
        async with self.connection.execute(query, parameters) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return await self._row_to_attack_node(row)

    async def store_node(self, node: AttackNode) -> None:
        """Store a node.

        The node's conditions don't have to be fully defined, they
        just need to contain the proper identifier.
        """
        query = """
        INSERT INTO AttackNodes
        (identifier, prv, nxt, technique, conditions, probabilities, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        log.debug('Storing node ID %s', node.identifier)
        parameters = (node.identifier,
                      node.prv.identifier if node.prv is not None else None,
                      node.nxt.identifier if node.nxt is not None else None,
                      node.technique,
                      self._mkstr(node.conditions, lambda c: str(c.identifier)),
                      self._mkstr([node.probability, *node.probability_history]),
                      node.description)
        await self.connection.execute(query, parameters)

    async def _row_to_workflow(self, row: Row) -> Workflow:
        identifier = int(row['identifier'])
        name: LiteralString = row['workflow_name']
        desc: str = row['workflow_desc']
        url: str = row['url']
        effective_attacks: list[str] = self._mklist(row['effective_attacks'], str)
        cost: int = int(row['cost'])
        params: dict = loads(row['params'])
        args: dict = loads(row['args'])
        conditions: list[Condition] = [c
                                       for c in [await self.retrieve_condition(i)
                                                 for i in self._mklist(row['conditions'], int)]
                                       if c is not None]
        return Workflow(identifier, name, desc, url, effective_attacks, cost, params, args, conditions)

    async def retrieve_workflow(self, identifier: int) -> Workflow | None:
        """Return the workflow specified by the identifier.

        Returns `None` if the workflow can't be found.
        """
        query = """
        SELECT *
        FROM Workflows
        WHERE identifier = ?
        """
        parameters = (identifier,)
        async with self.connection.execute(query, parameters) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return await self._row_to_workflow(row)

    async def store_workflow(self, workflow: Workflow) -> None:
        """Store a workflow.

        The workflow's conditions don't have to be fully defined, they
        just need to contain the proper identifier.
        """
        query = """
        INSERT INTO Workflows
        (identifier, workflow_name, workflow_description, url, effective_attacks, cost, params, args, conditions
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        parameters = (workflow.identifier,
                      workflow.name,
                      workflow.description,
                      workflow.url,
                      self._mkstr(workflow.effective_attacks),
                      workflow.cost,
                      dumps(workflow.workflow_parameters),
                      dumps(workflow.workflow_arguments),
                      self._mkstr(workflow.conditions, lambda c: str(c.identifier)))
        await self.connection.execute(query, parameters)

    async def _row_to_attack(self, row: Row) -> Attack:
        identifier = int(row['identifier'])

        # Retrieving the full attack graph requires knowing what the
        # initial node is.
        query = """
        SELECT an.identifier AS identifier
        FROM AttackNodes AS an
        INNER JOIN AttackGraphs AS ag ON ag.initial_node = an.identifier
        WHERE ag.identifier = ?
        """
        parameters = (row['attack_graph'],)
        async with self.connection.execute(query, parameters) as cursor:
            subrow = await cursor.fetchone()
            if subrow is None:
                msg = f'Initial node for attack graph {row["attack_graph"]} not found in the database'
                raise InvalidDatabaseStateError(msg)
            initial_node_identifier = subrow['identifier']
            # I could have technically made the initial node with the
            # previous query only, but I'd rather stick to the API I'm
            # making for now.
            initial_node = await self.retrieve_node(initial_node_identifier)
            if initial_node is None:
                msg = f'Node {initial_node_identifier} not found in the database'
                raise InvalidDatabaseStateError(msg)
        graph = await self.retrieve_full_graph(initial_node)

        attack_front_identifier = row['attack_front']
        attack_front = graph
        while attack_front.nxt is not None and attack_front.identifier != attack_front_identifier:
            attack_front = attack_front.nxt

        # Since we check even the initial node, we must have found the
        # attack front one way or the other.  Anything else is an
        # invalid database state.  The way to check for this is to see
        # if the identifiers are the same.
        if attack_front.identifier != attack_front_identifier:
            msg = f'Attack front {attack_front_identifier} not found in attack graph {graph.identifier}'
            raise InvalidDatabaseStateError(msg)

        context = row['context']
        ret = Attack(identifier, attack_front, {})
        ret.set_context_from_json(context)
        return ret

    async def retrieve_attacks(self) -> list[Attack]:
        """Return the list of current attacks."""
        ret = []
        query = """
        SELECT *
        FROM Attacks
        """
        async with self.connection.execute(query) as cursor:
            async for row in cursor:
                ret.append(await self._row_to_attack(row))
        return ret

    async def retrieve_full_graph(self, initial_node: AttackNode, attack_identifier: int | None = None) -> AttackNode:
        """Return an initial node's complete attack graph.

        When `attack_identifier` is not `None`, the node returned is
        the initial node.  Otherwise, the node returned is the
        attack's ongoing node.  This function modifies
        `initial_node`'s `nxt` value if it is malformed.
        """
        # Retrieve the attack front.  If no attack exists for the
        # attack graph, the attack front is the initial node.
        if attack_identifier is None:
            attack_front = initial_node.identifier
        else:
            query_for_attack_front = """
            SELECT attack_front
            FROM Attacks
            WHERE identifier = ?
            """
            async with self.connection.execute(query_for_attack_front, (attack_identifier,)) as cursor:
                row = await cursor.fetchone()
                if row is None:
                    msg = f'Attack {attack_identifier} not found in the database'
                    raise InvalidDatabaseStateError
                attack_front = row['attack_front']

        # Because we don't have initial_node.nxt, we need to query the
        # database to know if it even exists.
        final_node = initial_node
        query_for_first_nxt = """
        SELECT nxt
        FROM AttackNodes
        WHERE identifier = ?
        """
        async with self.connection.execute(query_for_first_nxt, (initial_node.identifier,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                msg = f'Attack node {initial_node.identifier} does not exist in the database'
                raise InvalidDatabaseStateError(msg)
            nxt = row['nxt']

        # Edge case: graphs of length 1
        if nxt is None:
            # Setting the nxt value ensures that a potentially
            # malformed parameter is fixed.
            initial_node.nxt = None
            return initial_node

        # Retrieve the remainder of the attack graph
        ret = initial_node if attack_front == initial_node.identifier else None
        query = """
        SELECT *
        FROM AttackNodes
        WHERE identifier = ?
        """
        while True:
            async with self.connection.execute(query, (nxt,)) as cursor:
                if cursor.arraysize > 1:
                    msg = f'Multiple next nodes for attack node {nxt}'
                    raise InvalidDatabaseStateError(msg)
                row = await cursor.fetchone()
                if row is None:
                    return final_node.first()
                node = await self._row_to_attack_node(row)
                final_node = final_node.then(node.identifier,
                                             node.technique,
                                             node.conditions,
                                             node.probability_history,
                                             node.description)
                del node
                if attack_front == final_node.identifier:
                    ret = final_node
                nxt = row['nxt']
                if nxt is None:
                    # If the attack front hasn't been mapped to a node
                    # yet, it must be an invalid node that's not in
                    # the attack graph.
                    if ret is None:
                        msg = f'Attack front {attack_front} does not exist in any of the nodes in attack graph'
                        raise InvalidDatabaseStateError(msg)
                    return ret

    async def retrieve_new_graphs(self, alert: Alert) -> list[AttackNode]:
        """Return a list of eligible new attack graphs.

        An attack graph is eligible if its initial node is triggered
        by the given alert and the alert isn't being tracked already
        by an existing attack.
        """
        ret = []
        # Edge case: attackless alert
        if len(alert.techniques()) == 0:
            log.warning('Alert has no MITRE Techniques, no new attack graphs triggered')
            return ret

        # Retrieve all attack graph identifiers that could potentially
        # be matched.
        potential_matches = []
        query_retrieve = """
        SELECT ag.identifier AS identifier
        FROM AttackGraphs AS ag
        INNER JOIN AttackNodes AS an ON an.identifier = ag.initial_node
        """
        query_retrieve += f'WHERE ({" OR ".join("an.technique LIKE ?" for _ in alert.techniques())})'
        parameters_retrieve = (*[f'%{attack}%' for attack in alert.techniques()],)
        async with self.connection.execute(query_retrieve, parameters_retrieve) as cursor:
            async for row in cursor:
                potential_matches.append(row['identifier'])

        potential_matches_str = f'({", ".join([str(i) for i in potential_matches])})'
        # For each attack graph, filter out those who aren't already
        # tracked by attacks and immediately append them.  These
        # queries trigger linter alerts due to potential SQL injection
        # attacks, but since the data we're getting is all strictly
        # coming from INT fields from the same database then there
        # should be no injection potential unless the database itself
        # is corrupted with invalid attack graph identifiers.
        query_no_attacks = f"""
        SELECT an.*
        FROM AttackGraphs AS ag
        LEFT JOIN Attacks AS a ON ag.identifier = a.attack_graph
        INNER JOIN AttackNodes AS an ON ag.initial_node = an.identifier
        WHERE a.identifier IS NULL
        AND ag.identifier IN {potential_matches_str}
        """  # noqa: S608
        async with self.connection.execute(query_no_attacks) as cursor:
            async for row in cursor:
                node = await self._row_to_attack_node(row)
                graph = await self.retrieve_full_graph(node)
                log.debug('Graph %s has no attacks ongoing, adding', graph.identifier)
                ret.append(graph)

        # For graphs with existing attacks, add them only if none of
        # those attacks are tracking the alert.
        query_with_attacks = f"""
        SELECT a.*
        FROM Attacks AS a
        WHERE a.attack_graph IN {potential_matches_str}
        """  # noqa: S608
        async with self.connection.execute(query_with_attacks) as cursor:
            async for row in cursor:
                attack = await self._row_to_attack(row)
                if not await self.already_tracked(alert, attack):
                    log.debug('Graph %s has no attacks matching the alert, adding', attack.attack_graph.identifier)
                    ret.append(attack.attack_graph)
        return ret

    async def already_tracked(self, alert: Alert, attack: Attack) -> bool:
        """Check if an alert is already mapped to an attack."""
        # For now, we will check if the alert is a duplicate of any of
        # the alerts stored inside the attack.
        for n in attack.attack_graph.all():
            stored_alert = attack.retrieve_alert(n)
            if stored_alert is not None and alert == stored_alert:
                return True
        return False

    async def start_attack(self, node: AttackNode) -> Attack:
        """Start tracking an attack graph.

        The attack graph being tracked is the one whose initial node
        is the argument's initial node.
        """
        query_graph = """
        SELECT identifier
        FROM AttackGraphs
        WHERE initial_node = ?
        """
        parameters_graph = (node.first().identifier,)
        identifier = None
        async with self.connection.execute(query_graph, parameters_graph) as cursor:
            async for row in cursor:
                identifier = row['identifier']
        if identifier is None:
            msg = 'Missing attack graph'
            raise InvalidDatabaseStateError(msg)
        query = """
        INSERT INTO Attacks
        (attack_graph, attack_front)
        VALUES (?, ?)
        """
        parameters = (identifier, node.first().identifier)
        cursor = await self.connection.execute(query, parameters)
        identifier = cursor.lastrowid
        if identifier is None:
            msg = 'INSERT operation did not result in a row ID'
            raise InvalidDatabaseStateError(msg)
        return Attack(identifier, node.first(), {})

    async def advance(self, attack: Attack, alert: Alert):
        """Advance an attack."""
        node = attack.attack_front
        attack.context[node.identifier] = alert
        if node.nxt is not None:
            attack_front = node.nxt
            query = """
            UPDATE Attacks
            SET attack_front = ?, context = ?
            WHERE identifier = ?
            """
            parameters = (attack_front.identifier, attack.get_context_as_json(), attack.identifier)
            await self.connection.execute(query, parameters)
        else:
            query = """
            DELETE FROM Attacks
            WHERE identifier = ?
            """
            parameters = (attack.identifier,)
            await self.connection.execute(query, parameters)
            attack.is_complete = True

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


async def update(alert: Alert) -> tuple[set[AttackNode], set[AttackNode], set[AttackNode]]:
    """Update the local state with an alert.

    Return 3 lists of nodes that should be mitigated:
    - Nodes previously executed in the attack graphs.
    - Nodes immediately related by the alert.
    - Nodes further along in the active attack graphs.
    """
    state = await get_state_manager().retrieve_attacks()

    past: set[AttackNode] = set()
    present: set[AttackNode] = set()
    future: set[AttackNode] = set()

    completed: list[Attack] = []

    # 2: Advance state if necessary.
    log.info('Advancing attack front')
    log.debug('Current attack front:  %s', [str(a) for a in state])
    for attack in state:
        log.debug('Checking if attack node %s is advanced by the alert', attack.identifier)
        if await attack.advanced_by(alert):
            log.debug('Advancing attack node %s', attack.identifier)
            await get_state_manager().advance(attack, alert)
            if attack.is_complete:
                log.debug('Attack node %s was completed by the alert', attack.identifier)
                completed.append(attack)
        else:
            log.debug('Attack node %s did not change state', attack.identifier)

    log.debug('Attack front after advancement: %s', [str(a) for a in state])

    # 1: Add new attacks to state
    new_attack_graphs = await get_state_manager().retrieve_new_graphs(alert)
    for graph in new_attack_graphs:
        new_attack = await get_state_manager().start_attack(graph)
        await get_state_manager().advance(new_attack, alert)
        state.append(new_attack)
    log.debug('Final attack front after new graphs: %s', [str(a) for a in state])

    # 3: Update probability percentages
    log.debug('Updating probabilities')
    for n, p in [(n, await n.update_probability(alert)) for node in state for n in node.attack_front.all()]:
        if p:
            await get_state_manager().update_probability(n)

    # Run all DB updates
    log.debug('Committing changes to DB')
    await get_state_manager().connection.commit()

    log.debug('Final attack front: %s', [a.identifier for a in state])
    log.info('Evaluating attack front')

    # TODO: Move this elsewhere, and instead of mitigating by node
    # mitigate by attack (run this check for all attacks, and use
    # context to determine if they should be mitigated),
    for attack in state:
        # Past: judge based on risk history
        for n in attack.attack_front.all_before():
            if n.historically_risky():
                log.debug('Node %s has been historically very risky, appending', n.identifier)
                past.add(n)
        # Present: only if it was related to this alert
        if attack.attack_front.technique in alert.rule_mitre_ids:
            log.debug('Node %s is directly impacted by the alert, appending', attack.attack_front.identifier)
            present.add(attack.attack_front)
        # Future: judge based on how likely it is
        for n in attack.attack_front.all_after():
            if n.probability > config.PROBABILITY_TRESHOLD:
                log.debug('Node %s is very likely to occur in the future, appending', n.identifier)
                future.add(n)

    return (past, present, future)
