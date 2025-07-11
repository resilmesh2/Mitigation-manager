from __future__ import annotations

from functools import reduce
from json import dumps, loads
from math import fabs
from types import SimpleNamespace
from typing import LiteralString, get_args

import hy
from aiohttp import ClientSession

from manager import config
from manager.config import log

WorkflowUrl = str
MitreTechnique = str
JsonPrimitive = str | int | float | bool | list


class InvalidAlertError(Exception):
    """Raises when an alert doesn't conform to the expected format."""


class Alert(SimpleNamespace):

    TRANSLATIONS = {  # noqa: RUF012
        'rule': {
            'id': 'rule_id',
            'mitre': {
                'id': 'rule_mitre_ids',
            },
        },
        'syscheck': {
            'sha1_after': 'file_hash',
            'path': 'file_path',
            'perm_after': 'file_permissions',
        },
        'agent': {
            'id': 'agent_id',
            'ip': 'agent_ip',
        },
        'data': {
            'dst_ip': 'connection_dst_ip',
            'src_port': 'connection_src_port',
            'dst_port': 'connection_dst_port',
            'pid': 'connection_pid',
        },
    }

    REQUIRED_TYPES = {  # noqa: RUF012
        'rule_mitre_ids': list,
    }

    @classmethod
    def from_wazuh(cls, wazuh_alert: dict) -> Alert:
        alert = Alert()
        alert._set(wazuh_alert, alert.TRANSLATIONS)
        alert._validate()

        # In the future it might be a good idea to store the entire
        # original alert as well.

        return alert

    @classmethod
    def serialize(cls, alert: Alert) -> str:
        return dumps(alert.__dict__)

    @classmethod
    def deserialize(cls, alert: str) -> Alert:
        d = loads(alert)
        ret = Alert()
        for k in d:
            setattr(ret, k, d[k])
        return ret

    def _set(self, a: dict, d: dict):
        for f in d:
            if f not in a:
                continue
            if type(d[f]) is dict:
                if type(a[f]) is not dict:
                    msg = f"Expected 'dict' in alert field '{f}', got '{type(a[f])}'"
                    raise InvalidAlertError(msg)
                self._set(a[f], d[f])
            elif type(d[f]) is str:
                if all(not isinstance(a[f], t) for t in get_args(JsonPrimitive)):
                    msg = f"Expected JSON primitive in alert field '{f}', got '{type(a[f])}'"
                    raise InvalidAlertError(msg)
                setattr(self, d[f], a[f])

    def _validate(self):
        for attr, clazz in self.REQUIRED_TYPES.items():
            if not hasattr(self, attr):
                continue
            t = type(getattr(self, attr))
            if t is not clazz:
                msg = f'Alert attribute {attr} is not the correct type (expected {clazz}, got {t})'
                raise InvalidAlertError(msg)

    def techniques(self) -> list[str]:
        """Return the associated MITRE Technique identifiers."""
        return [] if not hasattr(self, 'rule_mitre_ids') else self.rule_mitre_ids

    def triggers(self, node: AttackNode) -> bool:
        """Check if the alert triggers the attack node."""
        log.debug('Checking if %s is within %s', node.technique, self.techniques())
        return node.technique in self.techniques()


class Condition:
    def __init__(self,
                 identifier: int,
                 name: str,
                 description: str,
                 params: dict[str, JsonPrimitive],
                 args: dict[str, str | list[str]],
                 check: str,
                 ) -> None:
        self.identifier = identifier
        self.name = name
        self.description = description
        self.params = params
        self.args = args
        self.check = check

    def parameters(self, alert: Alert) -> dict[str, JsonPrimitive] | None:
        """Return a dict containing parameters and their values."""
        ret = {}
        for key, value in self.args.items():
            if key in ret:
                continue
            if type(value) is str:
                if hasattr(alert, value):
                    ret[key] = getattr(alert, value)
                else:
                    # If the alert doesn't have the required query
                    # field, abort
                    return None
            if type(value) is list:
                for v in value:
                    if hasattr(alert, v):
                        ret[key] = getattr(alert, v)
                        break
                if key not in ret:
                    # If the alert doesn't have at least one of the
                    # optional query fields, abort
                    return None
        return self.params | ret

    async def is_met(self, _alert: Alert) -> bool:
        """Check if the condition is met.

        Warning: this method executes arbitrary Hy code.  Never call
        this method with an untrusted string.

        Hy code running in this method will have access to the
        following:

        - `parameters: dict`: The object's parameters, as parsed by
          the `parameters()` method.
        - `alert: Alert`: The alert.
        - `state_manager: StateManager`: The state manager.
        - `isim_manager: IsimManager`: The ISIM manager.
        - All Hy macros defined in `manager.conditions`

        Because of the scope, Hy code will obviously have access to
        more than just this, but to reduce complexity it should only
        depend on this.
        """
        # Setup
        wrapper = """
        (require manager.conditions *)
        (prepare-function {})
        """

        func = hy.eval(hy.read_many(wrapper.format(self.check)))

        return await func(self.parameters(_alert), _alert, log)

    def _contains_isim_query(self) -> str | None:
        if '#query' not in self.params:
            return None
        return str(self.params['#query'])


class DummyCondition(Condition):
    def __init__(self, identifier: int) -> None:
        super().__init__(identifier,
                         'Dummy condition',
                         'A dummy condition.  Always evaluates to true.',
                         {},
                         {},
                         '(True)')


class AttackNode:
    """Represents a node in an attack graph."""

    def __init__(self,
                 identifier: int,
                 technique: str,
                 conditions: list[Condition],
                 probability_history: list[float],
                 description: str,
                 *,
                 prv: AttackNode | None = None,
                 nxt: AttackNode | None = None) -> None:
        self.identifier = identifier
        self.prv = prv
        self.nxt = nxt
        self.technique = technique
        self.conditions = conditions
        self.probability_history = probability_history
        self.description = description

        self._cache_flat_map = None
        self._cache_all_before = None
        self._cache_all_after = None

    @property
    def probability(self) -> float:
        """The node's probability of being triggered in the future."""
        return self.probability_history[-1] if len(self.probability_history) > 0 else 0.0

    def first(self) -> AttackNode:
        """Select the first node in the attack graph."""
        ret = self
        while ret.prv is not None:
            ret = ret.prv
        return ret

    def last(self) -> AttackNode:
        """Select the last node in the attack graph."""
        ret = self
        while ret.nxt is not None:
            ret = ret.nxt
        return ret

    def then(self,
             identifier: int,
             technique: str,
             conditions: list[Condition],
             probability_history: list[float],
             description: str,
             *,
             prv: AttackNode | None = None,
             nxt: AttackNode | None = None) -> AttackNode:
        """Add a new node after the current one and switch to it.

        If a node is already attached, it is fully detached.  Even if
        the described node specifies `prv`, `prv` is replaced with the
        current node.
        """
        tmp = AttackNode(identifier, technique, conditions, probability_history, description, prv=prv, nxt=nxt)
        if self.nxt is not None:
            self.nxt.prv = None
        tmp.prv = self
        self.nxt = tmp
        return tmp

    async def is_triggered(self, alert: Alert) -> bool:
        """Check whether the alert triggers the current node."""
        if not alert.triggers(self):
            return False
        for c in self.conditions:
            if not await c.is_met(alert):
                log.info('Condition not met: %s', c.name)
                return False
            log.debug('Condition met: %s', c.name)
        return True

    def _factor_1(self, graph_interest: float = config.GRAPH_INTEREST) -> float:
        """Return the first factor used in calculating probability.

        Factor 1 is proportional to the attack graph's progress level
        (read as: the further along the attack graph has progressed,
        the more likely it is to continue progressing).  This factor
        follows a quadratic curve.
        """
        exp = (1 - graph_interest) * 4 + 1
        return (len(self.all_before()) / (len(self.all_before()) + 1 + len(self.all_after()))) ** exp

    def _factor_2(self,
                  max_conditions: int = config.MAX_CONDITIONS,
                  ease_impact: float = config.EASE_IMPACT) -> float:
        """Return the second factor used in calculating probability.

        Factor 2 is proportional to how easy it is to complete an
        attack graph (read as: the less preconditions an attack has in
        total, the easier it is to do).
        """
        return sum([len(n.conditions) for n in self.all_before()] +
                   [len(n.conditions) for n in self.all_after()] +
                   [len(self.conditions)]) / max_conditions * ease_impact

    async def update_probability(self,
                                 alert: Alert,
                                 epsilon: float = config.PROBABILITY_EPSILON,
                                 ) -> bool:
        """Recalculates the probability of the node being executed."""
        # Factor 3 is proportional to how many conditions have been
        # met.  If there are no conditions, this value is 1.
        factor_3 = (1.0
                    if len(self.conditions) == 0
                    else ([await c.is_met(alert) for c in self.conditions].count(True) / len(self.conditions)))

        old = self.probability
        new = (self._factor_1() + self._factor_2() + factor_3) / 3
        if fabs(old - new) < epsilon:
            log.debug('Skipping probability update of node %s (no meaningful change)', self.identifier)
            return False
        self.probability_history.append(new)
        return True

    def historically_risky(self) -> float:
        """Check if the node has been generally too risky."""
        risk = reduce(lambda a, b: a + b, self.probability_history) / len(self.probability_history)
        return risk > config.PROBABILITY_TRESHOLD

    def all_before(self) -> set[AttackNode]:
        """Collect all nodes before the current one."""
        if self._cache_all_before is not None:
            return self._cache_all_before
        ret = set()
        tmp = self.prv
        while tmp is not None:
            ret.add(tmp)
            tmp = tmp.prv
        self._cache_all_before = ret
        return ret

    def all_after(self) -> set[AttackNode]:
        """Collect all nodes after the current one."""
        if self._cache_all_after is not None:
            return self._cache_all_after
        ret = set()
        tmp = self.nxt
        while tmp is not None:
            ret.add(tmp)
            tmp = tmp.nxt
        self._cache_all_after = ret
        return ret

    def all(self) -> set[AttackNode]:
        """Collect all nodes in the attack graph."""
        return self.all_before() | {self} | self.all_after()


class Attack:
    def __init__(self, identifier: int, attack_front: AttackNode, context: dict) -> None:
        self.identifier = identifier
        self.attack_graph = attack_front.first()
        self.attack_front = attack_front
        self.is_complete = False
        self.context = context

    async def advanced_by(self, alert: Alert) -> bool:
        """Check whether an alert causes an attack to advance."""
        return await self.attack_front.is_triggered(alert)

    def retrieve_alert(self, node: AttackNode) -> Alert | None:
        """Retrieve the alert that triggered a node.

        Returns `None` if the node doesn't belong to the attack graph
        or it hasn't been triggered yet.
        """
        if node.identifier in self.context:
            return self.context[node.identifier]
        return None

    def get_context_as_json(self) -> str:
        """Return the attack's context as a JSON string."""
        ret = {}
        for k, v in self.context.items():
            # All context entries that are just a number will always
            # correspond to alerts.
            if isinstance(k, int):
                ret[k] = Alert.serialize(v)
            else:
                ret[k] = v
        return dumps(ret)

    def set_context_from_json(self, context: str):
        for k, v in loads(context).items():
            if k.isdigit():
                self.context[int(k)] = Alert.deserialize(v)
            else:
                self.context[k] = v

    def __str__(self) -> str:
        """Return a debug-friendly representation of the Attack."""
        return (f'Attack {self.identifier} '
                f'on graph {self.attack_graph.identifier} '
                f'node {self.attack_front.identifier}')


class Workflow:
    def __init__(self,
                 identifier: int,
                 name: LiteralString,
                 description: str,
                 url: WorkflowUrl,
                 effective_attacks: list[MitreTechnique],
                 cost: int,
                 workflow_parameters: dict[str, JsonPrimitive],
                 workflow_arguments: dict[str, str | list[str]],
                 conditions: list[Condition],
                 ) -> None:
        self.identifier = identifier
        self.name = name
        self.description = description
        self.url = url
        self.effective_attacks = effective_attacks
        self.cost = cost
        self.workflow_parameters = workflow_parameters
        self.workflow_arguments = workflow_arguments
        self.conditions = conditions

        self.executed = False
        self.results = None

    def generate_request_json(self, alert: Alert) -> dict | None:
        """Generate the HTTP request JSON body.

        Returns a JSON-parsable dict with the request body, or `None`
        if there is no request body.
        """
        # This function body is very similar to Condition.parameters()
        # but it's been duplicated because the logic and semantics are
        # different.
        ret = {}
        for key, value in self.workflow_arguments.items():
            if key in ret:
                continue
            if type(value) is str:
                if hasattr(alert, value):
                    ret[key] = getattr(alert, value)
                else:
                    # If the alert doesn't have the required field,
                    # abort
                    return None
            if type(value) is list:
                for v in value:
                    if hasattr(alert, v):
                        ret[key] = getattr(alert, v)
                        break
                if key not in ret:
                    # If the alert doesn't have at least one of the
                    # optional fields, abort
                    return None
        return self.workflow_parameters | ret

    async def is_executable(self, alert: Alert) -> bool:
        """Check whether the workflow can be applied or not.

        Warning: this method executes arbitrary Hy code.  Never call
        this method with untrusted conditions.
        """
        return all([await c.is_met(alert) for c in self.conditions])

    async def execute(self, alert: Alert) -> bool:
        """Execute the workflow."""
        log.debug('Executing workflow "%s"', self.name)
        body = self.generate_request_json(alert)
        async with ClientSession() as client, client.post(self.url, json=body) as response:
            if response.status == 200:
                self.results = await response.json()
                self.executed = True
            else:
                log.debug('Workflow request failed with status code %s', response.status)
                log.debug(await response.text())
                self.executed = False
        return self.executed
