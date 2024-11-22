from __future__ import annotations

from functools import reduce
from math import fabs
from types import SimpleNamespace
from typing import LiteralString, get_args

import hy
from aiohttp import ClientSession

from manager import config
from manager.isim import get_isim_manager
from manager.state import get_state_manager

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

    def __init__(self, alert: dict) -> None:
        self._set(alert, self.TRANSLATIONS)
        self._validate()

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

    def has_mitre_attacks(self) -> bool:
        """Check if the alert has any associated MITRE ATT&CK IDs."""
        return hasattr(self, 'rule_mitre_ids') and len(self.rule_mitre_ids) > 0

    def triggers(self, node: AttackNode) -> bool:
        """Check if the alert triggers the attack node."""
        if not self.has_mitre_attacks():
            return False
        return node.technique in self.rule_mitre_ids


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

    async def is_met(self, alert: Alert) -> bool:
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

        Because of the scope, Hy code will obviously have access to
        more than just this, but to reduce complexity it should only
        depend on this.
        """
        # Set up variables
        parameters = self.parameters(alert)
        state_manager = get_state_manager()
        isim_manager = get_isim_manager()
        # There should only be one form to read anyway
        parsed_check = hy.read_one(self.check)
        result = hy.eval(parsed_check)
        return bool(result)

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

    def _factor_1(self, graph_interest: float = config.GRAPH_INTEREST) -> float:
        """Return the first factor used in calculating probability.

        Factor 1 is proportional to the attack graph's progress level
        (read as: the further along the attack graph has progressed,
        the more likely it is to continue progressing).  This factor
        follows a quadratic curve.
        """
        exp = (1 - graph_interest) * 4 + 1
        return (len(self.all_before()) / (len(self.all_before()) + len(self.all_after()))) ** exp

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
            config.log.debug('Skipping probability update of node %s (no meaningful change)', self.identifier)
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
        config.log.debug('Executing workflow "%s"', self.name)
        body = self.generate_request_json(alert)
        async with ClientSession() as client, client.post(self.url, json=body) as response:
            if response.status == 200:
                self.results = await response.json()
                self.executed = True
            config.log.debug('Workflow request failed with status code %s', response.status)
            config.log.debug(await response.text())
        return self.executed
