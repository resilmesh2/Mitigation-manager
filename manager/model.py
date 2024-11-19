from __future__ import annotations

from functools import reduce
from math import fabs
from types import SimpleNamespace
from typing import TYPE_CHECKING, LiteralString, get_args

from aiohttp import ClientSession

from manager import config
from manager.isim import check_conditions

if TYPE_CHECKING:
    from collections.abc import Callable

    from neo4j import Record

WorkflowUrl = str
MitreTechnique = str
JsonPrimitive = str | int | float | bool


class Alert(SimpleNamespace):

    TRANSLATIONS = {  # noqa: RUF012
        'rule': {
            'id': 'rule_id',
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

    def __init__(self, alert: dict) -> None:
        self._set(alert, self.TRANSLATIONS)

    def _set(self, a: dict, d: dict):
        for f in d:
            if f not in a:
                continue
            if type(d[f]) is dict:
                if type(a[f]) is not dict:
                    msg = f"Expected 'dict' in alert field '{f}', got '{type(a[f])}'"
                    raise ValueError(msg)
                self._set(a[f], d[f])
            elif type(d[f]) is str:
                if all(not isinstance(a[f], t) for t in get_args(JsonPrimitive)):
                    msg = f"Expected JSON primitive in alert field '{f}', got '{type(a[f])}'"
                    raise ValueError(msg)
                setattr(self, d[f], a[f])


class _UsesAlertParameters:
    def __init__(self,
                 params: dict[str, JsonPrimitive],
                 args: dict[str, str | list[str]],
                 ) -> None:
        self.params = params
        self.args = args

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


class Condition(_UsesAlertParameters):
    def __init__(self,
                 identifier: int,
                 params: dict[str, JsonPrimitive],
                 args: dict[str, str | list[str]],
                 query: LiteralString,
                 checks: list[Callable[[list[Record], dict[str, JsonPrimitive]], bool]],
                 ) -> None:
        super().__init__(params, args)
        self.identifier = identifier
        self.query: LiteralString = query
        self.checks = checks

    @staticmethod
    def check_any_result(records: list[Record], _: dict[str, JsonPrimitive]) -> bool:
        """Return true only if there's at least one result."""
        return len(records) > 0

    @staticmethod
    def _check_row_params(records: list[Record], params: dict[str, JsonPrimitive], _row, _param) -> bool:
        return _row(_param(params[x] == r.get(x) for x in params) for r in records)

    @staticmethod
    def check_any_param_in_any_row(records: list[Record], params: dict[str, JsonPrimitive]) -> bool:
        """Return true only if some row matches some parameter."""
        return Condition._check_row_params(records, params, any, any)

    @staticmethod
    def check_all_params_in_any_row(records: list[Record], params: dict[str, JsonPrimitive]) -> bool:
        """Return true only if some row matches all parameters."""
        return Condition._check_row_params(records, params, any, all)

    @staticmethod
    def check_any_param_in_all_rows(records: list[Record], params: dict[str, JsonPrimitive]) -> bool:
        """Return true only if all rows match some parameter."""
        return Condition._check_row_params(records, params, all, any)

    @staticmethod
    def check_all_params_in_all_rows(records: list[Record], params: dict[str, JsonPrimitive]) -> bool:
        """Return true only if all rows match all parameters."""
        return Condition._check_row_params(records, params, all, all)

    async def check(self, alert: Alert) -> bool:
        """Query the ISIM and check whether the condition is true."""
        p = self.parameters(alert)
        # If not all parameters are available, the condition isn't
        # fulfilled.
        if p is None:
            return False
        return await check_conditions(self.query, p, self.checks)


class DummyCondition(Condition):
    def __init__(self, identifier: int) -> None:
        super().__init__(identifier, {}, {}, '', [])


class AttackNode:
    """Represents a node in an attack graph."""

    def __init__(self,
                 identifier: int,
                 technique: str,
                 conditions: list[Condition],
                 probability_history: list[float],
                 *,
                 prv: AttackNode | None = None,
                 nxt: AttackNode | None = None) -> None:
        self.identifier = identifier
        self.prv = prv
        self.nxt = nxt
        self.technique = technique
        self.conditions = conditions
        self.probability_history = probability_history

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
             *,
             prv: AttackNode | None = None,
             nxt: AttackNode | None = None) -> AttackNode:
        """Add a new node after the current one and switch to it.

        If a node is already attached, it is fully detached.  Even if
        the described node specifies `prv`, `prv` is replaced with the
        current node.
        """
        tmp = AttackNode(identifier, technique, conditions, probability_history, prv=prv, nxt=nxt)
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
                    else ([await c.check(alert) for c in self.conditions].count(True) / len(self.conditions)))

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


class Workflow(_UsesAlertParameters):
    def __init__(self,
                 identifier: int,
                 name: LiteralString,
                 description: str,
                 url: WorkflowUrl,
                 effective_attacks: list[MitreTechnique],
                 cost: int,
                 params: dict[str, JsonPrimitive],
                 args: dict[str, str | list[str]],
                 ) -> None:
        super().__init__(params, args)
        self.identifier = identifier
        self.name = name
        self.description = description
        self.url = url
        self.effective_attacks = effective_attacks
        self.cost = cost

        self.executed = False
        self.results = None

    async def execute(self, alert: Alert) -> bool:
        """Execute the workflow."""
        body = self.parameters(alert)
        async with ClientSession() as client, client.post(self.url, json=body) as response:
            if response.status == 200:
                self.results = await response.json()
                self.executed = True
            config.log.debug('Workflow request failed with status code %s', response.status)
            config.log.debug(await response.text())
        return self.executed


class CVECondition(Condition):
    def __init__(self, cve_identifier: str) -> None:
        super().__init__(
            int.from_bytes(bytes(cve_identifier, 'UTF-8')),
            params={'cve_id': cve_identifier},
            args={'ip_address': 'agent_ip'},
            query='MATCH (ip:IP)<-[:HAS_ASSIGNED]-(:Node)'
            '-[:IS_A]-(:Host)<-[:ON]-(:SoftwareVersion)<-[:IN]-'
            '(:Vulnerability)-[:REFERS_TO]->(cve:CVE {CVE_id: $cve_id})\n'
            'RETURN ip.address as ip_address',
            checks=[lambda records, parameters:
                    any(parameters['ip_address'] == r.get('ip_address')
                        for r in records)],
        )
