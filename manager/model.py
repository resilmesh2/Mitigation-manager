from __future__ import annotations

from functools import reduce
from math import fabs
from types import SimpleNamespace
from typing import TYPE_CHECKING, LiteralString, get_args

from manager import config
from manager.isim import check_condition

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


class Condition:
    def __init__(self, params: dict[str, JsonPrimitive],
                 args: dict[str, str | list[str]],
                 query: LiteralString,
                 check_function: Callable[[list[Record], dict[str, JsonPrimitive]], bool],
                 ) -> None:
        self.params = params
        self.args = args
        self.query: LiteralString = query
        self.check_function = check_function

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

    async def check(self, alert: Alert) -> bool:
        """Query the ISIM and check whether the condition is true."""
        p = self.parameters(alert)
        # If not all parameters are available, the condition isn't
        # fulfilled.
        if p is None:
            return False
        return await check_condition(self.query, p, self.check_function)


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
        self.probability = probability_history[-1] if len(probability_history) > 0 else 0.0

        self._cache_flat_map = None
        self._cache_all_before = None
        self._cache_all_after = None

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
        """Add a new node after the current one and switch to it."""
        tmp = AttackNode(identifier, technique, conditions, probability_history, prv=prv, nxt=nxt)
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

        Factor 3 is proportional to how easy it is to complete an
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
        # met.
        factor_3 = [await c.check(alert) for c in self.conditions].count(True) / len(self.conditions)

        old = self.probability
        new = self._factor_1() * self._factor_2() * factor_3
        if fabs(self.probability - old) < epsilon:
            return False
        self.probability_history.append(old)
        self.probability = new
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
                 name: LiteralString,
                 url: WorkflowUrl,
                 mitigates: list[MitreTechnique],
                 conditions: list[Condition]) -> None:
        self.name = name
        self.url = url
        self.mitigates = mitigates
        self.conditions = conditions


class CVECondition(Condition):
    def __init__(self, cve_identifier: str) -> None:
        super().__init__(
            params={'cve_id': cve_identifier},
            args={'ip_address': 'agent_ip'},
            query='MATCH (ip:IP)<-[:HAS_ASSIGNED]-(:Node)'
            '-[:IS_A]-(:Host)<-[:ON]-(:SoftwareVersion)<-[:IN]-'
            '(:Vulnerability)-[:REFERS_TO]->(cve:CVE {CVE_id: $cve_id})\n'
            'RETURN ip.address as ip_address',
            check_function=lambda records, parameters:
            any(parameters['ip_address'] == r.get('ip_address') for r in records),
        )
