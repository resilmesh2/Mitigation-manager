from __future__ import annotations
from uuid import uuid4
from math import fabs

from manager import config
from manager.model.conditions import Condition

class Node:
    def __init__(self, _prev: Node | None, _next: Node | None) -> None:
        self.id = uuid4()
        self.prv = _prev
        self.nxt = _next

    def first(self) -> Node:
        ret = self
        while ret.prv is not None:
            ret = ret.prv
        return ret

    def last(self) -> Node:
        ret = self
        while ret.nxt is not None:
            ret = ret.nxt
        return ret

    def then(self, _type: type[Node], *args, **kwargs) -> Node:
        tmp = _type.__new__(_type)
        tmp.__init__(*args, **kwargs)
        tmp.prv = self
        self.nxt = tmp
        return tmp


class AttackNode(Node):
    """Represents a MITRE tactic."""
    def __init__(self, technique: str, conditions: list[Condition], *, prev: Node | None = None, next: Node | None = None) -> None:
        super().__init__(prev, next)
        self.technique = technique
        self.conditions = conditions
        self.probability = 0.0

        self._cache_flat_map = None
        self._cache_all_before = None
        self._cache_all_after = None

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

    def next_attack(self) -> AttackNode | None:
        tmp = self.nxt
        while tmp is not None and type(tmp) is not AttackNode:
            tmp = tmp.nxt
        return tmp

    def all_attack_nodes(self) -> set[AttackNode]:
        if self._cache_flat_map is not None:
            return self._cache_flat_map
        ret: set[AttackNode] = set()
        b = self.prv
        while b is not None:
            if type(b) is AttackNode:
                ret.add(b)
                b = b.prv
        a = self.nxt
        while a is not None:
            if type(a) is AttackNode:
                ret.add(a)
                a = a.nxt
        self._cache_flat_map = ret
        return ret

    async def update_probability(self,
                                 alert: dict,
                                 epsilon: float = config.PROBABILITY_EPSILON,
                                 ) -> bool:
        """Recalculates the probability of the node being executed."""
        # Factor 3 is proportional to how many conditions have been
        # met.
        factor_3 = [await c.check(alert) for c in self.conditions].count(True) / len(self.conditions)

        old = self._probability
        self._probability = self._factor_1() * self._factor_2() * factor_3
        return False if fabs(self._probability - old) < epsilon else True

    def all_before(self) -> list[AttackNode]:
        if self._cache_all_before is not None:
            return self._cache_all_before
        ret = []
        tmp = self.prv
        while tmp is not None:
            if type(tmp) is AttackNode:
                ret.append(tmp)
                tmp = tmp.prv
        self._cache_all_before = ret
        return ret

    def all_after(self) -> list[AttackNode]:
        if self._cache_all_after is not None:
            return self._cache_all_after
        ret = []
        tmp = self.nxt
        while tmp is not None:
            if type(tmp) is AttackNode:
                ret.append(tmp)
                tmp = tmp.nxt
        self._cache_all_after = ret
        return ret
