from manager import config
from manager.model import AttackNode

# ruff: noqa: SLF001


def test_attack_graph_creation():
    node = AttackNode(123, 'T0000', [], [], '')\
        .then(456, 'T0001', [], [], '')\
        .then(789, 'T0002', [], [], '')\
        .last()

    assert node.identifier == 789
    assert node.technique == 'T0002'

    node = node.prv
    assert node is not None
    assert node.identifier == 456
    assert node.technique == 'T0001'

    node = node.prv
    assert node is not None
    assert node.identifier == 123
    assert node.technique == 'T0000'

    node = AttackNode(123, 'T0004', [], [], '')\
        .then(456, 'T0005', [], [], '')\
        .then(789, 'T0006', [], [], '')\
        .first()

    assert node.identifier == 123
    assert node.technique == 'T0004'

    node = node.nxt
    assert node is not None
    assert node.identifier == 456
    assert node.technique == 'T0005'

    node = node.nxt
    assert node is not None
    assert node.identifier == 789
    assert node.technique == 'T0006'


def test_attack_graph_linkage():
    node = AttackNode(123, 'T0000', [], [], '')\
        .then(456, 'T0001', [], [], '')\
        .then(789, 'T0002', [], [], '')\
        .first()
    cur = node.nxt
    prev = node
    assert prev.prv is None
    while cur is not None:
        assert prev.nxt is cur
        assert cur.prv is prev
        prev = cur
        cur = cur.nxt
    assert prev.nxt is None


def test_attack_graph_sets():
    node = AttackNode(123, 'First', [], [], '')\
        .then(456, 'Second', [], [], '')\
        .then(789, 'Third', [], [], '')\
        .first()
    assert len(node.all_before()) == 0
    assert len(node.all_after()) == 2
    node = node.nxt  # pyright:ignore
    assert node is not None
    assert len(node.all_before()) == 1
    assert len(node.all_after()) == 1
    node = node.nxt  # pyright:ignore
    assert node is not None
    assert len(node.all_before()) == 2
    assert len(node.all_after()) == 0


def test_factor_1():
    node = AttackNode(123, 'T0001', [], [], '')\
        .then(456, 'T0002', [], [], '')\
        .then(789, 'T0003', [], [], '')\
        .first()

    prev = node._factor_1()
    n = node.nxt
    higher_interest = min(config.GRAPH_INTEREST + config.GRAPH_INTEREST * 0.1, 1)
    lower_interest = max(config.GRAPH_INTEREST - config.GRAPH_INTEREST * 0.1, 0)

    while n is not None:
        if type(n) is AttackNode:
            assert n._factor_1() > prev, \
                'Factor 1 is not strictly higher for each attack node'
            assert n._factor_1(higher_interest) >= n._factor_1(), \
                'Factor 1 is not equal or higher for a higher graph interest'
            assert n._factor_1(lower_interest) <= n._factor_1(), \
                'Factor 1 is not equal or lower for a lower graph interest'
            prev = n._factor_1()
        n = n.nxt


def test_factor_2():
    node = AttackNode(123, 'T0003', [], [], '')\
        .then(456, 'T0002', [], [], '')\
        .then(789, 'T0001', [], [], '')\
        .first()
    assert type(node) is AttackNode

    f2 = node._factor_2()

    for n in node.all():
        assert f2 == n._factor_2(), 'Not all nodes in the same graph have the same second factor'

    # If the graph is smaller, factor 2 will always be equal or
    # smaller.  This operation is dangerous but it will always be
    # legal on a properly built graph (see test_attack_graph_linkage).
    node.last().prv.nxt = None  # pyright: ignore
    assert node._factor_2() <= f2, 'Second factor was higher with a shorter attack graph'

    # If the graph is bigger, factor 2 will always be equal or bigger.
    node.last().nxt = AttackNode(123, 'T9998', [], [], '').then(456, 'T9999', [], [], '').first()
    assert node._factor_2() >= f2, 'Second factor was lower with a longer attack graph'
