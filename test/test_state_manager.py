from manager import config
from manager.model.state_manager import Node, AttackNode


def test_attack_graph_creation():
    node: Node = AttackNode('T0000', [])\
        .then(AttackNode, 'T0001', [])\
        .then(AttackNode, 'T0002', [])\
        .last()

    while node.prv is not None:
        assert type(node) is AttackNode
        node = node.prv

    node: Node = AttackNode('T0004', [])\
        .then(AttackNode, 'T0005', [])\
        .then(AttackNode, 'T0006', [])\
        .first()

    while node.nxt is not None:
        print(f'Node: {node}')
        assert type(node) is AttackNode
        node = node.nxt

def test_attack_graph_linkage():
    node: Node = AttackNode('T0000', [])\
        .then(AttackNode, 'T0001', [])\
        .then(AttackNode, 'T0002', [])\
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
    node: AttackNode = AttackNode('First', [])\
        .then(AttackNode, 'Second', [])\
        .then(AttackNode, 'Third', [])\
        .first()  # pyright:ignore
    assert len(node.all_before()) == 0
    assert len(node.all_after()) == 2
    node = node.nxt  # pyright:ignore
    assert len(node.all_before()) == 1
    assert len(node.all_after()) == 1
    node = node.nxt  # pyright:ignore
    assert len(node.all_before()) == 2
    assert len(node.all_after()) == 0


def test_factor_1():
    node: AttackNode = AttackNode('T0001', [])\
        .then(AttackNode, 'T0002', [])\
        .then(AttackNode, 'T0003', [])\
        .first()  # pyright:ignore

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
    node: AttackNode = AttackNode('T0003', [])\
        .then(AttackNode, 'T0002', [])\
        .then(AttackNode, 'T0001', [])\
        .first()  # pyright:ignore
    assert type(node) is AttackNode

    f2 = node._factor_2()

    for n in node.all_attack_nodes():
        assert f2 == n._factor_2(), 'Not all nodes in the same graph have the same second factor'

    # If the graph is smaller, factor 2 will always be equal or
    # smaller.  This operation is dangerous but it will always be
    # legal on a properly built graph (see test_attack_graph_linkage).
    node.last().prv.nxt = None  # pyright: ignore
    assert node._factor_2() <= f2, 'Second factor was higher with a shorter attack graph'

    # If the graph is bigger, factor 2 will always be equal or bigger.
    node.last().nxt = AttackNode('T9998', []).then(AttackNode, 'T9999', []).first()
    assert node._factor_2() >= f2, 'Second factor was lower with a longer attack graph'
