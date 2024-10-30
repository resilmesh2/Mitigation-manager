from neo4j import AsyncGraphDatabase
import pytest

from manager import isim
from manager.model import Alert, CVECondition


@pytest.mark.asyncio
async def test_cve_condition():
    """
    Verify the CVECondition class.
    Checks against the CyberCzech dataset for known IP/CVE pairs.
    """
    isim.set_driver(AsyncGraphDatabase().driver('neo4j://localhost:7687',
                                                auth=('neo4j', 'supertestovaciheslo')))
    # Example present on the Czech database
    cve = 'CVE-2018-8493'
    alert = Alert({'agent': {'ip': '10.7.104.43'}})

    condition = CVECondition(cve)
    assert await condition.check(alert)

    alert.agent_ip = alert.agent_ip.replace('43', '443')
    assert not await condition.check(alert)
