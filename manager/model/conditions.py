from collections.abc import Callable
from typing import Any, LiteralString

from neo4j import Record

from manager.isim import check_condition


class Condition:
    """Represents a condition."""

    def __init__(self, params: dict[str, Any],
                 args: dict[str, str | list[str]],
                 query: LiteralString,
                 check_function: Callable[[list[Record], dict], bool]) -> None:
        self.params = params
        self.args = args
        self.query: LiteralString = query
        self.check_function = check_function

    def parameters(self, alert: dict) -> dict | None:
        ret = {}
        for key, value in self.args.items():
            if key in ret:
                continue
            if type(value) is str:
                if value in alert:
                    ret[key] = alert[value]
                else:
                    # If the alert doesn't have the required query
                    # field, abort
                    return None
            if type(value) is list:
                for v in value:
                    if v in alert:
                        ret[key] = alert[v]
                        break
                if key not in ret:
                    # If the alert doesn't have at least one of the
                    # optional query fields, abort
                    return None
        return self.params | ret

    async def check(self, alert: dict) -> bool:
        """Query the ISIM and check whether the condition is true."""
        p = self.parameters(alert)
        # If not all parameters are available, the condition isn't
        # fulfilled.
        if p is None:
            return False
        return await check_condition(self.query, p, self.check_function)


class CVECondition(Condition):
    def __init__(self, cve_identifier: str) -> None:
        super().__init__(
            params={'cve_id': cve_identifier},
            args={'ip_address': 'agent.ip'},
            query='MATCH (ip:IP)<-[:HAS_ASSIGNED]-(:Node)'
            '-[:IS_A]-(:Host)<-[:ON]-(:SoftwareVersion)<-[:IN]-'
            '(:Vulnerability)-[:REFERS_TO]->(cve:CVE {CVE_id: $cve_id})\n'
            'RETURN ip.address as ip_address',
            check_function=lambda records, parameters:
            any(parameters['ip_address'] == r.get('ip_address') for r in records),
        )
