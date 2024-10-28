from typing import Any

from manager import isim


class Condition:
    """Represents a condition."""
    def __init__(self, data: dict) -> None:
        self.data = data

    def get(self, key: str) -> Any:
        return None if key not in self.data else self.data[key]

    async def check(self, alert: dict) -> bool:
        """Queries the ISIM and checks whether the condition is true."""
        # For now, follow the example class below: run a query that
        # either returns something (matches) or nothing (doesn't
        # match)
        parameters = {}
        for key, value in self.data['args'].values():
            if key in parameters:
                continue
            if type(value) is str:
                if value in alert:
                    parameters[key] = alert[value]
                else:
                    # If the alert doesn't have the query field, then
                    # the condition isn't fulfilled.
                    return False
            if type(value) is list:
                for v in value:
                    if v in alert:
                        parameters[key] = alert[v]
                        break
                if key not in parameters:
                    # If the alert doesn't have at least one of the
                    # required query fields, then the condition isn't
                    # fulfilled.
                    return False
        parameters |= self.data['params']
        return await isim.find_any(self.data['query'], parameters)



class VulnerabilityCondition(Condition):
    def __init__(self, vulnerability_identifier: str) -> None:
        super().__init__({
            'params': {
                'vid': vulnerability_identifier,
            },
            'args': {
                'ip_address': 'agent.ip',
                'example_any': [
                    'vulnerability',
                    'vuln',
                ],
            },
            'query': 'MATCH (d:Device)-->(v:Vulnerability)\n'
            'WHERE d.address = \'$ip_address\'\n'
            'AND v.id = \'$vid\'\n'
            'RETURN d.ip, v.id',
        })
