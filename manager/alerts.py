from typing import TYPE_CHECKING
from manager.config import log

if TYPE_CHECKING:
    from typing import Any

def mitre_identifiers(alert: dict) -> list[str] | None:
    try:
        return alert['rule']['mitre']['id']
    except KeyError as e:
        log.warning('Unable to extract MITRE identifiers: malformed alert')
        log.debug('Missing key: %s', e)
        return None


def parameters(alert: dict) -> dict[str, Any]:
    ret = {}

    if 'syscheck' in alert:
        ret['file.hash'] = alert['syscheck']['sha1_after']
        ret['file.path'] = alert['syscheck']['path']

    if 'agent' in alert:
        ret['agent.ip'] = alert['agent']['ip']
        ret['agent.id'] = alert['agent']['id']

    if 'data' in alert:
        ret['connection.dst_ip'] = alert['data']['dst_ip']
        ret['connection.src_port'] = alert['data']['src_port']
        ret['connection.dst_port'] = alert['data']['dst_port']

    return ret
