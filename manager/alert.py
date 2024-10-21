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


def parameters(alert: dict) -> list[tuple[str, Any]]:
    ret = []

    if 'syscheck' in alert:
        ret.extend([('file.hash', alert['syscheck']['sha1_after']), ('file.path', alert['syscheck']['path'])])

    if 'agent' in alert:
        ret.extend([('agent.ip', alert['agent']['ip']),
                    ('agent.id', alert['agent']['id'])])

    if 'data' in alert:
        ret.extend([('connection.dst_ip', alert['data']['dst_ip']),
                    ('connection.src_port', alert['data']['src_port']),
                    ('connection.dst_port', alert['data']['dst_port'])])

    return ret
