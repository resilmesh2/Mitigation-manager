# Copyright (C) 2025 Ekam Puri Nieto (UMU), Antonio Skarmeta Gomez
# (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the project
# root for details.

from manager import workflows
from manager.config import PROBABILITY_TRESHOLD, log
from manager.model import Alert, Attack, AttackNode


async def mitigate_attack(attack: Attack, alert: Alert):
    """Apply an appropriate mitigation for the attack in question.

    Both the historic attack information and the latest alert are used
    for mitigation, even if this alert hasn't triggered any
    condition/node in the attack.
    """
    # Past: judge based on risk history
    for n in attack.attack_front.all_before():
        if n.historically_risky():
            log.debug('Node %s has been historically very risky, mitigating', n.identifier)
            await mitigate_attack_immediately(attack, n, alert)
    # Present: only if it is related to this alert
    if attack.attack_front.technique in alert.techniques():
        log.debug('Node %s is directly impacted by the alert, mitigating', attack.attack_front.identifier)
        await mitigate_attack_immediately(attack, attack.attack_front, alert)
    # Future: judge based on how likely it is
    for n in attack.attack_front.all_after():
        if n.probability > PROBABILITY_TRESHOLD:
            log.debug('Node %s is very likely to occur in the future, mitigating', n.identifier)
            await mitigate_attack_immediately(attack, n, alert)


async def mitigate_attack_immediately(attack: Attack, node: AttackNode, alert: Alert):
    log.debug('Resolving optimal workflow for attack node')
    wf = await workflows.locate(node)
    if wf is None:
        log.warning('No satisfactory workflow located, unable to mitigate node')
    elif not await wf.is_executable(alert):
        log.warning('Workflow conditions are not met, unable to execute')
    else:
        log.debug('Applying workflow "%s"', wf.name)
        await wf.execute(alert)
        if wf.executed:
            log.info('Workflows applied successfully')
        else:
            log.warning('Unable to apply workflow')
