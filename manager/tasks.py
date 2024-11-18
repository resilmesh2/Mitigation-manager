import asyncio

from manager import state, workflows
from manager.config import log
from manager.model import Alert, AttackNode


async def handle_alert(alert: dict):
    """Handle an incoming alert.

    Updates the local state, checks for attack nodes requiring
    mitigation, locates applicable workflows, and applies them.
    """
    try:

        parsed_alert = Alert(alert)

        # Step 1: update and retrieve local state
        log.info('Updating local state')
        mitigatable_nodes = await state.update(parsed_alert)

        # Step 2: Apply any necessary instant mitigations
        log.info('Applying immediate mitigations for latest attack')
        await _apply_immediate_mitigation(mitigatable_nodes[1])

        # Step 3: Resolve any future mitigations
        log.info('Applying immediate mitigations for potential future attacks')
        await _apply_immediate_mitigation(mitigatable_nodes[2])

        # Step 4: Resolve past mitigations
        log.info('Applying immediate mitigations for previous attacks')
        await _apply_immediate_mitigation(mitigatable_nodes[0])

    except asyncio.CancelledError:
        log.info('Alert handling cancelled')
        return


async def _apply_immediate_mitigation(nodes: list[AttackNode]):
    for node in nodes:
        log.info('Resolving optimal workflow for attack node')
        wf = await workflows.locate(node)
        if wf is None:
            log.warning('No satisfactory workflow located, ignoring attack node')
        else:
            log.debug('Workflow located, applying')
            await wf.execute()
            if wf.executed:
                log.info('Workflows applied successfully')
            else:
                log.warning('Unable to apply workflow')
