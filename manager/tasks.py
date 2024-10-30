import asyncio

from manager import state, workflows
from manager.config import log
from manager.model import Alert


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
        for node in mitigatable_nodes[1]:
            log.info('Immediate mitigation required, resolving workflows')
            wf = await workflows.locate(node)
            if wf is None:
                log.warning('No satisfactory workflow located, ignoring attack node')
            else:
                log.debug('Workflow located, applying')
                results = await workflows.execute(wf)
                if workflows.successful(results):
                    log.info('Workflows applied successfully')
                else:
                    log.warning('Unable to apply workflow')
                    log.warning(workflows.error(wf))

        # Step 3: Resolve any future mitigations
        for node in mitigatable_nodes[2]:
            log.info('Preemptive mitigation available, resolving workflow')
            wf = await workflows.locate(node)
            if wf is None:
                log.warning('No satisfactory workflow located, ignoring node')
            else:
                log.debug('Workflow located, applying')
                results = await workflows.execute(wf)
                if workflows.successful(results):
                    log.info('Workflows applied successfully')
                else:
                    log.warning('Unable to apply workflow')
                    log.warning(workflows.error(wf))

        # Step 4: Resolve past mitigations
        for node in mitigatable_nodes[0]:
            log.info('Found problematic node, resolving workflow')
            wf = await workflows.locate(node)
            if wf is None:
                log.warning('No satisfactory workflow located, ignoring problematic node')
            else:
                log.debug('Workflow located, applying')
                results = await workflows.execute(wf)
                if workflows.successful(results):
                    log.info('Workflows applied successfully')
                else:
                    log.warning('Unable to apply workflow')
                    log.warning(workflows.error(wf))

    except asyncio.CancelledError:
        log.info('Alert handling cancelled')
        return
