import asyncio

from manager import solver, state, workflows
from manager.config import log

async def handle_alert(alert: dict):
    try:
        # Step 1: update and retrieve local state
        log.info('Updating local state')
        mitigatable_nodes = await state.update(alert)

        # Step 2: Apply any necessary instant mitigations
        for node in mitigatable_nodes[0]:
            log.info('Immediate mitigations required, resolving workflows')
            wf = await workflows.locate(node)
            if wf is None:
                log.warning('No satisfactory workflow located, ignoring attack node')
            else:
                log.info('Workflow located, applying')
                results = await workflows.execute(wf)
                if workflows.successful(results):
                    log.info('Workflows applied successfully')
                else:
                    log.warning('Unable to apply workflows')
                    log.warning(workflows.error(wf))
        else:
            log.info('No immediate mitigations required')

        # Step 3: Resolve any future mitigations

        # Step 4: Resolve past mitigations
    except asyncio.CancelledError:
        log.info('Alert handling cancelled')
        return
