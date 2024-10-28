import asyncio

from manager import solver, state, workflows
from manager.config import log

async def handle_alert(alert: dict):
    try:
        # Step 1: update local state
        log.info('Updating local state')
        await state.update(alert)

        # Step 2: if applicable, start mitigation process
        if await state.mitigations_needed():
            log.info('Mitigation required, resolving workflows')
            wf = await solver.find_workflow()
            log.info('Applying workflows')
            results = await workflows.execute(wf)
            if workflows.successful(results):
                log.info('Workflows applied successfully')
            else:
                log.warning('Unable to apply workflows')
                log.warning(workflows.error(wf))
        else:
            log.info('No mitigation required')
    except asyncio.CancelledError:
        log.info('Alert handling cancelled')
        return
