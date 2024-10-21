import asyncio

from manager import solver, state, workflow
from manager.config import log

async def handle_alert(alert: dict):
    try:
        # Step 1: update local state
        log.info('Updating local state')
        await state.update(alert)

        # Step 2: if applicable, start mitigation process
        if await state.mitigations_needed():
            wf = await solver.find_mitigation()
            results = await workflow.execute(wf)
            if workflow.successful(results):
                log.info('Mitigation applied successfully')
            else:
                log.warning('Unable to apply mitigation')
                log.warning(workflow.error(wf))
    except asyncio.CancelledError:
        log.info('Alert handling cancelled')
        return
