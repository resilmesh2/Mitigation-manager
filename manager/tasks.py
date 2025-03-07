import asyncio

from manager import state
from manager.config import log
from manager.mitigation import mitigate_attack
from manager.model import Alert


async def handle_alert(alert: dict):
    """Handle an incoming alert."""
    try:
        parsed_alert = Alert.from_wazuh(alert)
        # Retrieve and update local state
        log.info('Updating local state')
        attacks = await state.update(parsed_alert)
        # Address individual attacks
        await asyncio.gather(*[mitigate_attack(a, parsed_alert) for a in attacks])
    except asyncio.CancelledError:
        log.info('Alert handling cancelled')
        return
