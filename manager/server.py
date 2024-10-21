from datetime import datetime
from json import loads

import nats
from nats.aio.msg import Msg
from sanic import Blueprint, Sanic

from manager import bg_manager
from manager.config import log
from manager.tasks import handle_alert

async def initialize_nats(app: Sanic):
    async def handle_message(msg: Msg):
        try:
            alert = loads(msg.data.decode())
            log.debug(f'Received new alert: {alert["rule"]["description"]}')
            begin = datetime.now()
            app.add_task(handle_alert(alert))
            end = datetime.now()
            log.debug(f'Mitigation applied in {end - begin}')
        except ValueError as e:
            log.debug(f'Error while mitigating alert: {e}')
        except Exception as e:
            log.debug(f'Caught unknown exception ({type(e)}): {e}')
    log.debug('Connecting to NATS')
    app.ctx.nats_connection = await nats.connect('nats://nats:4222')
    log.debug('Subscribing to alerts')
    app.ctx.nats_subscription = await app.ctx.nats_connection.subscribe('alerts', cb=handle_message)
    log.info('Ready to mitigate')


def manager() -> Sanic:
    app = Sanic('Manager')
    bp_main = Blueprint.group(bg_manager, url_prefix='/api')
    app.blueprint(bp_main)
    app.before_server_start(initialize_nats)
    return app
