from json import loads

import nats
from nats.aio.msg import Msg
from neo4j import AsyncGraphDatabase
from sanic import Blueprint, Sanic

from manager import bg_manager, isim
from manager.config import getenv, log, set_config
from manager.tasks import handle_alert


async def initialize_nats(app: Sanic):  # noqa: D103
    async def handle_message(msg: Msg):  # noqa: RUF029
        alert = loads(msg.data.decode())
        log.info('New incoming alert')
        if 'rule' in alert:
            log.debug(alert['rule']['description'])
        app.add_task(handle_alert(alert))
    log.debug('Connecting to NATS')
    app.ctx.nats_connection = await nats.connect(getenv('NATS_URL'))
    log.debug('Subscribing to alerts')
    app.ctx.nats_subscription = await app.ctx.nats_connection.subscribe(
        getenv('NATS_TOPIC'),
        cb=handle_message,
    )
    log.info('Ready to mitigate')


async def shutdown_nats(app: Sanic):  # noqa: D103
    await app.ctx.nats_subscription.unsubscribe()
    await app.ctx.nats_connection.drain()


def initialize_neo4j(app: Sanic):  # noqa: D103
    driver = AsyncGraphDatabase().driver(getenv('NEO4J_URL'),
                                         auth=(getenv('NEO4J_USERNAME'), getenv('NEO4J_PASSWORD')))
    app.ctx.neo4j_driver = driver
    isim.set_driver(driver)


async def shutdown_neo4j(app: Sanic):  # noqa: D103
    await app.ctx.neo4j_driver.close()


def manager() -> Sanic:  # noqa: D103
    app = Sanic('Manager')
    bp_main = Blueprint.group(bg_manager, url_prefix='/api')
    app.blueprint(bp_main)
    set_config(app)
    app.before_server_start(initialize_nats)
    app.before_server_start(initialize_neo4j)
    app.before_server_stop(shutdown_neo4j)
    app.before_server_stop(shutdown_nats)
    return app
