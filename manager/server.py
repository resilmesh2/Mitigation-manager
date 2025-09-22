# Copyright (C) 2025 Ekam Puri Nieto (UMU), Antonio Skarmeta Gomez
# (UMU), Jorge Bernal Bernabe (UMU).  See LICENSE file in the project
# root for details.

from json import loads
from pathlib import Path

import aiosqlite
import nats
from nats.aio.msg import Msg
from neo4j import AsyncGraphDatabase
from sanic import Blueprint, Sanic

from manager import bg_manager, isim, state
from manager.config import getenv, log, set_config
from manager.tasks import handle_alert


async def initialize_nats(app: Sanic):
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


async def shutdown_nats(app: Sanic):
    await app.ctx.nats_subscription.unsubscribe()
    await app.ctx.nats_connection.drain()


def initialize_neo4j(app: Sanic):
    log.debug('Connecting to ISIM')
    driver = AsyncGraphDatabase().driver(getenv('NEO4J_URL'),
                                         auth=(getenv('NEO4J_USERNAME'),
                                               getenv('NEO4J_PASSWORD')))
    app.ctx.neo4j_driver = driver
    isim.set_isim_manager(driver)


async def shutdown_neo4j(app: Sanic):
    await app.ctx.neo4j_driver.close()


async def initialize_sqlite(app: Sanic):
    log.debug('Connecting to SQLite')
    app.ctx.sqlite_db = await aiosqlite.connect(getenv('SQLITE_DB_PATH'))
    app.ctx.sqlite_db.row_factory = aiosqlite.Row
    with Path('resources/init.sql').open() as f:
        script = f.read()
    c = await app.ctx.sqlite_db.cursor()
    await c.executescript(script)
    await app.ctx.sqlite_db.commit()
    await c.close()
    state.set_state_manager(state.StateManager(app.ctx.sqlite_db))


async def shutdown_sqlite(app: Sanic):
    await app.ctx.sqlite_db.close()


def manager() -> Sanic:
    app = Sanic('Manager')
    bp_main = Blueprint.group(bg_manager, url_prefix='/api')
    app.blueprint(bp_main)
    set_config(app)
    app.before_server_start(initialize_nats)
    app.before_server_start(initialize_neo4j)
    app.before_server_start(initialize_sqlite)
    app.before_server_stop(shutdown_sqlite)
    app.before_server_stop(shutdown_neo4j)
    app.before_server_stop(shutdown_nats)
    return app
