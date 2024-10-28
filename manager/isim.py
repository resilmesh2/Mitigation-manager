from typing import LiteralString
from neo4j import AsyncDriver, Query

DRIVER: AsyncDriver | None = None

def set_driver(driver: AsyncDriver):
    global DRIVER
    DRIVER = driver

def get_driver() -> AsyncDriver:
    global DRIVER
    if DRIVER is None:
        raise Exception('Neo4j driver was never set')
    return DRIVER


async def find_any(query: LiteralString, parameters: dict) -> bool:
    res = await get_driver().execute_query(Query(query), parameters)
    # TODO this might not do what I think it does
    return len(res.records) > 0
