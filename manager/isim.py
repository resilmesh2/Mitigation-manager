from typing import LiteralString
from typing_extensions import Callable
from neo4j import AsyncDriver, Query, Record

DRIVER: AsyncDriver | None = None

def set_driver(driver: AsyncDriver):
    global DRIVER
    DRIVER = driver

def get_driver() -> AsyncDriver:
    global DRIVER
    if DRIVER is None:
        raise Exception('Neo4j driver was never set')
    return DRIVER


async def check_condition(query: LiteralString,
                          parameters: dict,
                          condition: Callable[[list[Record], dict], bool]):
    res = await get_driver().execute_query(Query(query), parameters)
    return condition(res.records, parameters)
