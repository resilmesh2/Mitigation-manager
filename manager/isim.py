from collections.abc import Callable
from typing import LiteralString

from neo4j import AsyncDriver, Query, Record

DRIVER: AsyncDriver | None = None


def set_driver(driver: AsyncDriver):
    """Set the global ISIM driver."""
    global DRIVER
    DRIVER = driver


def get_driver() -> AsyncDriver:
    """Get the global ISIM driver."""
    global DRIVER
    if DRIVER is None:
        msg = 'Neo4j driver was never set'
        raise Exception(msg)
    return DRIVER


async def check_condition(query: LiteralString,
                          parameters: dict,
                          condition: Callable[[list[Record], dict], bool],
                          ) -> bool:
    """Query the ISIM and evaluate a condition."""
    res = await get_driver().execute_query(Query(query), parameters)
    return condition(res.records, parameters)
