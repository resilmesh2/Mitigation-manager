from collections.abc import Callable
from typing import LiteralString

from neo4j import AsyncDriver, Query, Record

from manager.config import InvalidEnvironmentError

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
        raise InvalidEnvironmentError(msg)
    return DRIVER


async def check_conditions(query: LiteralString,
                           parameters: dict,
                           conditions: list[Callable[[list[Record], dict], bool]],
                           ) -> bool:
    """Query the ISIM and evaluate a condition."""
    res = await get_driver().execute_query(Query(query), parameters)
    return all(c(res.records, parameters) for c in conditions)
