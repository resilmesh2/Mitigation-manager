from __future__ import annotations

from typing import TYPE_CHECKING, LiteralString

from manager.config import InvalidEnvironmentError

if TYPE_CHECKING:
    from neo4j import AsyncDriver, Record

ISIM_MANAGER: IsimManager | None = None


def set_isim_manager(isim_manager: AsyncDriver):
    """Set the global ISIM manager."""
    global ISIM_MANAGER
    ISIM_MANAGER = IsimManager(isim_manager)


def get_isim_manager() -> IsimManager:
    """Get the global ISIM manager."""
    global ISIM_MANAGER
    if ISIM_MANAGER is None:
        msg = 'Neo4j driver was never set'
        raise InvalidEnvironmentError(msg)
    return ISIM_MANAGER


class IsimManager:
    def __init__(self, driver: AsyncDriver) -> None:
        self.driver = driver

    async def run_query(self, query: LiteralString, parameters: dict) -> list[Record]:
        """Run a query against the ISIM."""
        res = await self.driver.execute_query(query, parameters)
        return res.records
