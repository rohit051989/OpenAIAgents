"""Neo4j async driver lifecycle management.

A single module-level driver is lazily created on first use and closed
during application shutdown.  All services receive the driver via
``get_driver()`` — they never instantiate it themselves.

Session helpers
---------------
Use ``kg_session(driver)`` to obtain a session scoped to the Knowledge
Graph database (``NEO4J_DATABASE_KG``) and ``ig_session(driver)`` for
the Information Graph database (``NEO4J_DATABASE_IG``).

Example::

    async with kg_session(driver) as session:
        result = await session.run(query)
"""

import logging
from typing import Optional

from neo4j import AsyncDriver, AsyncGraphDatabase

from config.settings import get_settings

logger = logging.getLogger(__name__)

_driver: Optional[AsyncDriver] = None


async def get_driver() -> AsyncDriver:
    """Return the (lazily-created) shared Neo4j async driver."""
    global _driver
    if _driver is None:
        settings = get_settings()
        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_pool_size=settings.neo4j_max_connection_pool_size,
            connection_timeout=settings.neo4j_connection_timeout,
        )
        logger.info("Neo4j driver created: %s", settings.neo4j_uri)
    return _driver


async def close_driver() -> None:
    """Close the driver and reset the module-level singleton."""
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None
        logger.info("Neo4j driver closed.")


def kg_session(driver: AsyncDriver):
    """Return a Neo4j async session scoped to the Knowledge Graph database."""
    return driver.session(database=get_settings().neo4j_database_kg)


def ig_session(driver: AsyncDriver):
    """Return a Neo4j async session scoped to the Information Graph database."""
    return driver.session(database=get_settings().neo4j_database_ig)


async def check_connectivity() -> bool:
    """Ping Neo4j to verify the connection is healthy.

    Returns ``True`` on success, ``False`` on any error.
    """
    try:
        drv = await get_driver()
        await drv.verify_connectivity()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Neo4j connectivity check failed: %s", exc)
        return False
