"""Shared pytest fixtures for the BATCH-kg-ui-mcp test suite.

Fixtures here are available to all tests without any explicit import.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock


# ---------------------------------------------------------------------------
# Neo4j driver mock helpers
# ---------------------------------------------------------------------------

def _make_session_mock(records: list[dict] | None = None, single: dict | None = None):
    """Return a mock async Neo4j session that yields *records* or a *single* row."""
    session_mock = AsyncMock()

    result_mock = AsyncMock()
    result_mock.data = AsyncMock(return_value=records or [])
    result_mock.single = AsyncMock(return_value=MagicMock(data=lambda: single or {}) if single else None)

    # Support async-for iteration over result
    if records is not None:
        result_mock.__aiter__ = AsyncMock(return_value=iter(records))

    session_mock.run = AsyncMock(return_value=result_mock)

    # Support async context manager: `async with driver.session() as session`
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=session_mock)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm, session_mock, result_mock


@pytest.fixture
def mock_driver():
    """Provide a MagicMock Neo4j async driver."""
    driver = MagicMock()
    driver.session = MagicMock()
    return driver


@pytest.fixture
def make_driver_with_records():
    """Factory fixture: returns a driver mock that yields specific records."""

    def _factory(records: list[dict]):
        driver = MagicMock()
        cm, session_mock, _ = _make_session_mock(records=records)
        driver.session = MagicMock(return_value=cm)
        return driver

    return _factory


@pytest.fixture
def make_driver_with_single():
    """Factory fixture: returns a driver mock whose result has a single row."""

    def _factory(single: dict):
        driver = MagicMock()

        session_mock = AsyncMock()
        result_mock = AsyncMock()
        record_mock = MagicMock()
        record_mock.data = MagicMock(return_value=single)
        record_mock.__getitem__ = MagicMock(side_effect=lambda k: single[k])

        result_mock.single = AsyncMock(return_value=record_mock)
        result_mock.data = AsyncMock(return_value=[single])

        session_mock.run = AsyncMock(return_value=result_mock)

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=session_mock)
        cm.__aexit__ = AsyncMock(return_value=False)
        driver.session = MagicMock(return_value=cm)
        return driver

    return _factory
