"""Unit tests for execution_service.

All tests mock the Neo4j driver — no live database required.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services import execution_service


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_driver(records: list[dict]) -> MagicMock:
    """Return a minimal async driver mock that yields *records*."""
    driver = MagicMock()

    result_mock = AsyncMock()
    result_mock.data = AsyncMock(return_value=records)

    session_mock = AsyncMock()
    session_mock.run = AsyncMock(return_value=result_mock)

    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=session_mock)
    cm.__aexit__ = AsyncMock(return_value=False)

    driver.session = MagicMock(return_value=cm)
    return driver


# ---------------------------------------------------------------------------
# get_failed_jobs
# ---------------------------------------------------------------------------

class TestGetFailedJobs:
    @pytest.mark.asyncio
    async def test_returns_failed_jobs(self):
        sample = [{"job_name": "JOB_A", "execution_id": "E1", "status": "FAILED"}]
        driver = _make_driver(sample)

        result = await execution_service.get_failed_jobs(driver, days=7, limit=10)

        assert result["count"] == 1
        assert result["time_range_days"] == 7
        assert result["failed_jobs"][0]["job_name"] == "JOB_A"

    @pytest.mark.asyncio
    async def test_empty_result(self):
        driver = _make_driver([])
        result = await execution_service.get_failed_jobs(driver)

        assert result["failed_jobs"] == []
        assert result["count"] == 0


# ---------------------------------------------------------------------------
# get_common_errors
# ---------------------------------------------------------------------------

class TestGetCommonErrors:
    @pytest.mark.asyncio
    async def test_returns_errors_sorted_by_occurrence(self):
        sample = [
            {"error": "NullPointerException", "occurrences": 10},
            {"error": "FileNotFoundException", "occurrences": 3},
        ]
        driver = _make_driver(sample)
        result = await execution_service.get_common_errors(driver, days=30, limit=10)

        assert result["count"] == 2
        assert result["common_errors"][0]["error"] == "NullPointerException"


# ---------------------------------------------------------------------------
# get_all_active_jobs
# ---------------------------------------------------------------------------

class TestGetAllActiveJobs:
    @pytest.mark.asyncio
    async def test_returns_active_jobs(self):
        sample = [
            {"job_id": "JOB_A", "job_name": "Job A", "execution_count": 5, "last_execution": "2026-04-05"},
        ]
        driver = _make_driver(sample)
        result = await execution_service.get_all_active_jobs(driver, days=30)

        assert result["count"] == 1
        assert result["active_jobs"][0]["job_id"] == "JOB_A"
        assert result["time_range_days"] == 30


# ---------------------------------------------------------------------------
# get_execution_timeline
# ---------------------------------------------------------------------------

class TestGetExecutionTimeline:
    @pytest.mark.asyncio
    async def test_returns_timeline_entries(self):
        sample = [
            {
                "execution_date": "2026-04-05",
                "total_executions": 20,
                "completed": 18,
                "failed": 2,
                "failure_rate": 10.0,
            }
        ]
        driver = _make_driver(sample)
        result = await execution_service.get_execution_timeline(driver, days=7)

        assert result["count"] == 1
        assert result["timeline"][0]["failure_rate"] == 10.0


# ---------------------------------------------------------------------------
# get_job_execution_history
# ---------------------------------------------------------------------------

class TestGetJobExecutionHistory:
    @pytest.mark.asyncio
    async def test_returns_history_for_job(self):
        sample = [
            {
                "execution_id": "EX001",
                "start_time": "2026-04-01T10:00:00",
                "end_time": "2026-04-01T10:05:00",
                "status": "COMPLETED",
                "duration_ms": 300000,
                "error_message": None,
            }
        ]
        driver = _make_driver(sample)
        result = await execution_service.get_job_execution_history(driver, job_id="JOB_A", days=30)

        assert result["job_id"] == "JOB_A"
        assert result["count"] == 1
        assert result["execution_history"][0]["status"] == "COMPLETED"
