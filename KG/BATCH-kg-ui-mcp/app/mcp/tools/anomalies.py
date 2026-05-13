"""MCP tool: detect_calendar_anomalies

Detects wrong job executions and cascading impact due to calendar rule violations.

This is a comprehensive tool that handles all 4 phases internally:
1. Fetch schedule rule bundle from Neo4j
2. Run evaluator pass to compute planned execution
3. Compare with actual execution and classify anomalies
4. Compute cascading impact on downstream jobs

The agent calls this one tool and gets a complete anomaly report.
"""

import logging
from datetime import datetime

from app.core.database import get_driver
from app.mcp.server import mcp
from app.services import anomalies_service

logger = logging.getLogger(__name__)


@mcp.tool(name="detect_calendar_anomalies")
async def tool_detect_calendar_anomalies(
    business_date: str,
    region: str = "ALL",
) -> dict:
    """Detect calendar-based job execution anomalies.

    Analyzes schedule rules, evaluates them against the given business date,
    compares against actual execution, and identifies anomalies (wrong executions,
    missed jobs) plus their cascading impact on downstream jobs.

    Use this when a user asks about:
    - Wrong job executions
    - Jobs that should/shouldn't have run on a date
    - Calendar constraint violations
    - Cascading impact of execution failures
    - Holiday-related execution issues

    Args:
        business_date: ISO date string (YYYY-MM-DD). Defaults to today if empty.
        region: Region code (e.g. 'US', 'UK', 'ALL'). Defaults to 'ALL'.

    Returns:
        Dictionary with:
          - business_date, region
          - planned_count, anomaly_count
          - anomalies: list of detected anomalies with type and impact
          - cascading_impact: downstream jobs affected
          - summary: aggregated statistics
    """
    # Default to today if empty
    if not business_date or business_date.strip() == "":
        business_date = datetime.now().strftime("%Y-%m-%d")

    logger.info(
        "MCP tool detect_calendar_anomalies business_date=%s region=%s",
        business_date,
        region,
    )

    driver = await get_driver()

    try:
        result = await anomalies_service.detect_calendar_anomalies(
            business_date, region, driver
        )
        return result
    except Exception as e:
        logger.exception("Anomaly detection failed")
        return {
            "success": False,
            "error": str(e),
            "business_date": business_date,
            "region": region,
        }
