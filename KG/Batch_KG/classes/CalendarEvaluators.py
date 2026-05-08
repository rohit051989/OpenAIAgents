"""
Calendar Rule Evaluators
========================
Pure-Python functions that answer "does this date match the rule?" (True/False).

Each function is registered under a key that maps to CalendarPattern.evaluatorFn
in the Neo4j knowledge graph.  The agentic backend calls them via:

    full_args = {**runtime_context} | json.loads(rule.params)
    result    = EVALUATOR_REGISTRY[pattern.evaluatorFn](**full_args)

runtime_context is built by the agent from the incoming request and always
contains at minimum:
    date    (str YYYY-MM-DD or datetime.date)  — the candidate date
    region  (str)                              — e.g. 'US', 'CA', 'ALL'

rule.params (configParams) are baked in by the rule author and vary per pattern.

All functions accept **kwargs so that extra context keys never cause TypeErrors.
"""

from __future__ import annotations

import calendar as _cal
from datetime import date as _date
from typing import Union

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_date(d: Union[str, _date]) -> _date:
    """Normalise input to datetime.date."""
    if isinstance(d, _date):
        return d
    return _date.fromisoformat(str(d)[:10])


def _last_day_of_month(year: int, month: int) -> int:
    return _cal.monthrange(year, month)[1]


def _quarter_of(d: _date) -> int:
    return (d.month - 1) // 3 + 1


def _quarter_months(quarter: int) -> tuple[int, int]:
    """Return (first_month, last_month) for a quarter number 1-4."""
    first = (quarter - 1) * 3 + 1
    return first, first + 2


# ---------------------------------------------------------------------------
# Core evaluators
# ---------------------------------------------------------------------------

def evaluate_nth_dow_month(
    date: Union[str, _date],
    dayOfWeek: int,
    occurrences: list[int],
    **kwargs,
) -> bool:
    """
    Match the Nth occurrence(s) of a specific weekday within the month.

    Args:
        date:        Candidate date.
        dayOfWeek:   ISO weekday (1=Mon … 7=Sun).
        occurrences: List of occurrence indices to match, e.g. [1] = first,
                     [-1] = last (not supported yet — use positive integers).
    """
    d = _to_date(date)
    if d.isoweekday() != dayOfWeek:
        return False
    week_of_month = (d.day - 1) // 7 + 1
    return week_of_month in occurrences


def evaluate_nth_multi_dow_month(
    date: Union[str, _date],
    daysOfWeek: list[int],
    occurrences: list[int],
    **kwargs,
) -> bool:
    """
    Match any of the first N weekdays (Mon-Fri) of the month.

    Counts Mon-Fri occurrences only; skips weekends.
    e.g. occurrences=[1,2,3,4,5] + daysOfWeek=[1,2,3,4,5] → first 5 business
    days of the month.
    """
    d = _to_date(date)
    if d.isoweekday() not in daysOfWeek:
        return False
    # Count qualifying weekdays from the 1st up to and including d
    count = sum(
        1
        for day in range(1, d.day + 1)
        if _date(d.year, d.month, day).isoweekday() in daysOfWeek
    )
    return count in occurrences


def evaluate_nth_dom_month(
    date: Union[str, _date],
    dayOfMonth: int,
    **kwargs,
) -> bool:
    """Match a fixed day-of-month (e.g. the 15th of every month)."""
    d = _to_date(date)
    return d.day == dayOfMonth


def evaluate_nth_first_biz_month(
    date: Union[str, _date],
    occurrences: list[int],
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the start of the month.

    Business day = Monday-Friday (holidays not considered here; use a
    compound rule or the HOLIDAY deny-rule to block holidays separately).
    """
    d = _to_date(date)
    if d.isoweekday() > 5:          # weekend — never a business day
        return False
    biz_count = sum(
        1
        for day in range(1, d.day + 1)
        if _date(d.year, d.month, day).isoweekday() <= 5
    )
    return biz_count in occurrences


def evaluate_nth_last_biz_month(
    date: Union[str, _date],
    occurrences: list[int],
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the END of the month.

    occurrence=1 → last business day, occurrence=2 → second-to-last, etc.
    """
    d = _to_date(date)
    if d.isoweekday() > 5:
        return False
    last_day = _last_day_of_month(d.year, d.month)
    biz_count = sum(
        1
        for day in range(d.day, last_day + 1)
        if _date(d.year, d.month, day).isoweekday() <= 5
    )
    return biz_count in occurrences


def evaluate_nth_first_biz_quarter(
    date: Union[str, _date],
    occurrences: list[int],
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the start of the quarter.

    Counts Monday-Friday from the first day of the quarter's first month.
    """
    d = _to_date(date)
    if d.isoweekday() > 5:
        return False
    q = _quarter_of(d)
    first_month, _ = _quarter_months(q)
    quarter_start = _date(d.year, first_month, 1)
    biz_count = 0
    cur = quarter_start
    while cur <= d:
        if cur.isoweekday() <= 5:
            biz_count += 1
        if cur == d:
            break
        from datetime import timedelta
        cur += timedelta(days=1)
    return biz_count in occurrences


def evaluate_nth_last_biz_quarter(
    date: Union[str, _date],
    occurrences: list[int],
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the END of the quarter.

    occurrence=1 → last business day of the quarter.
    """
    d = _to_date(date)
    if d.isoweekday() > 5:
        return False
    q = _quarter_of(d)
    _, last_month = _quarter_months(q)
    last_day_of_q = _last_day_of_month(d.year, last_month)
    quarter_end = _date(d.year, last_month, last_day_of_q)
    biz_count = sum(
        1
        for offset in range((quarter_end - d).days + 1)
        if (d + __import__('datetime').timedelta(days=offset)).isoweekday() <= 5
    )
    return biz_count in occurrences


def evaluate_first_biz_year(
    date: Union[str, _date],
    **kwargs,
) -> bool:
    """True on the first business day (Mon-Fri) of the calendar year."""
    d = _to_date(date)
    if d.isoweekday() > 5:
        return False
    for day in range(1, d.day + 1 if d.month == 1 else 0):
        candidate = _date(d.year, 1, day)
        if candidate.isoweekday() <= 5:
            return candidate == d
    return False


def evaluate_last_biz_year(
    date: Union[str, _date],
    **kwargs,
) -> bool:
    """True on the last business day (Mon-Fri) of the calendar year."""
    d = _to_date(date)
    if d.isoweekday() > 5:
        return False
    # Walk backward from Dec 31 to find the first weekday
    last_day = _date(d.year, 12, 31)
    candidate = last_day
    while candidate.isoweekday() > 5:
        from datetime import timedelta
        candidate -= timedelta(days=1)
    return candidate == d


def evaluate_holiday(
    date: Union[str, _date],
    region: str,
    holiday_set: set[str] | None = None,
    **kwargs,
) -> bool:
    """
    True if the date is a holiday in the given region.

    The agent resolves the holiday set from the graph before calling evaluators:
        holiday_set = {edge.date for edge in pattern.IS_HOLIDAY_ON
                       if edge.region in (region, 'ALL')}
    and passes it as runtime_context['holiday_set'].

    Args:
        date:        Candidate date.
        region:      Region code (e.g. 'US', 'CA').
        holiday_set: Set of ISO date strings pre-fetched by the agent.
    """
    if not holiday_set:
        return False
    d = _to_date(date)
    return d.isoformat() in holiday_set


def evaluate_graph_property(
    date: Union[str, _date],
    nodeName: str,
    propertyName: str,
    **kwargs,
) -> bool:
    """
    Generic evaluator: reads a boolean structural property from any calendar
    hierarchy node (Day, Week, Month, Quarter, Year) for the given date.

    This is a pure-Python computation — no Neo4j round-trip required.  The
    same properties stored on graph nodes during `_load_calendar_layer1` are
    re-derived here from the date, keeping the evaluator self-contained and
    fast.

    Args:
        date:         Candidate date (str YYYY-MM-DD or datetime.date).
        nodeName:     Calendar hierarchy level to inspect.
                      Supported: 'Day' | 'Week' | 'Month' | 'Quarter' | 'Year'
        propertyName: Boolean property name, e.g. 'isFirstOfMonth'.

    Returns:
        bool — True if the property is logically true for this date.

    Supported (nodeName, propertyName) pairs
    -----------------------------------------
    Day
      isFirstOfMonth   — first calendar day of the month
      isLastOfMonth    — last calendar day of the month
      isFirstOfQuarter — first calendar day of the quarter (Jan 1, Apr 1, …)
      isLastOfQuarter  — last calendar day of the quarter (Mar 31, Jun 30, …)
      isFirstOfYear    — January 1st
      isLastOfYear     — December 31st
      isWeekday        — Monday–Friday
      isWeekend        — Saturday or Sunday

    Week (the ISO week that contains this date)
      isFirstWeekOfMonth  — week contains the 1st of the month
      isLastWeekOfMonth   — week contains the last day of the month
      isFirstWeekOfYear   — ISO week 1
      isLastWeekOfYear    — ISO week 52 or 53

    Month
      isFirstOfQuarter    — January, April, July, October
      isLastOfQuarter     — March, June, September, December
      isFirstOfYear       — January
      isLastOfYear        — December

    Quarter
      isFirstOfYear       — Q1 (Jan–Mar)
      isLastOfYear        — Q4 (Oct–Dec)
    """
    d = _to_date(date)
    last_dom = _last_day_of_month(d.year, d.month)
    q = _quarter_of(d)
    _, last_q_month = _quarter_months(q)
    last_day_of_q = _last_day_of_month(d.year, last_q_month)

    # ── Day ──────────────────────────────────────────────────────────────────
    if nodeName == 'Day':
        mapping = {
            'isFirstOfMonth':   d.day == 1,
            'isLastOfMonth':    d.day == last_dom,
            'isFirstOfQuarter': d.month in (1, 4, 7, 10) and d.day == 1,
            'isLastOfQuarter':  d.month in (3, 6, 9, 12) and d.day == last_dom,
            'isFirstOfYear':    d.month == 1 and d.day == 1,
            'isLastOfYear':     d.month == 12 and d.day == 31,
            'isWeekday':        d.isoweekday() <= 5,
            'isWeekend':        d.isoweekday() > 5,
        }
        return bool(mapping.get(propertyName, False))

    # ── Week (ISO week containing d) ─────────────────────────────────────────
    if nodeName == 'Week':
        iso_year, iso_week, _ = d.isocalendar()
        # Days in this ISO week: Mon=d - (d.weekday()) to Sun
        week_start = d - __import__('datetime').timedelta(days=d.weekday())
        week_end   = week_start + __import__('datetime').timedelta(days=6)
        mapping = {
            'isFirstWeekOfMonth': week_start.month == d.month and week_start.day <= 7,
            'isLastWeekOfMonth':  week_end.month == d.month and week_end.day >= last_dom - 6,
            'isFirstWeekOfYear':  iso_week == 1,
            'isLastWeekOfYear':   iso_week >= 52,
        }
        return bool(mapping.get(propertyName, False))

    # ── Month ─────────────────────────────────────────────────────────────────
    if nodeName == 'Month':
        mapping = {
            'isFirstOfQuarter': d.month in (1, 4, 7, 10),
            'isLastOfQuarter':  d.month in (3, 6, 9, 12),
            'isFirstOfYear':    d.month == 1,
            'isLastOfYear':     d.month == 12,
        }
        return bool(mapping.get(propertyName, False))

    # ── Quarter ───────────────────────────────────────────────────────────────
    if nodeName == 'Quarter':
        mapping = {
            'isFirstOfYear': q == 1,
            'isLastOfYear':  q == 4,
        }
        return bool(mapping.get(propertyName, False))

    # ── Year (placeholder for future use) ────────────────────────────────────
    if nodeName == 'Year':
        return False  # no meaningful boolean Year-level properties yet

    return False


def evaluate_named_holiday(
    date: Union[str, _date],
    region: str,
    holidayNames: "list[str]",
    holiday_set: "list[dict] | None" = None,
    **kwargs,
) -> bool:
    """
    True if the date falls on ANY of the named holidays in the given region.

    A single rule can cover multiple holidays so the rule catalog stays compact.
    e.g. RULE_FEDERAL_BANK_HOLIDAYS with holidayNames = ["Christmas Day",
    "New Year's Day", "Independence Day", "Thanksgiving Day"].

    The agent resolves holiday_set from IS_HOLIDAY_ON edges before calling
    evaluators:

        holiday_set = [
            {"date": edge.date, "region": edge.region, "name": edge.name}
            for edge in pattern.IS_HOLIDAY_ON
            if edge.region in (region, 'ALL')
        ]

    Args:
        date:          Candidate date.
        region:        Region code (e.g. 'US', 'CA').
        holidayNames:  List of exact holiday names as stored in IS_HOLIDAY_ON.name.
                       Stored in JobRule.params as:
                         {"holidayNames": ["Christmas Day", "New Year's Day"]}
        holiday_set:   List of dicts pre-fetched by the agent.

    Returns True if the date matches ANY entry whose name is in holidayNames.
    """
    if not holiday_set or not holidayNames:
        return False
    d_str = _to_date(date).isoformat()
    name_set = set(holidayNames)
    for entry in holiday_set:
        if entry.get("region", "") not in (region, "ALL"):
            continue
        if entry.get("date", "") != d_str:
            continue
        if entry.get("name", "") in name_set:
            return True
    return False


def evaluate_specific_date(
    date: Union[str, _date],
    targetDates: "list[str]",
    **kwargs,
) -> bool:
    """
    True if the candidate date exactly matches ANY of the hardcoded dates.

    A single rule can cover multiple one-off exclusions (maintenance windows,
    company events, ad-hoc blackouts) so the rule catalog stays compact.
    e.g. RULE_MAINT_2026 with targetDates = ["2026-03-15", "2026-09-20"].

    Because dates are year-specific, rules using this pattern must be
    reviewed and updated when rolling into a new calendar year.

    Args:
        date:        Candidate date.
        targetDates: List of ISO date strings to match (YYYY-MM-DD).
                     Stored in JobRule.params as:
                       {"targetDates": ["2026-03-15", "2026-09-20"]}

    Returns True if the date matches ANY entry in targetDates.
    """
    d = _to_date(date)
    for raw in (targetDates or []):
        try:
            if d == _date.fromisoformat(str(raw)[:10]):
                return True
        except (ValueError, TypeError):
            continue
    return False


# ---------------------------------------------------------------------------
# Registry — maps CalendarPattern.evaluatorFn → callable
# ---------------------------------------------------------------------------

EVALUATOR_REGISTRY: dict[str, callable] = {
    "nth_dow_month":           evaluate_nth_dow_month,
    "nth_multi_dow_month":     evaluate_nth_multi_dow_month,
    "nth_dom_month":           evaluate_nth_dom_month,
    "nth_first_biz_month":     evaluate_nth_first_biz_month,
    "nth_last_biz_month":      evaluate_nth_last_biz_month,
    "nth_first_biz_quarter":   evaluate_nth_first_biz_quarter,
    "nth_last_biz_quarter":    evaluate_nth_last_biz_quarter,
    "first_biz_year":          evaluate_first_biz_year,
    "last_biz_year":           evaluate_last_biz_year,
    "holiday":                 evaluate_holiday,
    "evaluate_graph_property": evaluate_graph_property,
    "named_holiday":           evaluate_named_holiday,
    "specific_date":           evaluate_specific_date,
}
