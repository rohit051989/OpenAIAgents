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
    region  (str)                              — e.g. 'US', 'CA', 'UK'

rule.params (configParams) are baked in by the rule author and vary per pattern.

All functions accept **kwargs so that extra context keys never cause TypeErrors.

Parameter design
----------------
weekOccurrences  — used in DOW patterns: which occurrence of the weekday within
                   the month (1 = first, 2 = second, … 5 = fifth).  A list so
                   multiple occurrences can be matched by one rule.

months           — used in month-scoped patterns: which months to apply to
                   (1=Jan … 12=Dec).  Empty list / null means ALL months.

quarters         — used in quarter-scoped patterns: which quarters (1-4).
                   Empty list / null means ALL quarters.

bizDayFromStart  — list of BD ordinals from the START of the period.
                   [1] = first BD, [4] = 4th BD, [1,2] = 1st or 2nd BD.

bizDayFromEnd    — list of BD ordinals from the END of the period.
                   [1] = last BD, [2] = 2nd-to-last BD.

daysOfMonth      — list of calendar day numbers for DOM pattern (e.g. [1, 15]).
"""

from __future__ import annotations

import calendar as _cal
from datetime import date as _date, timedelta as _td
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


def _matches_months(d: _date, months: list) -> bool:
    """True when months is empty/null (all months) or d.month is in the list."""
    if not months:
        return True
    return d.month in months


def _matches_quarters(d: _date, quarters: list) -> bool:
    """True when quarters is empty/null (all quarters) or d's quarter is in the list."""
    if not quarters:
        return True
    return _quarter_of(d) in quarters


def _holiday_region_match(entry_region: str, rule_region: str) -> bool:
    """
    Region matching policy for holiday evaluators.

    - rule_region='US' matches US + ALL
    - rule_region='CA' matches CA + ALL
    - rule_region='ALL' matches ALL only
    """
    er = str(entry_region or "").strip().upper()
    rr = str(rule_region or "").strip().upper()
    if rr == "ALL":
        return er == "ALL"
    return er in (rr, "ALL")


# ---------------------------------------------------------------------------
# Core evaluators
# ---------------------------------------------------------------------------

def evaluate_nth_dow_month(
    date: Union[str, _date],
    dayOfWeek: int,
    weekOccurrences: list[int],
    months: list[int] | None = None,
    **kwargs,
) -> bool:
    """
    Match the Nth occurrence(s) of a specific weekday within the month,
    optionally restricted to specific months.

    Args:
        date:            Candidate date.
        dayOfWeek:       ISO weekday (1=Mon … 7=Sun).
        weekOccurrences: Which occurrence(s) of that weekday in the month.
                         e.g. [1] = first, [1,2] = first or second occurrence.
        months:          Restrict to these month numbers (1-12).
                         Empty list / null = all months.
    """
    d = _to_date(date)
    if not _matches_months(d, months or []):
        return False
    if d.isoweekday() != dayOfWeek:
        return False
    occurrence = (d.day - 1) // 7 + 1
    return occurrence in weekOccurrences


def evaluate_nth_multi_dow_month(
    date: Union[str, _date],
    daysOfWeek: list[int],
    weekOccurrences: list[int],
    months: list[int] | None = None,
    **kwargs,
) -> bool:
    """
    Match any of the given weekday(s) on their Nth occurrence within the month,
    optionally restricted to specific months.

    Args:
        date:            Candidate date.
        daysOfWeek:      ISO weekdays to match (e.g. [1,2,3,4,5] = Mon–Fri).
        weekOccurrences: Which occurrence(s) of those days in the month.
                         e.g. [1,2,3,4,5] = every occurrence across all weeks.
        months:          Restrict to these months (1-12). Empty = all months.
    """
    d = _to_date(date)
    if not _matches_months(d, months or []):
        return False
    if d.isoweekday() not in daysOfWeek:
        return False
    # Which occurrence of THIS specific weekday within the month?
    # e.g. if d is the 3rd Tuesday, occurrence = 3.
    # Formula is the same as nth_dow_month: (day - 1) // 7 + 1
    occurrence = (d.day - 1) // 7 + 1
    return occurrence in weekOccurrences


def evaluate_nth_dom(
    date: Union[str, _date],
    daysOfMonth: list[int],
    months: list[int] | None = None,
    **kwargs,
) -> bool:
    """
    Match specific calendar day number(s), optionally restricted to specific months.

    Args:
        date:        Candidate date.
        daysOfMonth: Calendar day numbers to match (e.g. [1, 15] = 1st and 15th).
        months:      Restrict to these months (1-12). Empty = all months.
    """
    d = _to_date(date)
    if not _matches_months(d, months or []):
        return False
    return d.day in daysOfMonth


def evaluate_nth_first_biz_month(
    date: Union[str, _date],
    bizDayFromStart: list[int],
    months: list[int] | None = None,
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the START of the month.

    Args:
        date:            Candidate date.
        bizDayFromStart: Which BD ordinal(s) from start to match.
                         [1] = 1st BD, [4] = 4th BD, [1,2] = 1st or 2nd BD.
        months:          Restrict to these months (1-12). Empty = all months.

    Business day = Mon–Fri. To exclude holidays, add a DENIES rule on HOLIDAY.
    """
    d = _to_date(date)
    if not _matches_months(d, months or []):
        return False
    if d.isoweekday() > 5:
        return False
    biz_count = sum(
        1
        for day in range(1, d.day + 1)
        if _date(d.year, d.month, day).isoweekday() <= 5
    )
    return biz_count in bizDayFromStart


def evaluate_nth_last_biz_month(
    date: Union[str, _date],
    bizDayFromEnd: list[int],
    months: list[int] | None = None,
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the END of the month.

    Args:
        date:          Candidate date.
        bizDayFromEnd: Which BD ordinal(s) from end to match.
                       [1] = last BD, [2] = 2nd-to-last BD.
        months:        Restrict to these months (1-12). Empty = all months.
    """
    d = _to_date(date)
    if not _matches_months(d, months or []):
        return False
    if d.isoweekday() > 5:
        return False
    last_day = _last_day_of_month(d.year, d.month)
    biz_count = sum(
        1
        for day in range(d.day, last_day + 1)
        if _date(d.year, d.month, day).isoweekday() <= 5
    )
    return biz_count in bizDayFromEnd


def evaluate_nth_first_biz_quarter(
    date: Union[str, _date],
    bizDayFromStart: list[int],
    quarters: list[int] | None = None,
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the START of the quarter.

    Args:
        date:            Candidate date.
        bizDayFromStart: Which BD ordinal(s) from start to match. [1] = first BD.
        quarters:        Restrict to these quarters (1-4). Empty = all quarters.
    """
    d = _to_date(date)
    if not _matches_quarters(d, quarters or []):
        return False
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
        cur += _td(days=1)
    return biz_count in bizDayFromStart


def evaluate_nth_last_biz_quarter(
    date: Union[str, _date],
    bizDayFromEnd: list[int],
    quarters: list[int] | None = None,
    **kwargs,
) -> bool:
    """
    Match the Nth business day(s) from the END of the quarter.

    Args:
        date:          Candidate date.
        bizDayFromEnd: Which BD ordinal(s) from end to match. [1] = last BD.
        quarters:      Restrict to these quarters (1-4). Empty = all quarters.
    """
    d = _to_date(date)
    if not _matches_quarters(d, quarters or []):
        return False
    if d.isoweekday() > 5:
        return False
    q = _quarter_of(d)
    _, last_month = _quarter_months(q)
    last_day_of_q = _last_day_of_month(d.year, last_month)
    quarter_end = _date(d.year, last_month, last_day_of_q)
    biz_count = 0
    cur = d
    while cur <= quarter_end:
        if cur.isoweekday() <= 5:
            biz_count += 1
        cur += _td(days=1)
    return biz_count in bizDayFromEnd


def evaluate_first_biz_year(
    date: Union[str, _date],
    **kwargs,
) -> bool:
    """True on the first business day (Mon-Fri) of the calendar year."""
    d = _to_date(date)
    if d.isoweekday() > 5:
        return False
    cur = _date(d.year, 1, 1)
    while cur.isoweekday() > 5:
        cur += _td(days=1)
    return cur == d


def evaluate_last_biz_year(
    date: Union[str, _date],
    **kwargs,
) -> bool:
    """True on the last business day (Mon-Fri) of the calendar year."""
    d = _to_date(date)
    if d.isoweekday() > 5:
        return False
    cur = _date(d.year, 12, 31)
    while cur.isoweekday() > 5:
        cur -= _td(days=1)
    return cur == d


def evaluate_holiday(
    date: Union[str, _date],
    region: str,
    holiday_set: set[str] | list[dict] | None = None,
    **kwargs,
) -> bool:
    """
    True if the date is a holiday in the given region.

    Holiday rows are primarily region-specific. Optionally, global closures can
    be modeled using region='ALL' rows.

    The agent may resolve holiday data in either of these shapes before calling
    evaluators:

        holiday_set = {edge.date for edge in pattern.IS_HOLIDAY_ON
                   if edge.region in (region, 'ALL')}

    or:

        holiday_set = [
            {"date": edge.date, "region": edge.region, "name": edge.name}
            for edge in pattern.IS_HOLIDAY_ON
            if edge.region in (region, 'ALL')
        ]

    Args:
        date:        Candidate date.
        region:      Region code (e.g. 'US', 'CA', 'UK', 'ALL').
        holiday_set: Either a set of ISO date strings or a list of dict rows
                     pre-fetched by the agent.
    """
    if not holiday_set:
        return False
    d = _to_date(date)
    d_str = d.isoformat()
    if isinstance(holiday_set, set):
        return d_str in holiday_set
    for entry in holiday_set:
        if not _holiday_region_match(entry.get("region", ""), region):
            continue
        if entry.get("date", "") != d_str:
            continue
        return True
    return False


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
        _, iso_week, _ = d.isocalendar()
        # Days in this ISO week: Mon=d - (d.weekday()) to Sun
        week_start = d - _td(days=d.weekday())
        week_end = week_start + _td(days=6)
        first_dom_date = _date(d.year, d.month, 1)
        last_dom_date = _date(d.year, d.month, last_dom)
        mapping = {
            'isFirstWeekOfMonth': week_start <= first_dom_date <= week_end,
            'isLastWeekOfMonth': week_start <= last_dom_date <= week_end,
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
    holidayDates: "list[str]",
    **kwargs,
) -> bool:
    """
    True if the date falls on ANY of the named dates

    A single rule can cover multiple holidays so the rule catalog stays compact.
    e.g. RULE_FEDERAL_BANK_HOLIDAYS with holidayDates = ["2026-12-25",
    "2027-01-01", "2027-07-04", "2027-11-25"].

    Args:
        date:          Candidate date.
        holidayDates:  List of exact holiday dates as stored in IS_HOLIDAY_ON.date.
                       Stored in BusinessCalendar.params as:
                         {"holidayDates": ["2026-12-25", "2027-01-01"]}

    Returns True if the date matches ANY entry in holidayDates.
    """
    if not holidayDates:
        return False
    d_str = _to_date(date).isoformat()
    date_set = set(holidayDates)
    return d_str in date_set


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
                     Stored in BusinessCalendar.params as:
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
    # DOW / calendar-day patterns
    "nth_dow_month":           evaluate_nth_dow_month,       # params: dayOfWeek, weekOccurrences, months?
    "nth_multi_dow_month":     evaluate_nth_multi_dow_month, # params: daysOfWeek, weekOccurrences, months?
    "nth_dom":                 evaluate_nth_dom,             # params: daysOfMonth, months?
    # Business-day month patterns
    "nth_first_biz_month":     evaluate_nth_first_biz_month, # params: bizDayFromStart, months?
    "nth_last_biz_month":      evaluate_nth_last_biz_month,  # params: bizDayFromEnd,   months?
    # Business-day quarter patterns
    "nth_first_biz_quarter":   evaluate_nth_first_biz_quarter, # params: bizDayFromStart, quarters?
    "nth_last_biz_quarter":    evaluate_nth_last_biz_quarter,  # params: bizDayFromEnd,   quarters?
    # Business-day year patterns
    "first_biz_year":          evaluate_first_biz_year,      # params: (none)
    "last_biz_year":           evaluate_last_biz_year,       # params: (none)
    # Holiday / structural patterns
    "holiday":                 evaluate_holiday,              # runtime: date, region, holiday_set
    "evaluate_graph_property": evaluate_graph_property,      # params: nodeName, propertyName
    "named_holiday":           evaluate_named_holiday,        # params: holidayDates
    "specific_date":           evaluate_specific_date,        # params: targetDates
}
