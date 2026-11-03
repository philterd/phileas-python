# Copyright 2026 Philterd, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Date parsing helpers shared by the SHIFT, TRUNCATE_TO_YEAR and RELATIVE actions."""

from __future__ import annotations

import calendar
import re
from datetime import date, timedelta
from typing import Optional

_MONTH_NAMES = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
_MONTH_MAP = {m.lower(): i + 1 for i, m in enumerate(_MONTH_NAMES)}

_MONTHS = "|".join(_MONTH_NAMES)

_RE_NUMERIC = re.compile(r"(0?[1-9]|1[0-2])([\/\-])(0?[1-9]|[12]\d|3[01])\2((19|20)\d{2})")
_RE_ISO = re.compile(r"((19|20)\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])")
_RE_MONTH_DAY_YEAR = re.compile(
    rf"({_MONTHS})\s+(0?[1-9]|[12]\d|3[01]),?\s+((19|20)\d{{2}})", re.IGNORECASE
)
_RE_DAY_MONTH_YEAR = re.compile(
    rf"(0?[1-9]|[12]\d|3[01])\s+({_MONTHS})\s+((19|20)\d{{2}})", re.IGNORECASE
)


def _parse(token: str) -> Optional[date]:
    """Parses *token* as a date in any supported format, or returns None."""
    try:
        return _parse_strict(token)
    except ValueError:
        # Shaped like a date but not a real one, e.g. 02/31/2020.
        return None


def _parse_strict(token: str) -> Optional[date]:
    m = _RE_NUMERIC.fullmatch(token)
    if m:
        return date(int(m.group(4)), int(m.group(1)), int(m.group(3)))
    m = _RE_ISO.fullmatch(token)
    if m:
        return date(int(m.group(1)), int(m.group(3)), int(m.group(4)))
    m = _RE_MONTH_DAY_YEAR.fullmatch(token)
    if m:
        return date(int(m.group(3)), _MONTH_MAP[m.group(1).lower()], int(m.group(2)))
    m = _RE_DAY_MONTH_YEAR.fullmatch(token)
    if m:
        return date(int(m.group(3)), _MONTH_MAP[m.group(2).lower()], int(m.group(1)))
    return None


def _shift_value(dt: date, years: int, months: int, days: int) -> date:
    total_months = dt.month + months
    new_year = dt.year + years + (total_months - 1) // 12
    new_month = (total_months - 1) % 12 + 1
    max_day = calendar.monthrange(new_year, new_month)[1]
    shifted = date(new_year, new_month, min(dt.day, max_day))
    return shifted + timedelta(days=days)


def shift_date(token: str, years: int, months: int, days: int) -> Optional[str]:
    """Shifts a recognized date by the offsets, preserving its input format.

    Output dates are always zero-padded (e.g. ``01/05/2020``). Returns None for
    unrecognized input.
    """
    try:
        return _shift_strict(token, years, months, days)
    except (ValueError, OverflowError):
        return None


def _shift_strict(token: str, years: int, months: int, days: int) -> Optional[str]:
    m = _RE_NUMERIC.fullmatch(token)
    if m:
        sep = m.group(2)
        dt = date(int(m.group(4)), int(m.group(1)), int(m.group(3)))
        shifted = _shift_value(dt, years, months, days)
        return f"{shifted.month:02d}{sep}{shifted.day:02d}{sep}{shifted.year}"

    m = _RE_ISO.fullmatch(token)
    if m:
        dt = date(int(m.group(1)), int(m.group(3)), int(m.group(4)))
        return _shift_value(dt, years, months, days).isoformat()

    m = _RE_MONTH_DAY_YEAR.fullmatch(token)
    if m:
        dt = date(int(m.group(3)), _MONTH_MAP[m.group(1).lower()], int(m.group(2)))
        shifted = _shift_value(dt, years, months, days)
        comma = "," if "," in token else ""
        return f"{_MONTH_NAMES[shifted.month - 1]} {shifted.day}{comma} {shifted.year}"

    m = _RE_DAY_MONTH_YEAR.fullmatch(token)
    if m:
        dt = date(int(m.group(3)), _MONTH_MAP[m.group(2).lower()], int(m.group(1)))
        shifted = _shift_value(dt, years, months, days)
        return f"{shifted.day} {_MONTH_NAMES[shifted.month - 1]} {shifted.year}"

    return None


def truncate_to_year(token: str) -> Optional[str]:
    """Returns the four-digit year of a recognized date, else None."""
    dt = _parse(token)
    return str(dt.year) if dt is not None else None


def _period(start: date, end: date) -> tuple:
    """(years, months, days) from *start* to *end*, as java.time.Period.between.

    Every component is negative when *end* is before *start*.
    """
    total_months = (end.year * 12 + end.month) - (start.year * 12 + start.month)
    days = end.day - start.day
    if total_months > 0 and days < 0:
        total_months -= 1
        days = (end - _shift_value(start, 0, total_months, 0)).days
    elif total_months < 0 and days > 0:
        total_months += 1
        days -= calendar.monthrange(end.year, end.month)[1]
    sign = -1 if total_months < 0 else 1
    years, months = divmod(abs(total_months), 12)
    return sign * years, sign * months, days


def _readable(years: int, months: int, days: int) -> str:
    # Half a month or more rounds up. Future periods have days <= 0, so they
    # never round, as in the Java engine.
    years, months = abs(years), abs(months)
    if days >= 15:
        months += 1
    return f"{years} years {months} months" if years else f"{months} months"


def relative_date(token: str, today: date, future_dates: bool) -> Optional[str]:
    """Expresses a recognized date relative to *today*, e.g. ``3 months ago``.

    A future date becomes ``in 3 months`` when *future_dates* is set. Returns
    None for unrecognized input or a future date that is not allowed.
    """
    dt = _parse(token)
    if dt is None:
        return None
    period = _period(dt, today)
    if dt <= today:
        return f"{_readable(*period)} ago"
    if future_dates:
        return f"in {_readable(*period)}"
    return None
