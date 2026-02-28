from __future__ import annotations

import calendar
import hashlib
import re
from datetime import date, timedelta


def _random_replace(filter_type: str, token: str) -> str:
    """Delegate to the anonymization service for the given filter type."""
    from phileas.services.anonymization import get_anonymization_service
    service = get_anonymization_service(filter_type)
    if service is not None:
        return service.anonymize(token)
    # Fallback: return the token unchanged if no service is registered
    return token


_MONTH_NAMES = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
_MONTH_MAP = {m.lower(): i + 1 for i, m in enumerate(_MONTH_NAMES)}


def _shift_date_value(dt: date, years: int, months: int, days: int) -> date:
    """Return *dt* shifted by the given years, months, and days."""
    total_months = dt.month + months
    new_year = dt.year + years + (total_months - 1) // 12
    new_month = (total_months - 1) % 12 + 1
    max_day = calendar.monthrange(new_year, new_month)[1]
    shifted = date(new_year, new_month, min(dt.day, max_day))
    return shifted + timedelta(days=days)


def _parse_and_shift_date(token: str, years: int, months: int, days: int) -> str:
    """Parse *token* as a date, shift it, and return a string in the same format.

    Output dates are always zero-padded (e.g. ``01/05/2020``) regardless of
    whether the original input used leading zeros.
    """
    # MM/DD/YYYY or MM-DD-YYYY (separator captured in group 2)
    m = re.fullmatch(r"(0?[1-9]|1[0-2])([\/\-])(0?[1-9]|[12]\d|3[01])\2((19|20)\d{2})", token)
    if m:
        sep = m.group(2)
        dt = date(int(m.group(4)), int(m.group(1)), int(m.group(3)))
        shifted = _shift_date_value(dt, years, months, days)
        return f"{shifted.month:02d}{sep}{shifted.day:02d}{sep}{shifted.year}"

    # YYYY-MM-DD (ISO 8601)
    m = re.fullmatch(r"((19|20)\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])", token)
    if m:
        dt = date(int(m.group(1)), int(m.group(3)), int(m.group(4)))
        shifted = _shift_date_value(dt, years, months, days)
        return shifted.isoformat()

    # Month DD, YYYY  (e.g. "January 15, 1990")
    m = re.fullmatch(
        r"(January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+(0?[1-9]|[12]\d|3[01]),?\s+((19|20)\d{2})",
        token,
        re.IGNORECASE,
    )
    if m:
        month_num = _MONTH_MAP[m.group(1).lower()]
        dt = date(int(m.group(3)), month_num, int(m.group(2)))
        shifted = _shift_date_value(dt, years, months, days)
        comma = "," if "," in token else ""
        return f"{_MONTH_NAMES[shifted.month - 1]} {shifted.day}{comma} {shifted.year}"

    # DD Month YYYY  (e.g. "15 January 1990")
    m = re.fullmatch(
        r"(0?[1-9]|[12]\d|3[01])\s+"
        r"(January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+((19|20)\d{2})",
        token,
        re.IGNORECASE,
    )
    if m:
        month_num = _MONTH_MAP[m.group(2).lower()]
        dt = date(int(m.group(3)), month_num, int(m.group(1)))
        shifted = _shift_date_value(dt, years, months, days)
        return f"{shifted.day} {_MONTH_NAMES[shifted.month - 1]} {shifted.year}"

    # Unrecognized format – return token unchanged
    return token


class FilterStrategy:
    REDACT = "REDACT"
    RANDOM_REPLACE = "RANDOM_REPLACE"
    STATIC_REPLACE = "STATIC_REPLACE"
    CRYPTO_REPLACE = "CRYPTO_REPLACE"
    HASH_SHA256_REPLACE = "HASH_SHA256_REPLACE"
    LAST_4 = "LAST_4"
    MASK = "MASK"
    SAME = "SAME"
    TRUNCATE = "TRUNCATE"
    ABBREVIATE = "ABBREVIATE"
    SHIFT_DATE = "SHIFT_DATE"

    DEFAULT_REDACTION_FORMAT = "{{{REDACTED-%t}}}"

    def __init__(
        self,
        strategy: str = "REDACT",
        redaction_format: str = "{{{REDACTED-%t}}}",
        static_replacement: str = "",
        mask_character: str = "*",
        mask_length: str = "SAME",
        condition: str = "",
        shift_years: int = 0,
        shift_months: int = 0,
        shift_days: int = 0,
    ):
        self.strategy = strategy
        self.redaction_format = redaction_format
        self.static_replacement = static_replacement
        self.mask_character = mask_character
        self.mask_length = mask_length
        self.condition = condition
        self.shift_years = shift_years
        self.shift_months = shift_months
        self.shift_days = shift_days

    def get_replacement(self, filter_type: str, token: str) -> str:
        """Return the replacement value for a token based on the strategy."""
        if self.strategy == FilterStrategy.REDACT:
            return self.redaction_format.replace("%t", filter_type)
        elif self.strategy == FilterStrategy.MASK:
            return self.mask_character * len(token)
        elif self.strategy == FilterStrategy.STATIC_REPLACE:
            return self.static_replacement
        elif self.strategy == FilterStrategy.HASH_SHA256_REPLACE:
            return hashlib.sha256(token.encode()).hexdigest()
        elif self.strategy == FilterStrategy.LAST_4:
            return "*" * (len(token) - 4) + token[-4:] if len(token) > 4 else token
        elif self.strategy == FilterStrategy.SAME:
            return token
        elif self.strategy == FilterStrategy.TRUNCATE:
            return token[:4] if len(token) > 4 else token
        elif self.strategy == FilterStrategy.ABBREVIATE:
            words = token.split()
            return "".join(w[0].upper() for w in words if w)
        elif self.strategy == FilterStrategy.RANDOM_REPLACE:
            return _random_replace(filter_type, token)
        elif self.strategy == FilterStrategy.SHIFT_DATE:
            return _parse_and_shift_date(token, self.shift_years, self.shift_months, self.shift_days)
        else:
            return self.redaction_format.replace("%t", filter_type)

    @classmethod
    def from_dict(cls, data: dict) -> "FilterStrategy":
        return cls(
            strategy=data.get("strategy", "REDACT"),
            redaction_format=data.get("redactionFormat", "{{{REDACTED-%t}}}"),
            static_replacement=data.get("staticReplacement", ""),
            mask_character=data.get("maskCharacter", "*"),
            mask_length=data.get("maskLength", "SAME"),
            condition=data.get("condition", ""),
            shift_years=data.get("shiftYears", 0),
            shift_months=data.get("shiftMonths", 0),
            shift_days=data.get("shiftDays", 0),
        )

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "redactionFormat": self.redaction_format,
            "staticReplacement": self.static_replacement,
            "maskCharacter": self.mask_character,
            "maskLength": self.mask_length,
            "condition": self.condition,
            "shiftYears": self.shift_years,
            "shiftMonths": self.shift_months,
            "shiftDays": self.shift_days,
        }
