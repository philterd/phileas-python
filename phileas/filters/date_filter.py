from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # MM/DD/YYYY or MM-DD-YYYY
    re.compile(r"\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b"),
    # YYYY-MM-DD (ISO 8601)
    re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
    # Month DD, YYYY
    re.compile(
        r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+(?:0?[1-9]|[12]\d|3[01]),?\s+(?:19|20)\d{2}\b",
        re.IGNORECASE,
    ),
    # DD Month YYYY
    re.compile(
        r"\b(?:0?[1-9]|[12]\d|3[01])\s+"
        r"(?:January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+(?:19|20)\d{2}\b",
        re.IGNORECASE,
    ),
]


class DateFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.DATE, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
