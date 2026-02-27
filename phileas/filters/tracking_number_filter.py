from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # UPS: 1Z followed by 16 alphanumeric characters
    re.compile(r"\b1Z[A-Z0-9]{16}\b", re.IGNORECASE),
    # FedEx: 12 or 15 digit numbers
    re.compile(r"\b(?:\d{12}|\d{15})\b"),
    # USPS: 20 or 22 digit numbers, or various formats
    re.compile(r"\b(?:92|93|94|95)\d{20}\b"),
    re.compile(r"\b[A-Z]{2}\d{9}US\b"),
]


class TrackingNumberFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.TRACKING_NUMBER, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
