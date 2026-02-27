from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    re.compile(
        r"\b\d{1,5}\s+(?:[A-Za-z0-9#.,\-]+\s+){1,4}"
        r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Circle|Cir|Terrace|Ter|Trail|Trl)\b",
        re.IGNORECASE,
    ),
]


class StreetAddressFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.STREET_ADDRESS, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
