from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # Formatted SSN: XXX-XX-XXXX
    re.compile(
        r"\b(?!219-09-9999|078-05-1120)(?!666|000|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b"
    ),
    # Unformatted SSN: XXXXXXXXX
    re.compile(
        r"\b(?!219099999|078051120)(?!666|000|9\d{2})\d{3}(?!00)\d{2}(?!0{4})\d{4}\b"
    ),
]


class SSNFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.SSN, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
