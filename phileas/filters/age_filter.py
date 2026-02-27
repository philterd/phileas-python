from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    re.compile(r"\b[0-9.]+[\s]*(year|years|yrs|yr|yo)(\.?)(\s)*(old)?\b", re.IGNORECASE),
    re.compile(r"\b(age)(d)?(\s*:?\s*)[0-9.]+\b", re.IGNORECASE),
    re.compile(r"\b[0-9.]+[-]*(year|years|yrs|yr|yo)(\.?)(-)*(old)?\b", re.IGNORECASE),
    re.compile(r"\b([0-9]{1,3}) (y\/o)\b", re.IGNORECASE),
]


class AgeFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.AGE, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
