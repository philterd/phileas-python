from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # US Passport: letter followed by 8 digits
    re.compile(r"\b[A-Z]\d{8}\b"),
    # Some US passports: 9 digits
    re.compile(r"\b\d{9}\b"),
]


class PassportNumberFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.PASSPORT_NUMBER, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
