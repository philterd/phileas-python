from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # 5+4 zip code
    re.compile(r"\b\d{5}-\d{4}\b"),
    # 5-digit zip code
    re.compile(r"\b\d{5}\b"),
]


class ZipCodeFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.ZIP_CODE, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
