from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
]


class VINFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.VIN, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
