from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    re.compile(
        r"\$\s?[0-9]+(?:,[0-9]+)*(?:\.[0-9]+)?(?:\s?(?:million|billion|trillion|thousand))?",
        re.IGNORECASE,
    ),
]


class CurrencyFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.CURRENCY, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
