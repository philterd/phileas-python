from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # ABA routing number: 9 digits where first two digits are 01-12 or 21-32
    re.compile(r"\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2])\d{7}\b"),
]


class BankRoutingNumberFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.BANK_ROUTING_NUMBER, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
