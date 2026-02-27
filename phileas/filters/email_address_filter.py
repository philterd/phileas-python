from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    re.compile(r"\b[\w.\-]+?@(?:[a-zA-Z\d\-]+?\.)+(?:[a-zA-Z\d]{2,4})+\b"),
]


class EmailAddressFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.EMAIL_ADDRESS, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
