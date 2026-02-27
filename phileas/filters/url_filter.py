from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    re.compile(
        r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/(?:[-\w.~!$&'()*+,;=:@%]|(?:%[\da-fA-F]{2}))*)*(?:\?(?:[-\w.~!$&'()*+,;=:@/?%]|(?:%[\da-fA-F]{2}))*)?(?:#(?:[-\w.~!$&'()*+,;=:@/?%]|(?:%[\da-fA-F]{2}))*)?",
        re.IGNORECASE,
    ),
]


class URLFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.URL, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
