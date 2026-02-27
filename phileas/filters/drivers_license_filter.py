from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # Generic US driver's license: letter(s) followed by digits
    re.compile(r"\b[A-Z]{1,2}\d{5,9}\b"),
    # All-digit formats (many states)
    re.compile(r"\b\d{7,9}\b"),
]


class DriversLicenseFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.DRIVERS_LICENSE, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
