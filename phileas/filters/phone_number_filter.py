from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # (NXX) NXX-XXXX
    re.compile(r"\b\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b"),
    # NXX-NXX-XXXX
    re.compile(r"\b\d{3}[\-\.]\d{3}[\-\.]\d{4}\b"),
    # +1 NXX NXX XXXX or +1-NXX-NXX-XXXX
    re.compile(r"\+1[\s\-]\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}"),
    # 10-digit no separator
    re.compile(r"\b[2-9]\d{2}[2-9]\d{6}\b"),
]


class PhoneNumberFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.PHONE_NUMBER, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
