from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # Visa
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
    # MasterCard
    re.compile(r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b"),
    # American Express
    re.compile(r"\b3[47][0-9]{13}\b"),
    # Discover
    re.compile(r"\b6(?:011|5[0-9]{2})[0-9]{12}\b"),
    # Diners Club
    re.compile(r"\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b"),
    # JCB
    re.compile(r"\b(?:2131|1800|35\d{3})\d{11}\b"),
]


class CreditCardFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.CREDIT_CARD, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
