from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # IPv4
    re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    # IPv6 (full)
    re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    # IPv6 compressed
    re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    ),
]


class IPAddressFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.IP_ADDRESS, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
