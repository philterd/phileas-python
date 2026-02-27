from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # Legacy P2PKH addresses (1...)
    re.compile(r"\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    # P2SH addresses (3...)
    re.compile(r"\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    # Bech32 addresses (bc1...)
    re.compile(r"\bbc1[a-z0-9]{39,59}\b"),
]


class BitcoinAddressFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.BITCOIN_ADDRESS, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
