# Copyright 2026 Philterd, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
