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


# A month name, spelled out or abbreviated to three letters (Sept for September too), with an
# optional period after it. Whitespace must follow, so a word that only starts with a month, such
# as Marble or Septic, is not read as one.
_MONTH = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?"
    r"|aug(?:ust)?|sep(?:tember|t)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?"
)

_PATTERNS = [
    # MM/DD/YYYY or MM-DD-YYYY
    re.compile(r"\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b"),
    # YYYY-MM-DD (ISO 8601)
    re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
    # Month DD, YYYY
    re.compile(
        rf"\b{_MONTH}\s+(?:0?[1-9]|[12]\d|3[01]),?\s+(?:19|20)\d{{2}}\b",
        re.IGNORECASE,
    ),
    # DD Month YYYY
    re.compile(
        rf"\b(?:0?[1-9]|[12]\d|3[01])\s+{_MONTH}\s+(?:19|20)\d{{2}}\b",
        re.IGNORECASE,
    ),
]


class DateFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.DATE, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        return self._detect_patterns(_PATTERNS, text, context)
