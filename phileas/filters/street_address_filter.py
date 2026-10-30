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


# The parts are joined by spaces and tabs only, as in the Java filter, so a match does not
# run from one line into the next (a ZIP code at the end of a line and "Dear Dr." on the
# next are not an address).
_PATTERNS = [
    re.compile(
        r"\b\d{1,5}[ \t]+(?:[A-Za-z0-9#.,\-]+[ \t]+){1,4}"
        r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Circle|Cir|Terrace|Ter|Trail|Trl)\b",
        re.IGNORECASE,
    ),
]


class StreetAddressFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.STREET_ADDRESS, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        return self._detect_patterns(_PATTERNS, text, context)
