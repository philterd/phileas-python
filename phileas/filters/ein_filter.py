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
"""
US Employer Identification Number (EIN), the federal tax ID.

Only the hyphenated ``NN-NNNNNNN`` form is matched; a bare nine-digit run is left
to SSN. The hyphen position is the distinction: EIN after the second digit, SSN
after the third and fifth.
"""

from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


_PATTERNS = [
    # Canonical EIN: NN-NNNNNNN.
    re.compile(r"\b\d{2}-\d{7}\b"),
]


# Prefixes the IRS issues, per "How EINs are Assigned and Valid EIN Prefixes".
# Read only when ``onlyValidPrefixes`` is on.
VALID_PREFIXES = frozenset(
    {
        "01", "02", "03", "04", "05", "06",
        "10", "11", "12", "13", "14", "15", "16",
        "20", "21", "22", "23", "24", "25", "26", "27",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
        "40", "41", "42", "43", "44", "45", "46", "47", "48",
        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
        "60", "61", "62", "63", "64", "65", "66", "67", "68",
        "71", "72", "73", "74", "75", "76", "77",
        "80", "81", "82", "83", "84", "85", "86", "87", "88",
        "90", "91", "92", "93", "94", "95", "98", "99",
    }
)


class EINFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.EIN, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        spans = self._detect_patterns(_PATTERNS, text, context)
        # A per-filter option on the policy node.
        if not self.config.get("onlyValidPrefixes", False):
            return spans
        return [s for s in spans if s.text[:2] in VALID_PREFIXES]
