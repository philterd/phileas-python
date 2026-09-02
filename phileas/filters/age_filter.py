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


# Separator between an "age"/"aged" keyword and its value, e.g. "Age: 47", "Age - 47".
# Matches the set Phileas (Java) uses.
_AGE_SEPARATOR = r"\s*(?:[:=-]\s*)?"


# A plausible age after an "age"/"aged" keyword: 0 to 125, optionally fractional and
# zero-padded ("AGE 045"). Only the keyword pattern needs the bound -- without it "form AGE
# 2024" reads as an age; the "y/o" and "years old" forms carry their own evidence.
_AGE_VALUE = r"0*(?:1[01]\d|12[0-5]|\d{1,2})(?:\.\d+)?"


# Spelled-out numbers covering a realistic age range, 0 to about 119. Mirrors Java.
_ONES = "one|two|three|four|five|six|seven|eight|nine"
_TEENS = "ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen"
_TENS = "twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety"
_ONE_TO_NINETY_NINE = rf"(?:(?:{_TENS})(?:[\s-](?:{_ONES}))?|{_TEENS}|{_ONES}|zero)"
# "one|a" is required: without it "two hundred years old" matched from "hundred".
_NUMBER_WORD = (
    rf"(?:(?:one|a)\s+hundred(?:\s+(?:and\s+)?{_ONE_TO_NINETY_NINE})?"
    rf"|{_ONE_TO_NINETY_NINE})"
)

# "five years ago" counts elapsed time, not an age.
_NOT_AGO = r"(?!\s*ago\b)"


_PATTERNS = [
    re.compile(
        r"\b[0-9.]+[\s]*(year|years|yrs|yr|yo)(\.?)(\s)*(old)?\b" + _NOT_AGO, re.IGNORECASE
    ),
    re.compile(r"\b(age)(d)?" + _AGE_SEPARATOR + _AGE_VALUE + r"\b", re.IGNORECASE),
    re.compile(
        r"\b[0-9.]+[-]*(year|years|yrs|yr|yo)(\.?)(-)*(old)?\b" + _NOT_AGO, re.IGNORECASE
    ),
    re.compile(r"\b([0-9]{1,3}) (y\/o)\b", re.IGNORECASE),
    # Spelled out: "thirty-five years old", "thirty-five-year-old".
    re.compile(
        rf"\b({_NUMBER_WORD})[\s-]*(year|years|yrs|yr|yo)(\.?)[\s-]*(old)?\b" + _NOT_AGO,
        re.IGNORECASE,
    ),
    # Spelled out after the keyword: "age thirty-five", "aged forty-two".
    re.compile(
        r"\b(age)(d)?" + _AGE_SEPARATOR + rf"({_NUMBER_WORD})\b", re.IGNORECASE
    ),
]


class AgeFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.AGE, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        return self._detect_patterns(_PATTERNS, text, context)
