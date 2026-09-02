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


# A plausible age following an "age"/"aged" keyword: 0 to 125, with an optional fractional
# part so "age 39.5" still matches. Without a bound the keyword alone is enough to redact any
# number after it, which caught "form AGE 2024" and "Bronze Age 1200". The ceiling sits well
# past a typical lifespan on purpose -- the job here is only to reject values that cannot be
# an age, so a genuine "Age: 130" is a knowingly accepted loss.
#
# This applies to the keyword pattern alone. The "y/o" and "years old" forms carry their own
# evidence that a number is an age, so they stay unbounded.
#
# Leading zeros are allowed because fixed-width record exports zero-pad the field ("AGE 045").
# They are stripped before the bound is read, so "age 0126" is still rejected.
_AGE_VALUE = r"0*(?:1[01]\d|12[0-5]|\d{1,2})(?:\.\d+)?"


_PATTERNS = [
    re.compile(r"\b[0-9.]+[\s]*(year|years|yrs|yr|yo)(\.?)(\s)*(old)?\b", re.IGNORECASE),
    re.compile(r"\b(age)(d)?" + _AGE_SEPARATOR + _AGE_VALUE + r"\b", re.IGNORECASE),
    re.compile(r"\b[0-9.]+[-]*(year|years|yrs|yr|yo)(\.?)(-)*(old)?\b", re.IGNORECASE),
    re.compile(r"\b([0-9]{1,3}) (y\/o)\b", re.IGNORECASE),
]


class AgeFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.AGE, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        return self._detect_patterns(_PATTERNS, text, context)
