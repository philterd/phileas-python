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
Phone numbers, detected with libphonenumber (the ``phonenumbers`` package).

A ``+``-prefixed number is found whatever the region; a bare national-format
number is found for the default region only. Mirrors the Java filter's scanner,
region, leniency, and confidence tiers.
"""

from __future__ import annotations

import re
from typing import List

from phonenumbers import Leniency, PhoneNumberMatcher

from phileas.models.span import Span
from .base import BaseFilter, FilterType


DEFAULT_REGION = "US"

# A number written the plain NANP way. Matching it is what earns full confidence.
_NANP_FORMAT = re.compile(r"(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}")


def _confidence(raw: str) -> float:
    if _NANP_FORMAT.fullmatch(raw):
        return 0.95
    return 0.75 if len(raw) > 14 else 0.60


class PhoneNumberFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.PHONE_NUMBER, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        spans: List[Span] = []
        for match in PhoneNumberMatcher(text, DEFAULT_REGION, leniency=Leniency.POSSIBLE):
            spans.append(
                Span(
                    character_start=match.start,
                    character_end=match.end,
                    filter_type=self.filter_type,
                    context=context,
                    confidence=_confidence(match.raw_string),
                    text=match.raw_string,
                    replacement="",
                    ignored=False,
                )
            )
        return spans
