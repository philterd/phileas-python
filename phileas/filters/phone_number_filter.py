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
number is found only for a configured region. Mirrors the Java filter's scanner,
regions, leniency, and confidence tiers.
"""

from __future__ import annotations

import re
from typing import List

from phonenumbers import Leniency, PhoneNumberMatcher, country_code_for_region, is_valid_number

from phileas.models.span import Span
from .base import BaseFilter, FilterType


DEFAULT_REGION = "US"

# A number written the plain NANP way. Matching it is what earns full confidence.
_NANP_FORMAT = re.compile(r"(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}")

# A bare "1" country code followed by a separator and a phone-formatted number, such
# as "1-112-997-5633". Without a "+", libphonenumber strips the "1" as the country
# code and then an area code's leading "1" as a national prefix, leaving too few
# digits for a possible number, so the match is dropped.
_BARE_COUNTRY_CODE = re.compile(r"(?<![\d+])1[-. ](?=\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4})")


def _confidence(raw: str) -> float:
    if _NANP_FORMAT.fullmatch(raw):
        return 0.95
    return 0.75 if len(raw) > 14 else 0.60


def _regions(config: dict) -> List[str]:
    """The ``region`` option as a list. Accepts a string or a list of strings."""
    region = config.get("region")
    if isinstance(region, str):
        region = [region]
    if not isinstance(region, list):
        return [DEFAULT_REGION]
    # Upper-cased because libphonenumber silently finds no national-format
    # numbers for a lower-case region rather than reporting the mistake.
    cleaned = [r.strip().upper() for r in region if isinstance(r, str) and r.strip()]
    # A repeated region only costs another scan; the merge collapses its results anyway.
    return list(dict.fromkeys(cleaned)) or [DEFAULT_REGION]


def _dedupe(matches: list) -> list:
    """Merge matches found across regions, keeping the best of each overlapping cluster.

    A valid number beats a merely-possible one, then the longer span, then the
    earlier. Returned in document order.
    """
    ordered = sorted(
        matches,
        key=lambda m: (not is_valid_number(m.number), -(m.end - m.start), m.start),
    )
    kept: list = []
    for candidate in ordered:
        if not any(candidate.start < k.end and k.start < candidate.end for k in kept):
            kept.append(candidate)
    return sorted(kept, key=lambda m: m.start)


class PhoneNumberFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.PHONE_NUMBER, config)
        self.regions = _regions(self.config)
        # The first configured region that uses country code 1, or None when none does.
        self.north_american_region = next(
            (r for r in self.regions if country_code_for_region(r) == 1), None
        )

    def detect(self, text: str, context: str = "default") -> List[Span]:
        matches: list = []
        for region in self.regions:
            matches.extend(PhoneNumberMatcher(text, region, leniency=Leniency.POSSIBLE))

        # Also scan, once, a copy in which a bare "1" country code becomes "+1", so
        # "1-112-997-5633" is found like "+1 112-997-5633". "1-" and "+1" have the same
        # length, so offsets in the copy are offsets in the text. A match from the copy
        # is kept only where the text itself had none, so a number already found, such
        # as "112-997-5633" in "Item 1 112-997-5633", keeps its span and confidence.
        if self.north_american_region:
            rewritten = _BARE_COUNTRY_CODE.sub("+1", text)
            if rewritten != text:
                found = list(matches)
                for match in PhoneNumberMatcher(
                    rewritten, self.north_american_region, leniency=Leniency.POSSIBLE
                ):
                    if not any(match.start < m.end and m.start < match.end for m in found):
                        matches.append(match)

        spans = []
        for match in _dedupe(matches):
            # Taken from the text rather than raw_string, which is the rewritten copy
            # for a match found there.
            raw = text[match.start:match.end]
            spans.append(
                Span(
                    character_start=match.start,
                    character_end=match.end,
                    filter_type=self.filter_type,
                    context=context,
                    confidence=_confidence(raw),
                    text=raw,
                    replacement="",
                    ignored=False,
                )
            )
        return spans
