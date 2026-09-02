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


# A run of digit groups joined by single spaces or hyphens, e.g. "4111 1111 1111 1111".
_RUN = re.compile(r"\d+(?:[ -]\d+)*")
_GROUP = re.compile(r"\d+")


# Issuer prefixes and lengths, matched against a candidate's digits alone.
_BRANDS = [
    # Visa
    re.compile(r"4[0-9]{12}(?:[0-9]{3})?"),
    # MasterCard
    re.compile(r"(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"),
    # American Express
    re.compile(r"3[47][0-9]{13}"),
    # Discover
    re.compile(r"6(?:011|5[0-9]{2})[0-9]{12}"),
    # Diners Club
    re.compile(r"3(?:0[0-5]|[68][0-9])[0-9]{11}"),
    # JCB
    re.compile(r"(?:2131|1800|35\d{3})\d{11}"),
]


# One alternation of the above, so a candidate costs a single match rather than six.
_ANY_BRAND = re.compile("|".join("(?:%s)" % b.pattern for b in _BRANDS))


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def _candidates(text: str):
    """Yield (start, end, digits) for every whole-group slice of card length.

    Slices start and end on a group, so a card keeps its own boundaries when it
    sits beside other digits: "89-4258428518601" offers "4258428518601".
    """
    for run in _RUN.finditer(text):
        groups = [(m.start(), m.group(0)) for m in _GROUP.finditer(run.group(0))]
        for i in range(len(groups)):
            digits = ""
            for j in range(i, len(groups)):
                digits += groups[j][1]
                if len(digits) > 16:
                    break
                if len(digits) >= 13:
                    yield (
                        run.start() + groups[i][0],
                        run.start() + groups[j][0] + len(groups[j][1]),
                        digits,
                    )


def _luhn_check(number: str) -> bool:
    """Return True if *number* (digits only) passes the Luhn algorithm."""
    digits = [int(d) for d in number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


class CreditCardFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.CREDIT_CARD, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        spans: List[Span] = []
        for start, end, digits in _candidates(text):
            if not _ANY_BRAND.fullmatch(digits):
                continue
            spans.append(
                Span(
                    character_start=start,
                    character_end=end,
                    filter_type=self.filter_type,
                    context=context,
                    confidence=1.0,
                    text=text[start:end],
                    replacement="",
                    ignored=False,
                )
            )
        spans = Span.drop_overlapping_spans(spans)

        # ``luhnCheck`` may be set as a per-filter option on the policy node.
        if not self.config.get("luhnCheck", False):
            return spans
        return [s for s in spans if _luhn_check(_digits(s.text))]
