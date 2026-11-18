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


# The patterns are ported from the Phileas (Java) StreetAddressFilter.

# Directionals, longest forms first so a full word wins over its abbreviation.
_DIRECTIONAL = r"(?:Northeast|Northwest|Southeast|Southwest|North|South|East|West|NE|NW|SE|SW|N|S|E|W)"

# Street types, each long form before its abbreviation so the whole word is preferred.
_STREET_TYPE = (
    r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Road|Rd|Lane|Ln|Way|Court|Ct|Place|Pl|Circle|Cir"
    r"|Highway|Hwy|Parkway|Pkwy|Square|Sq|Trail|Trl|Terrace|Ter|Turnpike|Tpke|Expressway|Expy|Freeway|Fwy"
    r"|Crossing|Xing|Crescent|Cres|Plaza|Plz|Landing|Lndg|Gardens|Garden|Gdns|Commons|Manor|Mnr|Ridge|Rdg"
    r"|Point|Pt|Grove|Grv|Alley|Aly|Cove|Cv|Bend|Bnd|Loop|Pike|Path|Mews|Row|Run|Walk|Close)"
)

# Unit / secondary-address designators, folded into the span when present.
_UNIT = (
    r"(?:[, \t]+(?:Apt|Apartment|Suite|Ste|Unit|Bldg|Building|Floor|Fl|Room|Rm|#)\.?[ \t]*#?[ \t]*[A-Za-z0-9-]+)?"
)

# The parts are joined by spaces and tabs only, so a match does not run from one line into
# the next (a ZIP code at the end of a line and "Dear Dr." on the next are not an address).
_PATTERNS = [
    # A street address: a house number (optionally a range and/or a trailing letter), an
    # optional leading directional, one to five name words, a street type, an optional
    # trailing directional, and an optional unit.
    re.compile(
        r"\b\d{1,6}(?:-\d{1,6})?[A-Za-z]?[ \t]+"
        r"(?:" + _DIRECTIONAL + r"[ \t]+)?"
        r"(?:[A-Za-z0-9'.-]+[ \t]+){1,5}"
        + _STREET_TYPE
        + r"\b\.?"
        r"(?:[ \t]+" + _DIRECTIONAL + r"\b)?" + _UNIT,
        re.IGNORECASE,
    ),
    # A PO box, e.g. "PO Box 1234", "P.O. Box 56", "Post Office Box 789", on one line.
    re.compile(
        r"\b(?:P\.?[ \t]?O\.?[ \t]?Box|Post[ \t]+Office[ \t]+Box)[ \t]+\d+\b",
        re.IGNORECASE,
    ),
]

# The confidence the Java filter gives both patterns.
_CONFIDENCE = 0.85


class StreetAddressFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.STREET_ADDRESS, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        return self._detect_patterns(_PATTERNS, text, context, confidence=_CONFIDENCE)
