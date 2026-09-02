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
    re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b"),
]

# Words joined by single spaces; candidates are whole-word slices of a run.
_RUN = re.compile(r"\w+(?: \w+)*")
_WORD = re.compile(r"\w+")

# The longest IBAN.
_MAX_LENGTH = 34


def _candidates(text: str):
    """Yield (start, end) for each whole-word slice that parses as an IBAN."""
    for run in _RUN.finditer(text):
        words = [(m.start(), m.group(0)) for m in _WORD.finditer(run.group(0))]
        for i in range(len(words)):
            # Every IBAN opens with a country-code letter.
            if not words[i][1][:1].isupper():
                continue
            joined = ""
            for j in range(i, len(words)):
                joined += words[j][1]
                if len(joined) > _MAX_LENGTH:
                    break
                if _PATTERNS[0].fullmatch(joined):
                    yield (
                        run.start() + words[i][0],
                        run.start() + words[j][0] + len(words[j][1]),
                    )


class IBANCodeFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.IBAN_CODE, config)
        # On by default, as in the Java filter.
        self.allow_spaces = self.config.get("allowSpaces", True) is not False

    def detect(self, text: str, context: str = "default") -> List[Span]:
        if not self.allow_spaces:
            return self._detect_patterns(_PATTERNS, text, context)

        spans: List[Span] = []
        for start, end in _candidates(text):
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
        return Span.drop_overlapping_spans(spans)
