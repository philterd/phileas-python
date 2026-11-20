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
from typing import List, Optional

from phileas.models.span import Span
from .base import BaseFilter, FilterType
from .validators import resolve_validator


# The span confidence of a custom identifier, as in Phileas (Java) and phileas-dotnet
# (philterd/phileas-conformance#7).
_CONFIDENCE = 0.9


class PatternFilter(BaseFilter):
    """Detects PII using a user-supplied regular expression (custom identifier).

    Config is a custom-identifier node from the policy ``identifiers.identifiers``
    array: ``classification`` (the label/filter type), ``pattern`` (the regex),
    optional ``caseSensitive`` (default True), optional ``groupNumber`` (the
    capture group to extract as the matched value), and an optional ``validator``
    (a named, post-match check; a match is kept only if it passes).
    """

    def __init__(self, config=None):
        config = config or {}
        filter_type = config.get("classification") or config.get("label") or FilterType.PATTERN
        super().__init__(filter_type, config)
        # The label (%l) is the classification, defaulting to "custom-identifier" as in Phileas (Java).
        self._classification = config.get("classification", "custom-identifier") or ""

        pattern_str = config.get("pattern", "")
        flags = 0 if config.get("caseSensitive", True) else re.IGNORECASE
        self._pattern: Optional[re.Pattern] = (
            re.compile(pattern_str, flags) if pattern_str else None
        )
        group = config.get("groupNumber")
        self._group = int(group) if group is not None else 0

        # Optional post-match validator. ``None`` means keep every match; an
        # unknown or not-yet-implemented name raises here (a loud policy error).
        self._validator = resolve_validator(config.get("validator"))

    def detect(self, text: str, context: str = "default") -> List[Span]:
        if self._pattern is None:
            return []
        spans: List[Span] = []
        for match in self._pattern.finditer(text):
            group = self._group if self._group <= (match.re.groups) else 0
            token = match.group(group)
            if token is None:
                continue
            # A validator, when present, keeps a match only if it passes.
            if self._validator is not None and not self._validator(token):
                continue
            spans.append(
                Span(
                    character_start=match.start(group),
                    character_end=match.end(group),
                    filter_type=self.filter_type,
                    context=context,
                    confidence=_CONFIDENCE,
                    text=token,
                    replacement="",
                    ignored=False,
                    classification=self._classification,
                )
            )
        return spans
