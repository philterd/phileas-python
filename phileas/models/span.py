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

from dataclasses import dataclass, field
from typing import List


@dataclass
class Span:
    character_start: int
    character_end: int
    filter_type: str
    context: str
    confidence: float
    text: str
    replacement: str
    ignored: bool = False
    applied: bool = True
    salt: str = ""

    def overlaps(self, other: "Span") -> bool:
        """Return True if this span overlaps with another span."""
        return self.character_start < other.character_end and self.character_end > other.character_start

    @staticmethod
    def drop_overlapping_spans(spans: List["Span"]) -> List["Span"]:
        """Remove overlapping spans, keeping the one with higher confidence."""
        if not spans:
            return spans

        sorted_spans = sorted(spans, key=lambda s: (s.character_start, -s.confidence))
        result: List[Span] = []

        for span in sorted_spans:
            dominated = False
            for kept in result:
                if span.overlaps(kept):
                    # kept span has equal or higher confidence (sorted by confidence desc)
                    dominated = True
                    break
            if not dominated:
                # Remove any already-added spans that are dominated by this one
                result = [k for k in result if not (span.overlaps(k) and span.confidence > k.confidence)]
                result.append(span)

        return sorted(result, key=lambda s: s.character_start)
