from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


class PatternFilter(BaseFilter):
    """Filter that identifies PII using a user-supplied regular expression."""

    def __init__(self, filter_config):
        label = getattr(filter_config, "label", None)
        if not label:
            label = FilterType.PATTERN
        super().__init__(label, filter_config)
        pattern_str = getattr(filter_config, "pattern", "")
        self._pattern: re.Pattern | None = re.compile(pattern_str) if pattern_str else None

    def filter(self, text: str, context: str = "default") -> List[Span]:
        if self._pattern is None:
            return []
        return self._find_spans([self._pattern], text, context)
