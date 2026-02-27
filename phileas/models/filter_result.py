from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .span import Span


@dataclass
class FilterResult:
    context: str
    document_id: str
    filtered_text: str
    spans: List[Span] = field(default_factory=list)
