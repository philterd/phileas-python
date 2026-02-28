from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .span import Span


@dataclass
class EvaluationResult:
    """Evaluation metrics comparing detected spans against ground-truth spans."""

    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    detected_spans: List[Span] = field(default_factory=list)
    ground_truth_spans: List["GroundTruthSpan"] = field(default_factory=list)


@dataclass
class GroundTruthSpan:
    """A single ground-truth span from a LAPPS JSON annotation file."""

    start: int
    end: int
    type: str = ""
