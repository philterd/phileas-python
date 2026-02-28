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
    """A single ground-truth span from an annotations JSON file."""

    start: int
    end: int
    type: str = ""
