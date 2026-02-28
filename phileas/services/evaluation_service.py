from __future__ import annotations

import json
from typing import List, Union

from phileas.models.evaluation_result import EvaluationResult, GroundTruthSpan
from phileas.models.span import Span
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService
from phileas.services.context.base import AbstractContextService


def _parse_annotations(data: Union[dict, list]) -> List[GroundTruthSpan]:
    """Parse ground-truth spans from an annotations JSON document.

    Accepted formats:

    1. A list of span objects::

        [{"start": 0, "end": 10, "type": "PERSON"}, ...]

    2. A dict with a ``"spans"`` key::

        {"text": "...", "spans": [{"start": 0, "end": 10, "type": "PERSON"}, ...]}

    Each span must contain ``"start"`` and ``"end"`` integer fields.
    The ``"type"`` field is optional.
    """
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("spans", [])
    else:
        raise ValueError("Annotations JSON must be a list or an object with a 'spans' key.")

    spans: List[GroundTruthSpan] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"Span at index {i} must be a JSON object.")
        if "start" not in item or "end" not in item:
            raise ValueError(f"Span at index {i} is missing 'start' or 'end' field.")
        spans.append(
            GroundTruthSpan(
                start=int(item["start"]),
                end=int(item["end"]),
                type=str(item.get("type", "")),
            )
        )
    return spans


def _spans_overlap(detected: Span, ground_truth: GroundTruthSpan) -> bool:
    """Return True if a detected span overlaps with a ground-truth span."""
    return (
        detected.character_start < ground_truth.end
        and detected.character_end > ground_truth.start
    )


class EvaluationService:
    """Evaluate filter performance against provided ground-truth spans."""

    def __init__(self, context_service: AbstractContextService | None = None) -> None:
        self._filter_service = FilterService(context_service)

    def evaluate(
        self,
        policy: Policy,
        context: str,
        document_id: str,
        text: str,
        annotations_json: Union[str, dict, list],
    ) -> EvaluationResult:
        """Run the filter on *text* and compare the result against *annotations_json*.

        Parameters
        ----------
        policy:
            The phileas policy to apply.
        context:
            Context name (forwarded to :class:`FilterService`).
        document_id:
            Document identifier (forwarded to :class:`FilterService`).
        text:
            The plain text to redact.
        annotations_json:
            Ground-truth annotations as a parsed JSON value (``dict`` or
            ``list``) or a raw JSON string.

        Returns
        -------
        :class:`~phileas.models.evaluation_result.EvaluationResult`
            Evaluation metrics and the raw detected / ground-truth spans.
        """
        if isinstance(annotations_json, str):
            annotations_json = json.loads(annotations_json)

        ground_truth = _parse_annotations(annotations_json)
        filter_result = self._filter_service.filter(policy, context, document_id, text)
        detected = [s for s in filter_result.spans if not s.ignored]

        # Match each detected span to at most one ground-truth span (greedy, by overlap)
        matched_gt: set[int] = set()
        tp = 0
        fp = 0
        for span in detected:
            matched = False
            for idx, gt in enumerate(ground_truth):
                if idx not in matched_gt and _spans_overlap(span, gt):
                    matched_gt.add(idx)
                    matched = True
                    break
            if matched:
                tp += 1
            else:
                fp += 1

        fn = len(ground_truth) - len(matched_gt)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return EvaluationResult(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1=f1,
            detected_spans=detected,
            ground_truth_spans=ground_truth,
        )
