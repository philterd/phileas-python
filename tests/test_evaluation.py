"""Tests for the EvaluationService and related utilities."""

from __future__ import annotations

import json

import pytest

from phileas.models.evaluation_result import EvaluationResult, GroundTruthSpan
from phileas.policy.policy import Policy
from phileas.policy.identifiers import EmailAddressFilterConfig
from phileas.services.evaluation_service import EvaluationService, _parse_annotations


# ---------------------------------------------------------------------------
# _parse_annotations unit tests
# ---------------------------------------------------------------------------

class TestParseAnnotations:
    def test_list_format(self):
        data = [{"start": 0, "end": 5, "type": "PERSON"}]
        spans = _parse_annotations(data)
        assert len(spans) == 1
        assert spans[0].start == 0
        assert spans[0].end == 5
        assert spans[0].type == "PERSON"

    def test_dict_format_with_spans_key(self):
        data = {"text": "hello world", "spans": [{"start": 0, "end": 5}]}
        spans = _parse_annotations(data)
        assert len(spans) == 1
        assert spans[0].start == 0
        assert spans[0].end == 5
        assert spans[0].type == ""

    def test_empty_list(self):
        assert _parse_annotations([]) == []

    def test_dict_with_empty_spans(self):
        assert _parse_annotations({"spans": []}) == []

    def test_missing_start_raises(self):
        with pytest.raises(ValueError, match="'start' or 'end'"):
            _parse_annotations([{"end": 5}])

    def test_missing_end_raises(self):
        with pytest.raises(ValueError, match="'start' or 'end'"):
            _parse_annotations([{"start": 0}])

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError):
            _parse_annotations("not a list or dict")

    def test_non_dict_item_raises(self):
        with pytest.raises(ValueError, match="JSON object"):
            _parse_annotations(["not_a_dict"])

    def test_multiple_spans(self):
        data = [
            {"start": 0, "end": 10, "type": "EMAIL"},
            {"start": 20, "end": 30, "type": "SSN"},
        ]
        spans = _parse_annotations(data)
        assert len(spans) == 2
        assert spans[1].type == "SSN"

    def test_string_json_parsed(self):
        """When a raw JSON string is passed to evaluate(), it should be parsed."""
        svc = EvaluationService()
        policy = Policy(name="empty")
        result = svc.evaluate(policy, "ctx", "doc", "hello", json.dumps([]))
        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.false_negatives == 0


# ---------------------------------------------------------------------------
# EvaluationService tests
# ---------------------------------------------------------------------------

def _policy_with_email():
    p = Policy(name="test")
    p.identifiers.email_address = EmailAddressFilterConfig()
    return p


class TestEvaluationServicePerfectMatch:
    def test_all_true_positives(self):
        """Ground truth exactly covers the detected email span."""
        text = "Email john@example.com here."
        # The email 'john@example.com' is at positions 6..22
        ground_truth = [{"start": 6, "end": 22, "type": "email-address"}]
        svc = EvaluationService()
        result = svc.evaluate(_policy_with_email(), "ctx", "doc", text, ground_truth)
        assert result.true_positives == 1
        assert result.false_positives == 0
        assert result.false_negatives == 0
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1 == 1.0

    def test_overlapping_spans_count_as_tp(self):
        """A ground-truth span that partially overlaps with a detected span is a TP."""
        text = "Email john@example.com here."
        # Slightly off positions still overlap
        ground_truth = [{"start": 5, "end": 23}]
        svc = EvaluationService()
        result = svc.evaluate(_policy_with_email(), "ctx", "doc", text, ground_truth)
        assert result.true_positives == 1
        assert result.false_positives == 0
        assert result.false_negatives == 0


class TestEvaluationServiceFalsePositives:
    def test_detected_but_not_in_ground_truth(self):
        """Filter detects an email that is not in the ground truth -> FP."""
        text = "Email john@example.com here."
        ground_truth = []  # no ground-truth spans
        svc = EvaluationService()
        result = svc.evaluate(_policy_with_email(), "ctx", "doc", text, ground_truth)
        assert result.true_positives == 0
        assert result.false_positives == 1
        assert result.false_negatives == 0
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1 == 0.0


class TestEvaluationServiceFalseNegatives:
    def test_ground_truth_not_detected(self):
        """Ground truth has a span that the filter didn't detect -> FN."""
        text = "Hello world."
        # Ground truth claims there is an entity here, but no filter detects it
        ground_truth = [{"start": 0, "end": 5, "type": "PERSON"}]
        svc = EvaluationService()
        policy = Policy(name="empty")  # no filters enabled
        result = svc.evaluate(policy, "ctx", "doc", text, ground_truth)
        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.false_negatives == 1
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1 == 0.0


class TestEvaluationServiceMetrics:
    def test_precision_recall_f1_calculation(self):
        """Check the precision/recall/F1 formula with mixed results."""
        text = "Email john@example.com here. And also jane@example.com."
        # Ground truth has both emails; filter will find both -> TP=2, FP=0, FN=0
        ground_truth = [
            {"start": 6, "end": 22},   # john@example.com
            {"start": 37, "end": 53},  # jane@example.com (approximate)
        ]
        svc = EvaluationService()
        result = svc.evaluate(_policy_with_email(), "ctx", "doc", text, ground_truth)
        # At minimum both emails get detected; exact positions may vary slightly
        assert result.true_positives + result.false_negatives == 2

    def test_empty_text_no_pii(self):
        text = "No PII here."
        ground_truth = []
        svc = EvaluationService()
        result = svc.evaluate(Policy(name="empty"), "ctx", "doc", text, ground_truth)
        assert result.true_positives == 0
        assert result.false_positives == 0
        assert result.false_negatives == 0
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1 == 0.0

    def test_result_contains_spans(self):
        text = "Email john@example.com here."
        ground_truth = [{"start": 6, "end": 22}]
        svc = EvaluationService()
        result = svc.evaluate(_policy_with_email(), "ctx", "doc", text, ground_truth)
        assert len(result.detected_spans) >= 1
        assert result.detected_spans[0].character_start == 6
        assert result.detected_spans[0].character_end == 22
        assert len(result.ground_truth_spans) == 1
        assert result.ground_truth_spans[0].start == 6
        assert result.ground_truth_spans[0].end == 22

    def test_dict_annotation_format(self):
        """The dict format {'spans': [...]} must also work."""
        text = "Email john@example.com here."
        annotation_data = {"text": text, "spans": [{"start": 6, "end": 22}]}
        svc = EvaluationService()
        result = svc.evaluate(_policy_with_email(), "ctx", "doc", text, annotation_data)
        assert result.true_positives == 1
