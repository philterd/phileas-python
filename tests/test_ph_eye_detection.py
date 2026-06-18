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

"""Tests for PhEyeFilter pure-logic paths (no network, no gliner)."""

from __future__ import annotations

import pytest

from phileas.filters.base import FilterType
from phileas.filters.ph_eye_filter import PhEyeFilter
from phileas.models.span import Span


# ---------------------------------------------------------------------------
# _opt(): nested phEyeConfiguration takes precedence, then top-level, then default
# ---------------------------------------------------------------------------
class TestOpt:
    def test_nested_configuration_wins_over_top_level(self):
        f = PhEyeFilter({"phEyeConfiguration": {"endpoint": "nested"}, "endpoint": "top"})
        assert f._opt("endpoint", "default") == "nested"

    def test_falls_back_to_top_level_when_not_in_nested(self):
        f = PhEyeFilter({"phEyeConfiguration": {"labels": ["X"]}, "endpoint": "top"})
        assert f._opt("endpoint", "default") == "top"

    def test_falls_back_to_top_level_when_no_nested_node(self):
        f = PhEyeFilter({"endpoint": "top"})
        assert f._opt("endpoint", "default") == "top"

    def test_returns_default_when_absent_everywhere(self):
        f = PhEyeFilter({})
        assert f._opt("endpoint", "default") == "default"

    def test_returns_default_with_none_config(self):
        f = PhEyeFilter(None)
        assert f._opt("timeout", 30) == 30

    def test_none_nested_node_treated_as_empty(self):
        # phEyeConfiguration explicitly None should not raise; falls through.
        f = PhEyeFilter({"phEyeConfiguration": None, "labels": ["TOP"]})
        assert f._opt("labels", ["DEFAULT"]) == ["TOP"]

    def test_nested_value_used_even_when_falsy(self):
        # key present in nested config => nested value returned, even if falsy.
        f = PhEyeFilter({"phEyeConfiguration": {"endpoint": ""}, "endpoint": "top"})
        assert f._opt("endpoint", "default") == ""

    def test_distinct_keys_resolved_independently(self):
        f = PhEyeFilter(
            {
                "phEyeConfiguration": {"endpoint": "nested-ep"},
                "bearerToken": "tok",
                "timeout": 5,
            }
        )
        assert f._opt("endpoint", "") == "nested-ep"
        assert f._opt("bearerToken", "") == "tok"
        assert f._opt("timeout", 30) == 5
        assert f._opt("missing", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# detect(): no endpoint and no modelPath -> [] (and never hits the network)
# ---------------------------------------------------------------------------
class TestDetectNoBackend:
    def test_empty_config_returns_empty_list(self):
        assert PhEyeFilter({}).detect("Alice met Bob in Paris.") == []

    def test_none_config_returns_empty_list(self):
        assert PhEyeFilter(None).detect("Alice met Bob in Paris.") == []

    def test_nested_config_without_endpoint_returns_empty(self):
        f = PhEyeFilter({"phEyeConfiguration": {"labels": ["PERSON"]}})
        assert f.detect("Some text") == []

    def test_model_path_alone_triggers_local_inference(self):
        # Schema 1.1.0: modelPath alone (no vocabPath) routes to local on-device
        # inference and does NOT fall through to the remote endpoint. With a path
        # that is not a real model directory, local loading fails rather than
        # silently returning [] via remote.
        f = PhEyeFilter({"modelPath": "/nonexistent/ph-eye-model"})
        with pytest.raises(Exception):
            f.detect("Some text")

    def test_returns_a_list(self):
        result = PhEyeFilter({}).detect("hello")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# _to_spans(): label membership filtering
# ---------------------------------------------------------------------------
class TestToSpansMembership:
    def test_label_not_in_labels_is_dropped(self):
        f = PhEyeFilter({})
        items = [{"label": "DOG", "score": 1.0, "text": "Rex", "start": 0, "end": 3}]
        assert f._to_spans(items, "default", ["PERSON"]) == []

    def test_label_in_labels_is_kept(self):
        f = PhEyeFilter({})
        items = [{"label": "PERSON", "score": 1.0, "text": "Bob", "start": 0, "end": 3}]
        spans = f._to_spans(items, "default", ["PERSON"])
        assert len(spans) == 1

    def test_empty_labels_disables_membership_filter(self):
        f = PhEyeFilter({})
        items = [
            {"label": "DOG", "score": 1.0, "text": "Rex", "start": 0, "end": 3},
            {"label": "CITY", "score": 1.0, "text": "NYC", "start": 4, "end": 7},
        ]
        spans = f._to_spans(items, "default", [])
        assert len(spans) == 2

    def test_mixed_membership(self):
        f = PhEyeFilter({})
        items = [
            {"label": "PERSON", "score": 0.9, "text": "Bob", "start": 0, "end": 3},
            {"label": "LOCATION", "score": 0.9, "text": "NYC", "start": 4, "end": 7},
            {"label": "ANIMAL", "score": 0.9, "text": "Rex", "start": 8, "end": 11},
        ]
        spans = f._to_spans(items, "default", ["PERSON", "LOCATION"])
        assert [s.text for s in spans] == ["Bob", "NYC"]


# ---------------------------------------------------------------------------
# _to_spans(): per-label threshold filtering (key is label.upper())
# ---------------------------------------------------------------------------
class TestToSpansThresholds:
    def _items(self):
        return [
            {"label": "PERSON", "score": 0.70, "text": "low", "start": 0, "end": 3},
            {"label": "PERSON", "score": 0.85, "text": "high", "start": 4, "end": 8},
        ]

    def test_below_threshold_dropped(self):
        f = PhEyeFilter({"thresholds": {"PERSON": 0.80}})
        spans = f._to_spans(self._items(), "default", ["PERSON"])
        assert [s.text for s in spans] == ["high"]

    def test_score_equal_to_threshold_is_kept(self):
        # condition is `score < threshold`, so equality passes.
        f = PhEyeFilter({"thresholds": {"PERSON": 0.85}})
        spans = f._to_spans(self._items(), "default", ["PERSON"])
        assert [s.text for s in spans] == ["high"]

    def test_no_threshold_defaults_to_zero(self):
        f = PhEyeFilter({})
        spans = f._to_spans(self._items(), "default", ["PERSON"])
        assert len(spans) == 2

    def test_threshold_key_is_uppercased_label(self):
        # item label arrives lowercase; threshold map keyed by upper().
        f = PhEyeFilter({"thresholds": {"PERSON": 0.80}})
        items = [
            {"label": "person", "score": 0.70, "text": "low", "start": 0, "end": 3},
            {"label": "person", "score": 0.90, "text": "high", "start": 4, "end": 8},
        ]
        spans = f._to_spans(items, "default", [])
        assert [s.text for s in spans] == ["high"]

    def test_threshold_read_from_nested_configuration(self):
        f = PhEyeFilter(
            {
                "phEyeConfiguration": {"thresholds": {"PERSON": 0.99}},
                "thresholds": {"PERSON": 0.0},
            }
        )
        spans = f._to_spans(self._items(), "default", ["PERSON"])
        assert spans == []

    def test_none_thresholds_treated_as_empty(self):
        f = PhEyeFilter({"thresholds": None})
        spans = f._to_spans(self._items(), "default", ["PERSON"])
        assert len(spans) == 2

    def test_threshold_only_applies_to_matching_label(self):
        f = PhEyeFilter({"thresholds": {"PERSON": 0.95}})
        items = [
            {"label": "PERSON", "score": 0.90, "text": "p", "start": 0, "end": 1},
            {"label": "CITY", "score": 0.10, "text": "c", "start": 2, "end": 3},
        ]
        spans = f._to_spans(items, "default", [])
        # PERSON dropped (below its threshold); CITY kept (no threshold => 0.0).
        assert [s.text for s in spans] == ["c"]


# ---------------------------------------------------------------------------
# _to_spans(): filter_type mapping
# ---------------------------------------------------------------------------
class TestToSpansFilterType:
    @pytest.mark.parametrize(
        "label,expected",
        [
            ("PERSON", "person"),
            ("person", "person"),
            ("Person", "person"),
            ("LOCATION", "location"),
            ("City", "city"),
            ("ORG", "org"),
        ],
    )
    def test_label_maps_to_lowercase_filter_type(self, label, expected):
        f = PhEyeFilter({})
        items = [{"label": label, "score": 1.0, "text": "x", "start": 0, "end": 1}]
        spans = f._to_spans(items, "default", [])
        assert spans[0].filter_type == expected

    def test_person_maps_specifically_to_person(self):
        f = PhEyeFilter({})
        items = [{"label": "PERSON", "score": 1.0, "text": "x", "start": 0, "end": 1}]
        spans = f._to_spans(items, "default", ["PERSON"])
        assert spans[0].filter_type == "person"

    def test_empty_label_falls_back_to_ph_eye_filter_type(self):
        # label.lower() == "" is falsy, so FilterType.PH_EYE is used.
        f = PhEyeFilter({})
        items = [{"score": 1.0, "text": "x", "start": 0, "end": 1}]
        spans = f._to_spans(items, "default", [])
        assert spans[0].filter_type == FilterType.PH_EYE
        assert spans[0].filter_type == "ph-eye"


# ---------------------------------------------------------------------------
# _to_spans(): Span field population
# ---------------------------------------------------------------------------
class TestToSpansFields:
    def test_all_fields_mapped_correctly(self):
        # threshold 0.0 isolates field mapping from the default 0.5 cutoff.
        f = PhEyeFilter({"threshold": 0.0})
        items = [
            {"label": "PERSON", "score": 0.42, "text": "Bob", "start": 5, "end": 8}
        ]
        spans = f._to_spans(items, "ctxA", ["PERSON"])
        s = spans[0]
        assert isinstance(s, Span)
        assert s.character_start == 5
        assert s.character_end == 8
        assert s.filter_type == "person"
        assert s.context == "ctxA"
        assert s.confidence == pytest.approx(0.42)
        assert s.text == "Bob"
        assert s.replacement == ""
        assert s.ignored is False

    def test_context_is_propagated(self):
        f = PhEyeFilter({})
        items = [{"label": "CITY", "score": 1.0, "text": "x", "start": 0, "end": 1}]
        spans = f._to_spans(items, "my-context", [])
        assert spans[0].context == "my-context"

    def test_missing_fields_use_defaults(self):
        # threshold 0.0 so the score-0.0 default item is not filtered out.
        f = PhEyeFilter({"threshold": 0.0})
        spans = f._to_spans([{}], "default", [])
        s = spans[0]
        assert s.character_start == 0
        assert s.character_end == 0
        assert s.text == ""
        assert s.confidence == 0.0
        assert s.filter_type == "ph-eye"

    def test_numeric_fields_coerced_to_int_and_float(self):
        f = PhEyeFilter({})
        items = [
            {"label": "CITY", "score": "0.5", "text": "x", "start": "2", "end": "4"}
        ]
        spans = f._to_spans(items, "default", [])
        s = spans[0]
        assert s.character_start == 2
        assert isinstance(s.character_start, int)
        assert s.character_end == 4
        assert s.confidence == pytest.approx(0.5)
        assert isinstance(s.confidence, float)

    def test_empty_items_returns_empty_list(self):
        f = PhEyeFilter({})
        assert f._to_spans([], "default", ["PERSON"]) == []

    def test_replacement_always_empty(self):
        f = PhEyeFilter({})
        items = [
            {"label": "PERSON", "score": 1.0, "text": "Bob", "start": 0, "end": 3},
            {"label": "CITY", "score": 1.0, "text": "NYC", "start": 4, "end": 7},
        ]
        spans = f._to_spans(items, "default", [])
        assert all(s.replacement == "" for s in spans)
