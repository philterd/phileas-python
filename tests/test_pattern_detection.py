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

"""Characterization tests for :class:`PatternFilter` (custom identifier)."""

import pytest

from phileas.filters.base import FilterType
from phileas.filters.pattern_filter import PatternFilter


def _texts(spans):
    return [s.text for s in spans]


class TestClassificationAsFilterType:
    def test_classification_becomes_filter_type(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        assert f.filter_type == "MRN"
        spans = f.detect("see MRN-123456 now")
        assert len(spans) == 1
        assert spans[0].filter_type == "MRN"

    def test_label_used_when_classification_absent(self):
        f = PatternFilter({"label": "LBL", "pattern": r"\d+"})
        assert f.filter_type == "LBL"
        assert all(s.filter_type == "LBL" for s in f.detect("abc 42 xyz"))

    def test_classification_takes_precedence_over_label(self):
        f = PatternFilter(
            {"classification": "MRN", "label": "LBL", "pattern": r"\d+"}
        )
        assert f.filter_type == "MRN"

    def test_default_classification_when_omitted(self):
        f = PatternFilter({"pattern": r"MRN-\d{6}"})
        assert f.filter_type == FilterType.PATTERN
        assert f.filter_type == "pattern"
        spans = f.detect("MRN-123456")
        assert len(spans) == 1
        assert spans[0].filter_type == "pattern"

    def test_default_classification_with_none_config(self):
        f = PatternFilter(None)
        assert f.filter_type == FilterType.PATTERN
        assert f.config == {}


class TestBasicDetection:
    def test_single_match_offsets(self):
        text = "see MRN-123456 now"
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        spans = f.detect(text)
        assert len(spans) == 1
        span = spans[0]
        assert span.text == "MRN-123456"
        assert span.character_start == 4
        assert span.character_end == 14
        assert text[span.character_start:span.character_end] == "MRN-123456"

    def test_span_attributes(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        span = f.detect("MRN-123456")[0]
        assert span.confidence == 1.0
        assert span.replacement == ""
        assert span.character_start == 0
        assert span.character_end == 10

    def test_context_passed_through(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        span = f.detect("MRN-123456", context="custom")[0]
        assert span.context == "custom"

    def test_default_context_is_default(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        span = f.detect("MRN-123456")[0]
        assert span.context == "default"

    def test_no_match_returns_no_spans(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        assert f.detect("nothing here") == []

    def test_empty_text_returns_no_spans(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        assert f.detect("") == []


class TestMultipleMatches:
    def test_two_matches_in_one_text(self):
        text = "MRN-111111 and MRN-222222"
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        spans = f.detect(text)
        assert len(spans) == 2
        assert _texts(spans) == ["MRN-111111", "MRN-222222"]
        assert spans[0].character_start == 0
        assert spans[1].character_start == 15
        for s in spans:
            assert text[s.character_start:s.character_end] == s.text

    def test_three_matches(self):
        f = PatternFilter({"classification": "N", "pattern": r"\d+"})
        spans = f.detect("1 22 333")
        assert _texts(spans) == ["1", "22", "333"]
        assert [(s.character_start, s.character_end) for s in spans] == [
            (0, 1),
            (2, 4),
            (5, 8),
        ]


class TestCaseSensitivity:
    def test_case_sensitive_default_no_match(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"mrn-\d{6}"})
        assert f.detect("MRN-123456") == []

    def test_case_sensitive_default_exact_match(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"mrn-\d{6}"})
        assert _texts(f.detect("mrn-123456")) == ["mrn-123456"]

    def test_case_sensitive_true_explicit(self):
        f = PatternFilter(
            {"classification": "MRN", "pattern": r"mrn-\d{6}", "caseSensitive": True}
        )
        assert f.detect("MRN-123456") == []

    def test_case_insensitive_matches_uppercase(self):
        f = PatternFilter(
            {"classification": "MRN", "pattern": r"mrn-\d{6}", "caseSensitive": False}
        )
        assert _texts(f.detect("MRN-123456")) == ["MRN-123456"]

    def test_case_insensitive_matches_mixed_case(self):
        f = PatternFilter(
            {"classification": "MRN", "pattern": r"mrn-\d{6}", "caseSensitive": False}
        )
        assert _texts(f.detect("MrN-123456")) == ["MrN-123456"]


class TestGroupNumber:
    def test_group_one_extracts_capture_with_offsets(self):
        text = "xx MRN-123456 yy"
        f = PatternFilter(
            {"classification": "MRN", "pattern": r"MRN-(\d{6})", "groupNumber": 1}
        )
        spans = f.detect(text)
        assert len(spans) == 1
        span = spans[0]
        assert span.text == "123456"
        assert span.character_start == 7
        assert span.character_end == 13
        assert text[span.character_start:span.character_end] == "123456"

    def test_group_zero_is_whole_match(self):
        f = PatternFilter(
            {"classification": "MRN", "pattern": r"MRN-(\d{6})", "groupNumber": 0}
        )
        span = f.detect("MRN-123456")[0]
        assert span.text == "MRN-123456"
        assert (span.character_start, span.character_end) == (0, 10)

    def test_default_group_is_whole_match(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-(\d{6})"})
        span = f.detect("MRN-123456")[0]
        assert span.text == "MRN-123456"

    def test_second_group_extracted(self):
        text = "ab"
        f = PatternFilter(
            {"classification": "X", "pattern": r"(a)(b)", "groupNumber": 2}
        )
        span = f.detect(text)[0]
        assert span.text == "b"
        assert (span.character_start, span.character_end) == (1, 2)

    def test_group_number_as_string(self):
        f = PatternFilter(
            {"classification": "X", "pattern": r"(a)(b)", "groupNumber": "2"}
        )
        assert _texts(f.detect("ab")) == ["b"]

    def test_group_number_out_of_range_falls_back_to_whole_match(self):
        # groupNumber greater than the number of groups -> falls back to group 0.
        f = PatternFilter(
            {"classification": "MRN", "pattern": r"MRN-(\d{6})", "groupNumber": 5}
        )
        assert _texts(f.detect("MRN-123456")) == ["MRN-123456"]

    def test_group_multiple_matches(self):
        text = "MRN-111111 MRN-222222"
        f = PatternFilter(
            {"classification": "MRN", "pattern": r"MRN-(\d{6})", "groupNumber": 1}
        )
        spans = f.detect(text)
        assert _texts(spans) == ["111111", "222222"]
        assert spans[0].character_start == 4
        assert spans[1].character_start == 15

    def test_non_participating_optional_group_skipped(self):
        # When the requested group did not participate in the match, its value
        # is None and that match produces no span.
        f = PatternFilter(
            {"classification": "X", "pattern": r"a(b)?c", "groupNumber": 1}
        )
        assert f.detect("ac") == []

    def test_participating_optional_group_detected(self):
        f = PatternFilter(
            {"classification": "X", "pattern": r"a(b)?c", "groupNumber": 1}
        )
        assert _texts(f.detect("abc")) == ["b"]


class TestEmptyOrMissingPattern:
    def test_empty_pattern_no_spans(self):
        f = PatternFilter({"classification": "X", "pattern": ""})
        assert f.detect("MRN-123456") == []

    def test_missing_pattern_no_spans(self):
        f = PatternFilter({"classification": "X"})
        assert f.detect("MRN-123456") == []

    def test_none_config_no_spans(self):
        assert PatternFilter(None).detect("anything") == []

    def test_empty_config_no_spans(self):
        assert PatternFilter({}).detect("anything") == []
