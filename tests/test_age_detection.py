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

"""Characterization tests for AgeFilter detection."""

import pytest

from phileas.filters.age_filter import AgeFilter


@pytest.fixture
def age_filter():
    return AgeFilter()


def _texts(spans):
    return [s.text for s in spans]


class TestConstruction:
    def test_default_config_is_empty_dict(self):
        f = AgeFilter()
        assert f.config == {}

    def test_none_config_becomes_empty_dict(self):
        f = AgeFilter(None)
        assert f.config == {}

    def test_filter_type_attribute(self):
        assert AgeFilter().filter_type == "age"


class TestPositiveDetections:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("She is 45 years old.", "45 years old"),
            ("aged 25", "aged 25"),
            ("30 yr old", "30 yr old"),
            ("25 yo", "25 yo"),
            ("65 y/o", "65 y/o"),
            ("age: 55", "age: 55"),
            ("I am 30 years old", "30 years old"),
            ("age 40", "age 40"),
            ("12 yrs", "12 yrs"),
            ("100 years", "100 years"),
            ("3.5 years old", "3.5 years old"),
            ("30-year-old", "30-year-old"),
            ("30-years-old", "30-years-old"),
            ("25 y/o", "25 y/o"),
            ("age:55", "age:55"),
            ("age :55", "age :55"),
            ("aged25", "aged25"),
        ],
    )
    def test_detects_expected_text(self, age_filter, text, expected):
        spans = age_filter.detect(text)
        assert expected in _texts(spans)

    @pytest.mark.parametrize(
        "text",
        [
            "She is 45 years old.",
            "aged 25",
            "30 yr old",
            "25 yo",
            "65 y/o",
            "age: 55",
        ],
    )
    def test_each_guidance_case_detected(self, age_filter, text):
        assert len(age_filter.detect(text)) >= 1


class TestSpanAttributes:
    def test_filter_type_is_age(self, age_filter):
        spans = age_filter.detect("She is 45 years old.")
        assert spans
        assert all(s.filter_type == "age" for s in spans)

    def test_confidence_is_one(self, age_filter):
        spans = age_filter.detect("aged 25")
        assert all(s.confidence == 1.0 for s in spans)

    def test_replacement_always_empty(self, age_filter):
        spans = age_filter.detect("65 y/o")
        assert all(s.replacement == "" for s in spans)

    def test_offsets_match_source_text(self, age_filter):
        text = "She is 45 years old."
        span = age_filter.detect(text)[0]
        assert text[span.character_start:span.character_end] == span.text

    def test_character_start_of_embedded_match(self, age_filter):
        text = "I am 30 years old"
        span = age_filter.detect(text)[0]
        assert span.character_start == text.index("30")
        assert span.text == "30 years old"

    def test_context_default_does_not_error(self, age_filter):
        spans = age_filter.detect("aged 25", context="custom")
        assert spans
        assert spans[0].text == "aged 25"


class TestNegativeDetections:
    @pytest.mark.parametrize(
        "text",
        [
            "year 2020",
            "I have 5 apples",
            "The number is 42",
            "born in 1990",
            "5",
            "",
            "no numbers here at all",
            "the meeting is at 3",
            "page 7 of the book",
            "room 101",
        ],
    )
    def test_no_detection(self, age_filter, text):
        assert age_filter.detect(text) == []


class TestMultipleMatches:
    def test_two_aged_phrases(self, age_filter):
        spans = age_filter.detect("aged 25 and aged 30")
        assert _texts(spans) == ["aged 25", "aged 30"]

    def test_two_yo_phrases(self, age_filter):
        # NOTE: the first match captures a trailing space ("25 yo ") because the
        # optional "old" makes the word boundary land after the space. This is a
        # characterization of current behavior.
        spans = age_filter.detect("25 yo and 30 yo")
        texts = _texts(spans)
        assert "30 yo" in texts
        assert any(t.strip() == "25 yo" for t in texts)
        assert len(spans) == 2

    def test_trailing_punctuation_not_included(self, age_filter):
        spans = age_filter.detect("He is 25 yo.")
        assert _texts(spans) == ["25 yo"]


class TestReturnShape:
    def test_returns_list(self, age_filter):
        assert isinstance(age_filter.detect("age 40"), list)

    def test_empty_input_returns_empty_list(self, age_filter):
        assert age_filter.detect("") == []
