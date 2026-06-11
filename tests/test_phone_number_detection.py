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

"""Detection tests for :class:`PhoneNumberFilter`.

These are characterization tests: they assert what the filter actually does,
which is regex-based detection. Note that some patterns overlap, so a single
phone number can produce more than one (sometimes duplicate) span; tests here
assert on the *presence* of the expected span rather than exact list equality
where overlap occurs.
"""

import pytest

from phileas.filters.phone_number_filter import PhoneNumberFilter

FILTER_TYPE = "phone-number"


def _spans(text, config=None):
    return PhoneNumberFilter(config).detect(text)


def _texts(text, config=None):
    return [s.text for s in _spans(text, config)]


def _has_span(text, expected_text):
    """True if any detected span has exactly ``expected_text``."""
    return expected_text in _texts(text)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_construction(self):
        f = PhoneNumberFilter()
        assert f.filter_type == FILTER_TYPE
        assert f.config == {}

    def test_none_config(self):
        f = PhoneNumberFilter(None)
        assert f.filter_type == FILTER_TYPE
        assert f.config == {}

    def test_dict_config(self):
        f = PhoneNumberFilter({"foo": "bar"})
        assert f.filter_type == FILTER_TYPE
        assert f.config == {"foo": "bar"}


# ---------------------------------------------------------------------------
# Span shape / metadata
# ---------------------------------------------------------------------------


class TestSpanMetadata:
    def test_filter_type_on_spans(self):
        spans = _spans("Call 800-555-1234.")
        assert spans
        assert all(s.filter_type == FILTER_TYPE for s in spans)

    def test_confidence_is_one(self):
        spans = _spans("Call 800-555-1234.")
        assert all(s.confidence == 1.0 for s in spans)

    def test_replacement_is_empty(self):
        spans = _spans("Call 800-555-1234.")
        assert spans
        assert all(s.replacement == "" for s in spans)

    def test_offsets_point_at_match(self):
        text = "Call 2025551234 now"
        spans = _spans(text)
        assert spans
        s = next(s for s in spans if s.text == "2025551234")
        assert text[s.character_start : s.character_end] == s.text
        assert s.character_start == len("Call ")
        assert s.character_end == len("Call 2025551234")

    def test_default_context(self):
        # detect() exposes context='default'; verify it does not error.
        spans = PhoneNumberFilter().detect("Call 800-555-1234.", context="default")
        assert spans


# ---------------------------------------------------------------------------
# Positive detection
# ---------------------------------------------------------------------------


class TestPositiveDetection:
    @pytest.mark.parametrize(
        "number",
        [
            "800-555-1234",
            "800.555.1234",
            "800 555 1234",
            "2025551234",
            "8005551234",
        ],
    )
    def test_detects_whole_number(self, number):
        # These formats are captured verbatim.
        assert _has_span(f"Reach me at {number} today", number)

    def test_paren_format_detected(self):
        # The leading "(" is not included by the pattern (word boundary), but
        # the rest of the number including the ")" is captured.
        text = "Reach me at (800) 555-1234 today"
        assert _has_span(text, "800) 555-1234")

    def test_paren_format_excludes_open_paren(self):
        # Characterization: the open paren is not part of any detected span.
        assert not _has_span("Call (800) 555-1234", "(800) 555-1234")

    def test_plus_one_space_format(self):
        text = "Reach me at +1 800 555 1234 today"
        texts = _texts(text)
        assert "+1 800 555 1234" in texts
        # overlapping pattern also matches the trailing 10-digit grouping
        assert "800 555 1234" in texts

    def test_plus_one_dash_format(self):
        text = "Reach me at +1-800-555-1234 today"
        texts = _texts(text)
        assert "+1-800-555-1234" in texts
        assert "800-555-1234" in texts

    def test_ten_digit_starts_2_through_9(self):
        # First digit and fourth digit must be 2-9 for the no-separator pattern.
        assert _has_span("num 2025551234 end", "2025551234")
        assert _has_span("num 9998887777 end", "9998887777")

    @pytest.mark.parametrize(
        "number",
        ["800-555-1234", "800.555.1234"],
    )
    def test_standalone_number_detected(self, number):
        assert _has_span(number, number)

    def test_multiple_numbers_in_text(self):
        text = "Home 800-555-1234 or cell 9998887777."
        texts = _texts(text)
        assert "800-555-1234" in texts
        assert "9998887777" in texts


# ---------------------------------------------------------------------------
# Negative detection
# ---------------------------------------------------------------------------


class TestNegativeDetection:
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "no phone here",
            "call me",
            "abc-def-ghij",
            "phone: 123",
            "555-12",
            "12-345-6789",
            "just some words and 42 numbers",
        ],
    )
    def test_no_detection(self, text):
        assert _spans(text) == []

    def test_too_few_digits(self):
        assert _spans("Call 800-555-123") == []

    def test_letters_in_place_of_digits(self):
        assert _spans("Call ABC-DEF-GHIJ now") == []

    def test_ten_digits_starting_with_1_not_matched(self):
        # No-separator pattern requires first digit 2-9; "1..." is not matched.
        assert "1005551234" not in _texts("num 1005551234 end")

    def test_ten_digits_bad_fourth_digit_not_matched(self):
        # Fourth digit must be 2-9; "1234567890" (4th digit '4' ok? no, 4 is ok)
        # Use a clearly-invalid one whose 4th digit is < 2.
        assert "5550005678" not in _texts("num 5550005678 end")

    def test_paren_without_separator_not_matched(self):
        # "(800)555-1234" lacks the required separator after the area code.
        assert _spans("Call (800)555-1234 now") == []

    def test_only_letters(self):
        assert _spans("the quick brown fox") == []


# ---------------------------------------------------------------------------
# Boundary behaviour
# ---------------------------------------------------------------------------


class TestBoundaries:
    def test_eleven_digit_plus_grouping_truncated(self):
        # "+1 800 555 12345" matches the +1 pattern up to 4 trailing digits.
        text = "Call +1 800 555 12345 now"
        assert "+1 800 555 1234" in _texts(text)

    def test_number_embedded_in_longer_digit_run_no_separator(self):
        # A 14-digit run should not yield a clean 10-digit no-separator match
        # because of the word boundaries around the run.
        assert "2025551234" not in _texts("id 20255512349999 end")

    def test_idempotent_across_calls(self):
        f = PhoneNumberFilter()
        text = "Call 800-555-1234."
        first = [(s.text, s.character_start, s.character_end) for s in f.detect(text)]
        second = [(s.text, s.character_start, s.character_end) for s in f.detect(text)]
        assert first == second
