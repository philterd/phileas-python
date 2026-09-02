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

Detection runs through libphonenumber's scanner, so a number yields exactly one
span covering the whole number, and confidence varies by how it is written.
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

    def test_confidence_tiers(self):
        # Plain NANP formatting earns 0.95; anything else is 0.75 above 14
        # characters and 0.60 below, matching the Java filter.
        assert _spans("Call 800-555-1234.")[0].confidence == 0.95
        assert _spans("Call +1-800-555-1234.")[0].confidence == 0.75
        assert _spans("Call 2025551234.")[0].confidence == 0.60

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
        # The whole number is one span, open paren included.
        assert _texts("Reach me at (800) 555-1234 today") == ["(800) 555-1234"]

    def test_paren_format_without_separator_detected(self):
        assert _texts("Call (800)555-1234 now") == ["(800)555-1234"]

    def test_plus_one_space_format(self):
        assert _texts("Reach me at +1 800 555 1234 today") == ["+1 800 555 1234"]

    def test_plus_one_dash_format(self):
        assert _texts("Reach me at +1-800-555-1234 today") == ["+1-800-555-1234"]

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

    def test_possible_leniency_accepts_unassigned_nanp_digits(self):
        # POSSIBLE leniency judges length, not NANP digit rules, so numbers the
        # old regex excluded on their first or fourth digit are now detected.
        assert "1005551234" in _texts("num 1005551234 end")
        assert "5550005678" in _texts("num 5550005678 end")

    def test_only_letters(self):
        assert _spans("the quick brown fox") == []


# ---------------------------------------------------------------------------
# Boundary behaviour
# ---------------------------------------------------------------------------


class TestBoundaries:
    def test_eleven_digit_grouping_not_truncated(self):
        # The old regex cut this down to a valid-looking "+1 800 555 1234".
        # libphonenumber rejects the whole run instead of reporting part of it.
        assert _spans("Call +1 800 555 12345 now") == []

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


class TestInternational:
    """The gap this filter was rewritten to close: non-NANP numbers were shipped
    unredacted by the old regex. A "+" prefix is found whatever the region."""

    @pytest.mark.parametrize(
        "number",
        [
            "+44 20 7946 0958",
            "+33 1 42 68 53 00",
            "+91 98765 43210",
            "+49 30 901820",
            "+81 3-3224-9999",
            "+61 2 9374 4000",
        ],
    )
    def test_international_number_detected(self, number):
        assert _texts(f"Reach me at {number} today") == [number]

    def test_international_number_redacted_end_to_end(self):
        from phileas.policy.policy import Policy
        from phileas.services.filter_service import FilterService

        policy = Policy.from_dict(
            {"name": "t", "identifiers": {"phoneNumber": {
                "phoneNumberFilterStrategies": [{"strategy": "REDACT"}]}}}
        )
        r = FilterService().filter(policy, "c", "d", "Call +44 20 7946 0958 today.")
        assert "+44 20 7946 0958" not in r.filtered_text
        assert "{{{REDACTED-phone-number}}}" in r.filtered_text

    def test_national_format_foreign_number_not_claimed(self):
        # Without a "+", a foreign national-format number is not a US number,
        # so it is not detected while the region is US. Region config is #48.
        assert _spans("Reach me at 020 7946 0958 today") == []


class TestNANPRegression:
    """The formats the old regex handled must keep working."""

    @pytest.mark.parametrize(
        "number",
        [
            "(555) 123-4567",
            "+1 555 123 4567",
            "555-123-4567",
            "555.123.4567",
            "5551234567",
            "(800) 555-1234",
            "+1-800-555-1234",
            "800 555 1234",
        ],
    )
    def test_nanp_format_detected(self, number):
        assert _texts(f"Reach me at {number} today") == [number]
