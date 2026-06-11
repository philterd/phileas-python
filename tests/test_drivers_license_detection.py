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

"""Detection tests for the DriversLicenseFilter filter."""

import pytest

from phileas.filters.drivers_license_filter import DriversLicenseFilter


# 1-2 uppercase letters followed by 5-9 digits.
LETTER_PREFIXED = [
    "A12345",       # 1 letter, 5 digits (min)
    "A123456",      # 1 letter, 6 digits
    "A1234567",     # 1 letter, 7 digits
    "A12345678",    # 1 letter, 8 digits
    "A123456789",   # 1 letter, 9 digits (max)
    "AB12345",      # 2 letters, 5 digits
    "AB123456",     # 2 letters, 6 digits
    "AB1234567",    # 2 letters, 7 digits
    "AB12345678",   # 2 letters, 8 digits
    "AB123456789",  # 2 letters, 9 digits (max)
]

# All-digit driver's license formats: 7-9 digits.
ALL_DIGIT = [
    "1234567",      # 7 digits (min)
    "12345678",     # 8 digits
    "123456789",    # 9 digits (max)
]

POSITIVES = LETTER_PREFIXED + ALL_DIGIT


@pytest.fixture
def dl_filter():
    return DriversLicenseFilter()


# --- Positive cases ---------------------------------------------------------


@pytest.mark.parametrize("value", POSITIVES)
def test_positive_detected_standalone(dl_filter, value):
    spans = dl_filter.detect(value)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == value
    assert span.character_start == 0
    assert span.character_end == len(value)
    assert span.filter_type == "drivers-license"
    assert span.confidence == 1.0
    assert span.replacement == ""


@pytest.mark.parametrize("value", POSITIVES)
def test_positive_detected_in_sentence(dl_filter, value):
    text = f"The driver's license is {value} on file."
    spans = dl_filter.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == value
    assert text[span.character_start : span.character_end] == value
    assert span.filter_type == "drivers-license"


@pytest.mark.parametrize(
    "wrapped,inner",
    [
        ("AB123456.", "AB123456"),
        ("(AB123456)", "AB123456"),
        ("AB123456,", "AB123456"),
        ("[AB123456]", "AB123456"),
        ("1234567.", "1234567"),
        ("(1234567)", "1234567"),
    ],
)
def test_positive_with_surrounding_punctuation(dl_filter, wrapped, inner):
    spans = dl_filter.detect(wrapped)
    assert len(spans) == 1
    assert spans[0].text == inner


def test_multiple_licenses_in_text(dl_filter):
    text = "DL1: AB12345 DL2: 1234567 DL3: C987654"
    spans = dl_filter.detect(text)
    assert {s.text for s in spans} == {"AB12345", "1234567", "C987654"}
    assert len(spans) == 3
    for s in spans:
        assert s.filter_type == "drivers-license"
        assert text[s.character_start : s.character_end] == s.text


def test_default_context_returns_results(dl_filter):
    assert len(dl_filter.detect("AB123456", context="default")) == 1


def test_custom_context_still_detects(dl_filter):
    assert len(dl_filter.detect("AB123456", context="custom-ctx")) == 1


def test_letter_prefixed_only_matches_letter_pattern(dl_filter):
    # "A1234567" is 1 letter + 7 digits. The all-digit pattern requires a word
    # boundary before the digit run, but the leading letter blocks it, so this
    # produces exactly one (letter-prefixed) match, not two overlapping spans.
    spans = dl_filter.detect("A1234567")
    assert len(spans) == 1
    assert spans[0].text == "A1234567"


# --- Negative cases ---------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "A1234",        # 1 letter, 4 digits (too few)
        "AB1234",       # 2 letters, 4 digits (too few)
        "A123",         # 1 letter, 3 digits
        "12345",        # 5 digits (too few for all-digit)
        "123456",       # 6 digits (too few for all-digit)
    ],
)
def test_too_short_not_detected(dl_filter, text):
    assert dl_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "A1234567890",   # 1 letter, 10 digits (too many)
        "AB1234567890",  # 2 letters, 10 digits (too many)
        "1234567890",    # 10 digits (too many for all-digit)
        "12345678901",   # 11 digits
    ],
)
def test_too_long_not_detected(dl_filter, text):
    # No internal word boundary lets the regex pick out a valid-length
    # sub-run, so an over-length token matches nothing.
    assert dl_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "ABC12345",  # 3 letters
        "ABCD1234",  # 4 letters
    ],
)
def test_too_many_letters_not_detected(dl_filter, text):
    assert dl_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "a12345",       # lowercase single letter
        "ab12345",      # lowercase double letter
        "aB12345",      # mixed case
    ],
)
def test_lowercase_letters_not_detected(dl_filter, text):
    assert dl_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "XAB12345",   # leading letter -> effectively 3 letters
        "AB12345Z",   # trailing letter
        "A12345B",    # trailing letter after digits
    ],
)
def test_glued_to_extra_letters_not_detected(dl_filter, text):
    assert dl_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "",
        "no license here at all",
        "just words and letters only",
        "555-123-4567",   # phone-like, hyphens break runs
        "123-45-6789",    # ssn-like, hyphens break runs
    ],
)
def test_no_false_positives(dl_filter, text):
    assert dl_filter.detect(text) == []


# --- Construction -----------------------------------------------------------


def test_filter_constructs_with_none_config():
    f = DriversLicenseFilter(None)
    spans = f.detect("AB123456")
    assert len(spans) == 1
    assert spans[0].filter_type == "drivers-license"


def test_filter_constructs_with_empty_config():
    f = DriversLicenseFilter({})
    spans = f.detect("AB123456")
    assert len(spans) == 1


def test_default_construction_has_empty_config():
    f = DriversLicenseFilter()
    assert f.config == {}
