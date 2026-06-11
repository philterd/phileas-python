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

"""Detection tests for the PassportNumberFilter filter."""

import pytest

from phileas.filters.passport_number_filter import PassportNumberFilter


# Letter followed by 8 digits.
LETTER_PLUS_8 = [
    "A12345678",
    "Z00000000",
    "M98765432",
    "B11111111",
]

# 9-digit passport numbers.
NINE_DIGITS = [
    "123456789",
    "000000000",
    "987654321",
    "555555555",
]

VALID_PASSPORTS = LETTER_PLUS_8 + NINE_DIGITS


@pytest.fixture
def passport_filter():
    return PassportNumberFilter()


@pytest.mark.parametrize("value", VALID_PASSPORTS)
def test_valid_passport_detected_standalone(passport_filter, value):
    spans = passport_filter.detect(value)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == value
    assert span.character_start == 0
    assert span.character_end == len(value)
    assert span.filter_type == "passport-number"
    assert span.confidence == 1.0
    assert span.replacement == ""


@pytest.mark.parametrize("value", VALID_PASSPORTS)
def test_valid_passport_detected_in_sentence(passport_filter, value):
    text = f"My passport number is {value} thanks."
    spans = passport_filter.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == value
    assert text[span.character_start : span.character_end] == value
    assert span.filter_type == "passport-number"


@pytest.mark.parametrize(
    "wrapped,inner",
    [
        ("A12345678.", "A12345678"),
        ("(A12345678)", "A12345678"),
        ("A12345678,", "A12345678"),
        ("[A12345678]", "A12345678"),
        ("123456789.", "123456789"),
        ("(123456789)", "123456789"),
    ],
)
def test_passport_with_surrounding_punctuation(passport_filter, wrapped, inner):
    spans = passport_filter.detect(wrapped)
    assert len(spans) == 1
    assert spans[0].text == inner


def test_multiple_passports_in_text(passport_filter):
    text = "First A12345678 and second 987654321 on file."
    spans = passport_filter.detect(text)
    assert len(spans) == 2
    assert {s.text for s in spans} == {"A12345678", "987654321"}
    for s in spans:
        assert s.filter_type == "passport-number"
        assert text[s.character_start : s.character_end] == s.text


def test_default_context_returns_results(passport_filter):
    spans = passport_filter.detect("A12345678", context="default")
    assert len(spans) == 1


def test_custom_context_still_detects(passport_filter):
    spans = passport_filter.detect("A12345678", context="custom-ctx")
    assert len(spans) == 1


# --- Negative cases ---------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "A1234567",  # letter + 7 digits (too short)
        "A123456",  # letter + 6 digits
        "12345678",  # 8 digits (too short)
        "1234567",  # 7 digits
    ],
)
def test_too_short_not_detected(passport_filter, text):
    assert passport_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "A123456789",  # letter + 9 digits (too long)
        "1234567890",  # 10 digits (too long)
        "12345678901",  # 11 digits
    ],
)
def test_too_long_not_detected(passport_filter, text):
    assert passport_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "a12345678",  # lowercase letter prefix
        "z00000000",
        "m98765432",
    ],
)
def test_lowercase_letter_prefix_not_detected(passport_filter, text):
    # The letter+8 pattern requires an uppercase [A-Z]; lowercase is not
    # matched, and the token has 9 chars so the 9-digit rule does not apply.
    assert passport_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "AB1234567",  # two letters + 7 digits
        "A1234567B",  # trailing letter inside token
        "A12345678B",  # letter + 8 digits + trailing letter
        "1A2345678",  # letter in the middle
    ],
)
def test_extra_letters_not_detected(passport_filter, text):
    assert passport_filter.detect(text) == []


def test_glued_to_alphanumeric_not_detected(passport_filter):
    # No word boundary: surrounding alphanumerics extend the token.
    assert passport_filter.detect("XXA12345678XX") == []
    assert passport_filter.detect("999123456789999") == []


@pytest.mark.parametrize(
    "text",
    [
        "",
        "no passport here at all",
        "just some words and letters ABCDE",
        "the year was 2024",
    ],
)
def test_no_false_positives(passport_filter, text):
    assert passport_filter.detect(text) == []


def test_letter_plus_8_at_string_boundaries(passport_filter):
    spans = passport_filter.detect("A12345678")
    assert len(spans) == 1
    assert spans[0].character_start == 0
    assert spans[0].character_end == 9


def test_nine_digits_preceded_by_letter_boundary(passport_filter):
    # "ID 123456789" - the digit run is preceded by a space, so it matches.
    text = "ID 123456789"
    spans = passport_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "123456789"


def test_filter_constructs_with_none_config():
    f = PassportNumberFilter(None)
    spans = f.detect("A12345678")
    assert len(spans) == 1
    assert spans[0].filter_type == "passport-number"


def test_filter_constructs_with_empty_config():
    f = PassportNumberFilter({})
    spans = f.detect("123456789")
    assert len(spans) == 1
    assert spans[0].filter_type == "passport-number"
